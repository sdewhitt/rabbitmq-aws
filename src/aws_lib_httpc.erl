%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% The single owner of the Gun request lifecycle for the plugin.
%%
%% Before this module, the open -> await_up -> request -> await -> await_body ->
%% close sequence was open-coded in the AWS API path (aws_lib) and in three
%% near-identical metadata-service sites (aws_lib_config). That duplication
%% caused real bugs (the await_body error handling had to be fixed in three
%% places) and drift (connect timeouts differed between paths). Every caller now
%% routes through here, so the lifecycle, timeout handling, header
%% normalization, and response shaping live in exactly one place.
%%
%% The connection handle is an OPAQUE conn(): callers obtain one from open/3,
%% hand it back to request/6 and close/1, and never touch the underlying Gun pid
%% directly. This keeps the "one place owns Gun" invariant enforceable -- a
%% caller cannot reach around the boundary and issue its own gun:get/await on the
%% handle.
-module(aws_lib_httpc).

-export([open/3, request/6, request/7, close/1, response_status/1]).

-export_type([conn/0, response/0]).

-include("aws_lib.hrl").

%% Opaque connection handle. A bare Gun pid today; kept opaque so it can grow
%% (e.g. to carry host/port for stale-connection reconnect, issues #91/#107)
%% without changing any caller.
-opaque conn() :: pid().

-type open_opts() :: #{
    transport => tcp | tls,
    protocols => [http | http2],
    connect_timeout => timeout(),
    %% Gun's reconnection count. Omitted, gun defaults to 5 (a dropped socket
    %% reconnects in the background). A bounded reuse caller (issue #91) passes
    %% 0 so a dropped connection terminates the Gun process instead: a request
    %% on it then fails fast via gun:await's process monitor ({error, {down,
    %% _}}) rather than blocking on a background reconnect.
    retry => non_neg_integer(),
    %% Request (await/await_body) timeout, consulted only by request/7.
    timeout => timeout(),
    %% HTTP CONNECT proxy configuration. When present, the connection is opened
    %% to the proxy host over TCP, then an HTTP CONNECT tunnel is established
    %% to the origin with TLS negotiated inside the tunnel (SNI/verify against
    %% the ORIGIN, never the proxy). A configured proxy that fails is a HARD
    %% error -- never silently falls back to direct connection.
    %% ProxyAuth is {Username, Password} | undefined.
    proxy =>
        {string(), inet:port_number(), {string(), string()} | undefined}
        | undefined
}.

%% The response tuple this module produces, consumed by
%% aws_lib_response:format_response/1 and the metadata-service callers. NOTE: the first
%% status-line element is the literal atom `http_version', not an
%% http_version() string -- this is the shape the plugin has always built, so it
%% is typed as-is rather than as aws_lib.hrl's status_line() (whose first element
%% is a string).
-type response() ::
    {ok, {{http_version, status_code(), reason_phrase()}, headers(), body()}}
    | {error, term()}.

-spec open(Host :: string(), Port :: inet:port_number(), Opts :: open_opts()) ->
    {ok, conn()}
    | {error, {
        gun_open_failed | gun_connection_failed | proxy_connect_failed | proxy_unreachable, term()
    }}.
%% @doc Open a Gun connection and wait for it to come up. When `proxy' is
%% present in Opts, the connection is opened to the proxy over TCP and an HTTP
%% CONNECT tunnel is established to the origin Host:Port with TLS inside the
%% tunnel (SNI and certificate verification target the ORIGIN, never the proxy).
%% A configured proxy that fails is a HARD error -- we never silently fall back
%% to a direct connection.
%% @end
open(Host, Port, Opts) ->
    case maps:get(proxy, Opts, undefined) of
        undefined ->
            open_direct(Host, Port, Opts);
        {ProxyHost, ProxyPort, ProxyAuth} ->
            open_via_proxy(Host, Port, ProxyHost, ProxyPort, ProxyAuth, Opts)
    end.

%%--------------------------------------------------------------------
%% Direct connection (no proxy)
%%--------------------------------------------------------------------

open_direct(Host, Port, Opts) ->
    ConnectTimeout = maps:get(connect_timeout, Opts, infinity),
    GunOpts0 = #{
        transport => maps:get(transport, Opts, tcp),
        protocols => maps:get(protocols, Opts, [http]),
        connect_timeout => ConnectTimeout
    },
    %% Only override gun's default retry count when the caller asks; existing
    %% one-shot callers leave it unset and keep gun's default behaviour.
    GunOpts =
        case maps:find(retry, Opts) of
            {ok, Retry} -> GunOpts0#{retry => Retry};
            error -> GunOpts0
        end,
    case gun:open(Host, Port, GunOpts) of
        {ok, ConnPid} ->
            case gun:await_up(ConnPid, ConnectTimeout) of
                {ok, _Protocol} ->
                    {ok, ConnPid};
                {error, Reason} ->
                    gun:close(ConnPid),
                    {error, {gun_connection_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {gun_open_failed, Reason}}
    end.

%%--------------------------------------------------------------------
%% HTTP CONNECT proxy tunneling
%%--------------------------------------------------------------------

%% Open a TCP connection to the proxy, then issue HTTP CONNECT to tunnel to
%% the origin. TLS is negotiated inside the tunnel with SNI and certificate
%% verification against the ORIGIN hostname -- never the proxy. The proxy sees
%% only the CONNECT request and opaque bytes thereafter.
open_via_proxy(OriginHost, OriginPort, ProxyHost, ProxyPort, ProxyAuth, Opts) ->
    ConnectTimeout = maps:get(connect_timeout, Opts, infinity),
    %% Step 1: Open a plain TCP connection to the proxy. The proxy speaks HTTP
    %% so we connect with transport => tcp, protocols => [http].
    ProxyGunOpts0 = #{
        transport => tcp,
        protocols => [http],
        connect_timeout => ConnectTimeout
    },
    ProxyGunOpts =
        case maps:find(retry, Opts) of
            {ok, Retry} -> ProxyGunOpts0#{retry => Retry};
            error -> ProxyGunOpts0
        end,
    case gun:open(ProxyHost, ProxyPort, ProxyGunOpts) of
        {ok, ConnPid} ->
            case gun:await_up(ConnPid, ConnectTimeout) of
                {ok, _Protocol} ->
                    %% Step 2: Issue HTTP CONNECT through the proxy to the origin.
                    %% TLS opts for the tunnel MUST verify the ORIGIN certificate.
                    TlsOpts = origin_tls_opts(OriginHost),
                    ConnectDest = #{
                        host => OriginHost,
                        port => OriginPort,
                        transport => tls,
                        tls_opts => TlsOpts,
                        protocols => maps:get(protocols, Opts, [http])
                    },
                    Headers = proxy_auth_headers(ProxyAuth),
                    StreamRef = gun:connect(ConnPid, ConnectDest, Headers),
                    %% Step 3: Await the tunnel establishment.
                    await_tunnel_up(ConnPid, StreamRef, ConnectTimeout);
                {error, Reason} ->
                    gun:close(ConnPid),
                    {error, {proxy_unreachable, Reason}}
            end;
        {error, Reason} ->
            {error, {proxy_unreachable, Reason}}
    end.

%% TLS options for the tunnel to the origin. SNI is set to the origin hostname,
%% verify is verify_peer with the system CA bundle. Never verify_none.
origin_tls_opts(OriginHost) ->
    SniHost =
        case is_list(OriginHost) of
            true -> OriginHost;
            false -> binary_to_list(OriginHost)
        end,
    [
        {verify, verify_peer},
        {depth, 10},
        {server_name_indication, SniHost},
        {customize_hostname_check, [
            {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
        ]}
        | cacerts_opts()
    ].

%% Return the CA certificate options. OTP 25+ supports `cacerts` from the
%% OS trust store via public_key:cacerts_get/0. If that call fails
%% (should not happen on OTP 25+), the resulting empty list means the TLS
%% handshake will reject -- fail-closed, never verify_none.
cacerts_opts() ->
    try
        Certs = public_key:cacerts_get(),
        [{cacerts, Certs}]
    catch
        _:_ ->
            %% Fail-closed: TLS handshake will reject without a CA store.
            []
    end.

%% Build Proxy-Authorization header for HTTP Basic auth if credentials are
%% provided. The header value is never included in error tuples.
proxy_auth_headers(undefined) ->
    [];
proxy_auth_headers({Username, Password}) ->
    Encoded = base64:encode_to_string(Username ++ ":" ++ Password),
    [{<<"proxy-authorization">>, iolist_to_binary(["Basic ", Encoded])}].

%% Await gun_tunnel_up or an error/unexpected response from the proxy. Per
%% RFC 7231 Section 4.3.6, only 2xx indicates a successful CONNECT; any other
%% status (3xx, 4xx, 5xx) is treated as a hard failure.
await_tunnel_up(ConnPid, StreamRef, Timeout) ->
    MRef = monitor(process, ConnPid),
    Result = do_await_tunnel(ConnPid, StreamRef, Timeout, MRef),
    demonitor(MRef, [flush]),
    Result.

do_await_tunnel(ConnPid, StreamRef, Timeout, MRef) ->
    receive
        {gun_tunnel_up, ConnPid, StreamRef, _Protocol} ->
            {ok, ConnPid};
        {gun_response, ConnPid, StreamRef, _IsFin, Status, _Headers} ->
            %% Any HTTP response other than the implicit 2xx that triggers
            %% gun_tunnel_up is a CONNECT rejection (3xx, 4xx, 5xx).
            gun:close(ConnPid),
            {error, {proxy_connect_failed, Status}};
        {gun_error, ConnPid, StreamRef, Reason} ->
            gun:close(ConnPid),
            {error, {proxy_connect_failed, Reason}};
        {gun_error, ConnPid, Reason} ->
            gun:close(ConnPid),
            {error, {proxy_connect_failed, Reason}};
        {'DOWN', MRef, process, ConnPid, Reason} ->
            {error, {proxy_connect_failed, Reason}}
    after Timeout ->
        gun:close(ConnPid),
        {error, {proxy_connect_failed, timeout}}
    end.

-spec request(
    Conn :: conn(),
    Method :: method(),
    Path :: path(),
    Headers :: headers(),
    Body :: body(),
    Timeout :: timeout()
) -> response().
%% @doc Issue one request on an existing connection and read the full response.
%% Headers are normalized to binaries; the await/await_body dance is performed
%% here so its error handling lives in one place. Returns the status-line-shaped
%% tuple aws_lib_response:format_response/1 accepts, or {error, Reason} for any transport
%% or body-read failure (including a raise, which is caught).
%% @end
request(Conn, Method, Path, Headers, Body, Timeout) ->
    HeadersBin = normalize_headers(Headers),
    try
        StreamRef = do_gun_request(Conn, Method, Path, HeadersBin, Body),
        case gun:await(Conn, StreamRef, Timeout) of
            {response, fin, Status, RespHeaders} ->
                {ok, {
                    {http_version, Status, status_text(Status)}, RespHeaders, <<>>
                }};
            {response, nofin, Status, RespHeaders} ->
                %% await_body/3 can return {error, timeout} (and other {error, _}
                %% reasons); surface it cleanly rather than letting a hard match
                %% turn it into a {badmatch, _} term.
                case gun:await_body(Conn, StreamRef, Timeout) of
                    {ok, RespBody} ->
                        {ok, {
                            {http_version, Status, status_text(Status)},
                            RespHeaders,
                            RespBody
                        }};
                    {error, Reason} ->
                        {error, Reason}
                end;
            {error, Reason} ->
                {error, Reason}
        end
    catch
        _:Error ->
            {error, Error}
    end.

-spec response_status(response()) -> {http, status_code()} | transport_error.
%% @doc The status of a response/0: `{http, StatusCode}' for a completed HTTP
%% exchange, or `transport_error' for a transport-level failure that never
%% produced a status line. Lives here, where the response/0 shape is built, so
%% callers classify the outcome without matching the raw tuple (whose status
%% line uses the literal atom `http_version', a shape a caller-side match on the
%% aws_lib.hrl status_line() type cannot see as inhabited).
%% @end
response_status({ok, {{http_version, StatusCode, _Reason}, _Headers, _Body}}) ->
    {http, StatusCode};
response_status({error, _Reason}) ->
    transport_error.

-spec request(
    Host :: string(),
    Port :: inet:port_number(),
    Method :: method(),
    Path :: path(),
    Headers :: headers(),
    Body :: body(),
    Opts :: open_opts()
) -> response().
%% @doc One-shot request: open a connection, issue the request, and close the
%% connection, whatever the outcome. The request timeout is taken from Opts
%% (`timeout' key, defaulting to the connect timeout). An open/await_up failure
%% is returned (not raised) so it flows through the caller's error handling.
%% @end
request(Host, Port, Method, Path, Headers, Body, Opts) ->
    case open(Host, Port, Opts) of
        {ok, Conn} ->
            Timeout = maps:get(timeout, Opts, maps:get(connect_timeout, Opts, infinity)),
            try
                request(Conn, Method, Path, Headers, Body, Timeout)
            after
                close(Conn)
            end;
        {error, _Reason} = Error ->
            Error
    end.

-spec close(Conn :: conn()) -> ok.
%% @doc Close a connection opened with open/3.
%% @end
close(Conn) ->
    gun:close(Conn).

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

normalize_headers(Headers) ->
    [{to_binary(Key), to_binary(Value)} || {Key, Value} <- Headers].

to_binary(Value) when is_binary(Value) -> Value;
to_binary(Value) when is_list(Value) -> list_to_binary(Value).

do_gun_request(Conn, get, Path, Headers, _Body) ->
    gun:get(Conn, Path, Headers);
do_gun_request(Conn, post, Path, Headers, Body) ->
    gun:post(Conn, Path, Headers, Body, #{});
do_gun_request(Conn, put, Path, Headers, Body) ->
    gun:put(Conn, Path, Headers, Body, #{});
do_gun_request(Conn, head, Path, Headers, _Body) ->
    gun:head(Conn, Path, Headers, #{});
do_gun_request(Conn, delete, Path, Headers, _Body) ->
    gun:delete(Conn, Path, Headers, #{});
do_gun_request(Conn, patch, Path, Headers, Body) ->
    gun:patch(Conn, Path, Headers, Body, #{});
do_gun_request(Conn, options, Path, Headers, _Body) ->
    gun:options(Conn, Path, Headers, #{}).

%% The reason phrase for a status code, used to build the status line Gun does
%% not carry. Response construction, so it lives here alongside the rest of the
%% response/0 shaping rather than in aws_lib_response, which only interprets a
%% response.
status_text(200) -> "OK";
status_text(206) -> "Partial Content";
status_text(400) -> "Bad Request";
status_text(401) -> "Unauthorized";
status_text(403) -> "Forbidden";
status_text(404) -> "Not Found";
status_text(416) -> "Range Not Satisfiable";
status_text(500) -> "Internal Server Error";
status_text(Code) -> integer_to_list(Code).
