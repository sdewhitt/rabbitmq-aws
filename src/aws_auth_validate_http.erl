%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% HTTP auth-backend reachability validation.
%%
%% Validates a `rabbit_auth_backend_http' configuration (the auth_http.*
%% settings a customer would put in rabbitmq.conf) without a broker restart.
%% Mirrors the LDAP backend's shape: pure input validation runs first, secret
%% ARNs are resolved only after, and every outcome collapses to a fixed
%% category so the response leaks no target URL, response body, or raw httpc
%% error.
%%
%% Scope: REACHABILITY-ONLY (deliberate first cut). An HTTP auth server, by
%% contract, answers `allow'/`deny' for a specific {user, vhost, resource}
%% tuple -- a `deny' is a correctly-working server, not a misconfiguration. So
%% we do NOT assert that any particular principal is authorized. Instead we
%% confirm each configured `*_path' is reachable over (m)TLS and answers like
%% an auth server (a well-formed HTTP response). That catches the actual pain
%% (wrong URL, TLS/CA misconfig, unreachable host) without needing a real test
%% credential or an authz-semantics judgement.
%%
%% A future credentialed-probe mode (assert user_path returns `allow' for a
%% supplied username + password_arn) is intentionally out of scope here; see
%% http-validation-analysis.md, open question 1.
%%
%% Category mapping (reuses the existing aws_auth_validate_backend categories;
%% no new category is introduced, per R4 "keep the set small"):
%%   * connection_failed (400) -- host unreachable / DNS / connection refused.
%%   * tls_failed        (400) -- TLS handshake / cert verification failure.
%%   * auth_failed       (422) -- reached the server but its response is not
%%                                auth-server-shaped (no usable HTTP status).
%%     NOTE: auth_failed is borrowed for "endpoint did not behave like an auth
%%     server". If reachability-only proves too coarse, introduce a dedicated
%%     `endpoint_unverified' category (analogous to authz_unverified) -- that
%%     requires extending aws_auth_validate_backend:error_category/0 and the
%%     handler's status_for_category/1.
-module(aws_auth_validate_http).

-behaviour(aws_auth_validate_backend).

-export([method_name/0, validate/1, allowed_fields/0]).

%% Default per-request timeout (ms) when auth_validation_connection_timeout_ms
%% is unset. Matches the LDAP backend's default.
-define(DEFAULT_TIMEOUT_MS, 5_000).

%% The four request paths a rabbit_auth_backend_http config can define. Each is
%% an absolute URL. user_path is required (the broker always issues a user
%% check); the other three are optional and validated/probed only when present.
-define(PATH_KEYS, [
    <<"user_path">>,
    <<"vhost_path">>,
    <<"resource_path">>,
    <<"topic_path">>
]).
-define(REQUIRED_PATH_KEY, <<"user_path">>).

%% Accepted values for http_method (mirrors rabbit_auth_backend_http's
%% auth_http.http_method).
-define(HTTP_METHOD_VALUES, [<<"get">>, <<"post">>]).

%% ssl_options surface, identical to the LDAP backend's (auth_http.ssl_options.*
%% has the same shape as auth_ldap.ssl_options.*).
%% Accepted ssl_options keys, named to match what a customer writes under
%% auth_http.ssl_options.* in rabbitmq.conf so a config can be pasted as-is.
%% In particular the key is `sni' (the broker's config key), NOT the internal
%% `server_name_indication' atom it maps to -- the probe translates sni ->
%% server_name_indication when it builds the httpc ssl options. cacertfile_arn
%% mirrors the tutorial's aws.arns.auth_http.ssl_options.cacertfile ARN line.
-define(SSL_OPTION_KEYS, [
    <<"cacertfile_arn">>,
    <<"verify">>,
    <<"depth">>,
    <<"versions">>,
    <<"sni">>
]).
-define(SSL_VERIFY_VALUES, [<<"verify_peer">>, <<"verify_none">>]).
-define(SSL_VERSION_VALUES, [
    <<"tlsv1.3">>,
    <<"tlsv1.2">>,
    <<"tlsv1.1">>,
    <<"tlsv1">>
]).

%% Fixed, hardcoded reason strings (R4): no URL, host, or raw error echoed.
-define(REASON_BAD_PATHS, <<"at least user_path must be a non-empty URL string">>).
-define(REASON_BAD_PATH_VALUE, <<"each path must be a non-empty URL string">>).
-define(REASON_BAD_URL, <<"a configured path is not a valid http(s) URL">>).
-define(REASON_URL_NOT_ALLOWED, <<"a configured path targets a disallowed address">>).
-define(REASON_BAD_HTTP_METHOD, <<"http_method must be get or post">>).
-define(REASON_BAD_SSL_OPTIONS, <<"ssl_options must be an object">>).
-define(REASON_UNKNOWN_SSL_OPTION, <<
    "ssl_options contains an unknown key; allowed keys are cacertfile_arn, "
    "verify, depth, versions, sni"
>>).
-define(REASON_BAD_SSL_VERIFY, <<"ssl_options.verify must be verify_peer or verify_none">>).
-define(REASON_BAD_SSL_DEPTH, <<"ssl_options.depth must be a non-negative integer">>).
-define(REASON_BAD_SSL_VERSIONS, <<"ssl_options.versions must be a list of known TLS versions">>).
-define(REASON_BAD_SSL_SNI, <<"ssl_options.sni must be a string">>).
-define(REASON_BAD_SSL_CACERT_ARN, <<"ssl_options.cacertfile_arn must be a non-empty string">>).
-define(REASON_CONNECTION, <<"could not connect to HTTP auth server">>).
-define(REASON_TLS_HANDSHAKE, <<"TLS handshake failed">>).
-define(REASON_ENDPOINT, <<"HTTP auth server did not return a usable response">>).
-define(REASON_ARN_RESOLVE, <<"failed to resolve ARN">>).

%% HTTP status codes rabbit_auth_backend_http treats as a usable auth response
%% (it accepts 200 and 201). We accept the same set as "the endpoint answered
%% like an auth server"; any other well-formed status still proves reachability
%% but is reported as endpoint-unverified (the server is up but not responding
%% the way the auth backend expects).
-define(AUTH_RESPONSE_CODES, [200, 201]).

%% SSRF guard toggles (see the SSRF guard section below for the full rationale).
%% ?ENFORCE_ADDRESS_POLICY gates BOTH the per-URL address check (url_allowed/1,
%% via classify_address/1) and the probe-layer DNS resolve+classify, and the
%% fail-closed guard in validate/1 (ssrf_policy_ready/0) is bound to it too --
%% so enforcement and probing turn on together. It is now TRUE: the address
%% policy (classify_ip/1 + the probe-layer resolve+pin) is implemented.
%% NOTE: AppSec review + pen test are still pending (parent FAQ 2.1); the method
%% remains opt-in (aws_auth_validate_registry ?OPT_IN_METHODS) so it is not live
%% until an operator explicitly enables it.
-define(ALLOWED_SCHEMES, ["https", "http"]).
-define(ENFORCE_ADDRESS_POLICY, true).

%% Always-denied address ranges -- the broker's own privileged infrastructure.
%% We deliberately do NOT block RFC1918 / unique-local: a customer's HTTP auth
%% server normally lives in their VPC, so blocking private ranges would make the
%% endpoint useless. The threat is the broker reaching its OWN infra (IMDS =
%% instance-role credential theft, loopback = broker-local services), not
%% reaching private addresses in general.
-define(DENIED_V4_CIDRS, [
    %% loopback 127.0.0.0/8
    {{127, 0, 0, 0}, 8},
    %% link-local 169.254.0.0/16 (this range CONTAINS the IMDS 169.254.169.254)
    {{169, 254, 0, 0}, 16},
    %% unspecified / "this host" 0.0.0.0/8
    {{0, 0, 0, 0}, 8}
]).
-define(DENIED_V6_CIDRS, [
    %% loopback ::1/128
    {{0, 0, 0, 0, 0, 0, 0, 1}, 128},
    %% link-local fe80::/10 (IPv6 IMDS link-local lives here)
    {{16#fe80, 0, 0, 0, 0, 0, 0, 0}, 10},
    %% AWS IMDSv6 fd00:ec2::254/128
    {{16#fd00, 16#0ec2, 0, 0, 0, 0, 0, 16#0254}, 128},
    %% unspecified ::/128
    {{0, 0, 0, 0, 0, 0, 0, 0}, 128}
]).

%%--------------------------------------------------------------------
%% Behaviour callbacks
%%--------------------------------------------------------------------

method_name() ->
    <<"http">>.

allowed_fields() ->
    [
        <<"user_path">>,
        <<"vhost_path">>,
        <<"resource_path">>,
        <<"topic_path">>,
        <<"http_method">>,
        <<"ssl_options">>
    ].

-spec validate(map()) -> aws_auth_validate_backend:result().
validate(Body) when is_map(Body) ->
    %% FAIL-CLOSED until the SSRF address policy is live. The probe issues
    %% outbound requests to customer-supplied URLs from the broker's network
    %% position; until classify_address/1 denies IMDS/link-local/loopback/
    %% private targets (?ENFORCE_ADDRESS_POLICY = true) and AppSec has signed
    %% off, no probe may run -- otherwise this is an SSRF vector (e.g. to
    %% 169.254.169.254). Report method_disabled so an operator who turned the
    %% method on still gets a safe, fixed-category 404 rather than a live
    %% unrestricted probe. This guard lifts automatically when the policy lands.
    case ssrf_policy_ready() of
        false ->
            {error, method_disabled};
        true ->
            %% Same ARN-first ordering as the LDAP backend: all pure,
            %% network-free validation (URL shape, method, ssl_options values,
            %% and the SSRF guard) runs before any cacertfile_arn is resolved
            %% or any request is made.
            case parse_input(Body) of
                {error, _, _} = Err ->
                    Err;
                {ok, Params} ->
                    do_http_validate(Params)
            end
    end.

%% The probe is only allowed to run once the SSRF address policy is enforced.
%% Tied to the same compile-time toggle the guard uses, so the backend cannot
%% issue outbound requests while classify_address/1 is still a no-op.
ssrf_policy_ready() ->
    ?ENFORCE_ADDRESS_POLICY.

%%--------------------------------------------------------------------
%% Input parsing (pure, no network)
%%--------------------------------------------------------------------

parse_input(Body) ->
    Steps = [
        fun parse_paths/2,
        fun parse_http_method/2,
        fun parse_ssl_options/2,
        %% SSRF guard runs in the pure phase so a disallowed target is rejected
        %% before any ARN resolution or outbound request. See guard_urls/2.
        fun guard_urls/2
    ],
    parse_input(Steps, Body, #{timeout => connection_timeout_ms()}).

parse_input([], _Body, Acc) ->
    {ok, Acc};
parse_input([Step | Rest], Body, Acc0) ->
    case Step(Body, Acc0) of
        {ok, Acc1} -> parse_input(Rest, Body, Acc1);
        {error, _, _} = Err -> Err
    end.

%% Collect the configured paths. user_path is mandatory; the others are
%% optional. Each present value must be a non-empty string and parse as an
%% http(s) URL. Stored as a list of {Key, UrlString} preserving which path is
%% which (so a probe failure could be attributed internally, though the
%% response stays category-only).
parse_paths(Body, Acc) ->
    case maps:get(?REQUIRED_PATH_KEY, Body, undefined) of
        V when not (is_binary(V) andalso byte_size(V) > 0) ->
            {error, input_invalid, ?REASON_BAD_PATHS};
        _ ->
            collect_paths(?PATH_KEYS, Body, Acc, [])
    end.

collect_paths([], _Body, Acc, Paths) ->
    {ok, Acc#{paths => lists:reverse(Paths)}};
collect_paths([Key | Rest], Body, Acc, Paths) ->
    case maps:get(Key, Body, undefined) of
        undefined ->
            collect_paths(Rest, Body, Acc, Paths);
        V when is_binary(V), byte_size(V) > 0 ->
            case parse_url(V) of
                {ok, Url} -> collect_paths(Rest, Body, Acc, [{Key, Url} | Paths]);
                {error, _} -> {error, input_invalid, ?REASON_BAD_URL}
            end;
        _ ->
            {error, input_invalid, ?REASON_BAD_PATH_VALUE}
    end.

%% Parse + minimally validate an http(s) URL. Returns a normalized
%% representation the probe and the SSRF guard can both use. Kept deliberately
%% small here; richer parsing belongs with the guard work.
parse_url(Bin) when is_binary(Bin) ->
    Str = binary_to_list(Bin),
    case uri_string:parse(Str) of
        #{scheme := Scheme, host := Host} = Parsed when
            Host =/= [], (Scheme =:= "http" orelse Scheme =:= "https")
        ->
            %% Reject, as off-shape *_path input:
            %%  * an out-of-range port (else httpc crashes at request time),
            %%  * userinfo (user:pass@host) -- embedded credentials httpc would
            %%    turn into an Authorization header,
            %%  * a pre-existing query string -- the broker's auth_http.*_path
            %%    config is query-less and the probe appends its own ?username=
            %%    params; a path that already carried a query would be mangled
            %%    into a double-? URL and spuriously fail.
            Port = maps:get(port, Parsed, undefined),
            HasQuery = maps:is_key(query, Parsed) andalso maps:get(query, Parsed) =/= [],
            case Port of
                P when is_integer(P), (P < 1 orelse P > 65535) ->
                    {error, bad_url};
                _ when HasQuery ->
                    {error, bad_url};
                _ ->
                    case maps:is_key(userinfo, Parsed) of
                        true -> {error, bad_url};
                        false -> {ok, Parsed#{url_string => Str}}
                    end
            end;
        _ ->
            {error, bad_url}
    end.

parse_http_method(Body, Acc) ->
    case maps:get(<<"http_method">>, Body, undefined) of
        undefined ->
            %% Match rabbit_auth_backend_http's own default of `get' (set in
            %% its app env) when the caller omits http_method, so the probe
            %% uses the same method the broker would. For a reachability check
            %% the method barely matters (both yield a response), so we default
            %% rather than reject.
            {ok, Acc#{http_method => get}};
        V when is_binary(V) ->
            case lists:member(V, ?HTTP_METHOD_VALUES) of
                true -> {ok, Acc#{http_method => binary_to_existing_atom(V, utf8)}};
                false -> {error, input_invalid, ?REASON_BAD_HTTP_METHOD}
            end;
        _ ->
            {error, input_invalid, ?REASON_BAD_HTTP_METHOD}
    end.

%% ssl_options parsing is identical to the LDAP backend's: validate both keys
%% and values in the pure phase so a mis-typed value cannot be silently dropped
%% and re-defaulted.
parse_ssl_options(Body, Acc) ->
    case maps:get(<<"ssl_options">>, Body, undefined) of
        undefined ->
            {ok, Acc#{ssl_options => #{}}};
        Map when is_map(Map) ->
            case [K || K <- maps:keys(Map), not lists:member(K, ?SSL_OPTION_KEYS)] of
                [] -> validate_ssl_values(maps:to_list(Map), Acc, Map);
                [_ | _] -> {error, input_invalid, ?REASON_UNKNOWN_SSL_OPTION}
            end;
        _ ->
            {error, input_invalid, ?REASON_BAD_SSL_OPTIONS}
    end.

validate_ssl_values([], Acc, Map) ->
    {ok, Acc#{ssl_options => Map}};
validate_ssl_values([{Key, Value} | Rest], Acc, Map) ->
    case valid_ssl_value(Key, Value) of
        ok -> validate_ssl_values(Rest, Acc, Map);
        {error, _, _} = Err -> Err
    end.

valid_ssl_value(<<"verify">>, V) ->
    case lists:member(V, ?SSL_VERIFY_VALUES) of
        true -> ok;
        false -> {error, input_invalid, ?REASON_BAD_SSL_VERIFY}
    end;
valid_ssl_value(<<"depth">>, V) when is_integer(V), V >= 0 ->
    ok;
valid_ssl_value(<<"depth">>, _) ->
    {error, input_invalid, ?REASON_BAD_SSL_DEPTH};
valid_ssl_value(<<"versions">>, V) when is_list(V), V =/= [] ->
    case lists:all(fun(Ver) -> lists:member(Ver, ?SSL_VERSION_VALUES) end, V) of
        true -> ok;
        false -> {error, input_invalid, ?REASON_BAD_SSL_VERSIONS}
    end;
valid_ssl_value(<<"versions">>, _) ->
    {error, input_invalid, ?REASON_BAD_SSL_VERSIONS};
valid_ssl_value(<<"sni">>, V) ->
    case is_nonempty_binary(V) of
        true -> ok;
        false -> {error, input_invalid, ?REASON_BAD_SSL_SNI}
    end;
valid_ssl_value(<<"cacertfile_arn">>, V) ->
    case is_nonempty_binary(V) of
        true -> ok;
        false -> {error, input_invalid, ?REASON_BAD_SSL_CACERT_ARN}
    end.

%%--------------------------------------------------------------------
%% SSRF guard
%%--------------------------------------------------------------------
%%
%% The validator issues outbound requests to customer-supplied URLs using the
%% broker's network position -- a textbook SSRF / confused-deputy surface.
%% Defense is two-phase:
%%
%%   * PURE phase (guard_urls/2 here, via classify_address/1): enforce the
%%     scheme allowlist, and when the host is a LITERAL IP, classify it against
%%     the always-denied infra ranges immediately -- no DNS, deterministic. This
%%     catches http://169.254.169.254/... and https://[::1]/... up front.
%%
%%   * NETWORK phase (resolve_and_pin/1 in the probe): a HOSTNAME is only
%%     resolved at connect time, so the pure check cannot see its address. The
%%     probe resolves the host to ALL A/AAAA records, denies if ANY is a
%%     blocked infra address, then connects to the PINNED resolved IP (Host
%%     header + TLS SNI preserved) so httpc cannot re-resolve to a different
%%     address (DNS-rebinding / TOCTOU defense).
%%
%% Redirects are not followed (autoredirect=false in probe_one/4), so a 3xx
%% cannot bounce the probe to a blocked address.
%%
%% Policy: deny the broker's own infra (IMDS, loopback, link-local, unspecified
%% -- see ?DENIED_V4_CIDRS / ?DENIED_V6_CIDRS). RFC1918 / unique-local are NOT
%% denied: a customer auth server normally lives in their VPC.

guard_urls(_Body, #{paths := Paths} = Acc) ->
    case check_urls(Paths) of
        ok -> {ok, Acc};
        {error, _, _} = Err -> Err
    end.

check_urls([]) ->
    ok;
check_urls([{_Key, Url} | Rest]) ->
    case url_allowed(Url) of
        ok -> check_urls(Rest);
        {error, _, _} = Err -> Err
    end.

%% Pure per-URL policy check: scheme allowlist + literal-IP classification.
%% Hostnames pass here (allow) and are re-checked after DNS in the probe layer.
url_allowed(#{scheme := Scheme} = Url) ->
    case lists:member(Scheme, ?ALLOWED_SCHEMES) of
        false ->
            {error, input_invalid, ?REASON_URL_NOT_ALLOWED};
        true ->
            case classify_address(Url) of
                allow -> ok;
                deny -> {error, input_invalid, ?REASON_URL_NOT_ALLOWED}
            end
    end.

%% Classify a URL's host in the pure phase. A literal IP is classified directly
%% against the infra denylist. A hostname cannot be classified without DNS, so
%% it is allowed here and resolved+classified in the probe layer.
classify_address(#{host := Host}) ->
    case inet:parse_address(Host) of
        {ok, IP} -> classify_ip(IP);
        {error, _} -> allow
    end.

%% classify_ip/1: allow | deny for a parsed IP tuple. Denies the broker-infra
%% ranges only. Several IPv6 notations embed a v4 address; each must be
%% unwrapped to its v4 form and re-classified, otherwise the v6 encoding
%% smuggles a denied v4 address (e.g. 169.254.169.254) past the v4 denylist.
%% Covered: IPv4-mapped ::ffff:a.b.c.d, IPv4-compatible ::a.b.c.d, NAT64
%% 64:ff9b::/96, and 6to4 2002:WWXX:YYZZ::/48. The unwrap clauses come BEFORE
%% the generic 8-tuple clause so they win.
classify_ip({0, 0, 0, 0, 0, 16#ffff, W1, W2}) ->
    %% IPv4-mapped ::ffff:a.b.c.d
    classify_ip(v4_from_words(W1, W2));
classify_ip({0, 0, 0, 0, 0, 0, W1, W2}) when {W1, W2} =/= {0, 0}, {W1, W2} =/= {0, 1} ->
    %% IPv4-compatible ::a.b.c.d (RFC4291-deprecated). The guard lets the
    %% unspecified :: and loopback ::1 fall through to the v6 denylist instead
    %% (::1 must be matched as v6 loopback, not as v4 0.0.0.1).
    classify_ip(v4_from_words(W1, W2));
classify_ip({16#64, 16#ff9b, 0, 0, 0, 0, W1, W2}) ->
    %% NAT64 well-known prefix 64:ff9b::/96 -> embedded v4 in the low 32 bits.
    classify_ip(v4_from_words(W1, W2));
classify_ip({16#2002, W1, W2, _, _, _, _, _}) ->
    %% 6to4 2002::/16 -> embedded v4 in segments 2-3.
    classify_ip(v4_from_words(W1, W2));
classify_ip({_, _, _, _} = V4) ->
    case in_any_cidr(V4, ?DENIED_V4_CIDRS) of
        true -> deny;
        false -> allow
    end;
classify_ip({_, _, _, _, _, _, _, _} = V6) ->
    case in_any_cidr(V6, ?DENIED_V6_CIDRS) of
        true -> deny;
        false -> allow
    end.

%% Two 16-bit words -> a v4 4-tuple {a,b,c,d}.
v4_from_words(W1, W2) ->
    {W1 bsr 8, W1 band 16#ff, W2 bsr 8, W2 band 16#ff}.

in_any_cidr(IP, Cidrs) ->
    lists:any(fun(Cidr) -> in_cidr(IP, Cidr) end, Cidrs).

%% in_cidr/2: is IP within {Network, PrefixBits}? Same address family only
%% (a v4 IP never matches a v6 CIDR and vice-versa). Converts both to a single
%% integer, drops the host bits below the prefix, and compares the network bits.
in_cidr({_, _, _, _} = IP, {{_, _, _, _} = Net, Prefix}) when
    Prefix >= 0, Prefix =< 32
->
    same_prefix(ip_to_int(IP), ip_to_int(Net), 32, Prefix);
in_cidr({_, _, _, _, _, _, _, _} = IP, {{_, _, _, _, _, _, _, _} = Net, Prefix}) when
    Prefix >= 0, Prefix =< 128
->
    same_prefix(ip_to_int(IP), ip_to_int(Net), 128, Prefix);
in_cidr(_IP, _Cidr) ->
    %% Cross-family (e.g. v4 IP vs v6 CIDR): never matches.
    false.

same_prefix(IpInt, NetInt, TotalBits, Prefix) ->
    HostBits = TotalBits - Prefix,
    (IpInt bsr HostBits) =:= (NetInt bsr HostBits).

%% Fold an IP tuple into a single unsigned integer (v4: 32-bit, v6: 128-bit).
ip_to_int(Tuple) ->
    BitsPerElem =
        case tuple_size(Tuple) of
            4 -> 8;
            8 -> 16
        end,
    lists:foldl(
        fun(Elem, Acc) -> (Acc bsl BitsPerElem) bor Elem end,
        0,
        tuple_to_list(Tuple)
    ).

%%--------------------------------------------------------------------
%% Reachability probe (network)
%%--------------------------------------------------------------------
%%
%% Reachability-only: confirm each configured path is reachable over (m)TLS and
%% answers like an auth server. We send a representative request with a clearly
%% SYNTHETIC username (never a real credential) and treat:
%%   * a 2xx the real backend accepts (200/201)  -> reachable + auth-shaped (ok)
%%   * any other well-formed HTTP status          -> reachable but the path is
%%       likely wrong (auth_failed) -- catches user_path pointing at the wrong
%%       endpoint, the most common config mistake after TLS/connectivity
%%   * connection refused / DNS / timeout         -> connection_failed
%%   * TLS handshake / cert verification failure  -> tls_failed
%% We do NOT interpret allow vs deny: both are 2xx and both mean "the server is
%% working", so a deny for the synthetic user is a success, not a failure.
%%
%% The whole probe runs inside a try/catch that collapses any raise to
%% connection_failed, so a resolved secret can never reach a crash report (R6).
do_http_validate(Params) ->
    try
        case build_client_ssl_opts(Params) of
            {error, _, _} = Err ->
                Err;
            {ok, SslOpts} ->
                probe_paths(maps:get(paths, Params), Params, SslOpts)
        end
    catch
        _Class:_Reason:_Stack ->
            {error, connection_failed, ?REASON_CONNECTION}
    end.

%% Probe each configured path in turn; the first non-ok outcome wins (mirrors
%% the LDAP backend's check_dns/2 short-circuit).
probe_paths([], _Params, _SslOpts) ->
    ok;
probe_paths([{Key, Url} | Rest], Params, SslOpts) ->
    case probe_one(Key, Url, Params, SslOpts) of
        ok -> probe_paths(Rest, Params, SslOpts);
        {error, _, _} = Err -> Err
    end.

probe_one(Key, Url, #{http_method := Method, timeout := Timeout}, SslOpts) ->
    %% Resolve the host and classify every resolved address against the infra
    %% denylist BEFORE connecting, then connect to the pinned IP so httpc cannot
    %% re-resolve to a different (possibly denied) address (DNS-rebinding /
    %% TOCTOU defense). For a literal-IP host this is a no-op pin to that IP.
    case resolve_and_pin(Url) of
        {error, _, _} = Err ->
            Err;
        {ok, PinnedUrl, Host} ->
            UrlStr = maps:get(url_string, PinnedUrl),
            Query = query_for(Key),
            Request = build_request(Method, UrlStr, Query, Host),
            HttpOpts =
                [
                    {timeout, Timeout},
                    {connect_timeout, Timeout},
                    %% Do not auto-follow redirects: a redirect could send the
                    %% probe to an address the SSRF guard would reject (and we
                    %% do not re-vet the Location target).
                    {autoredirect, false}
                ] ++ ssl_http_opt(Url, Host, SslOpts),
            case httpc:request(Method, Request, HttpOpts, [{body_format, binary}]) of
                {ok, {{_Vsn, Code, _Phrase}, _Headers, _Body}} ->
                    case lists:member(Code, ?AUTH_RESPONSE_CODES) of
                        true -> ok;
                        false -> {error, auth_failed, ?REASON_ENDPOINT}
                    end;
                {error, Reason} ->
                    classify_http_error(Reason)
            end
    end.

%% Resolve the URL's host to all addresses, deny if ANY is a blocked infra
%% address, and return the URL rewritten to connect to a single pinned IP plus
%% the original host (for the Host header / SNI). A literal-IP host is pinned to
%% itself (already classified in the pure phase, re-checked here defensively).
%% A resolution failure is a reachability fact -> connection_failed.
resolve_and_pin(#{host := Host} = Url) ->
    case inet:parse_address(Host) of
        {ok, IP} ->
            %% Literal IP: re-classify defensively, pin to itself.
            case classify_ip(IP) of
                deny -> {error, input_invalid, ?REASON_URL_NOT_ALLOWED};
                allow -> {ok, pin_url(Url, Host), Host}
            end;
        {error, _} ->
            resolve_hostname_and_pin(Url, Host)
    end.

resolve_hostname_and_pin(Url, Host) ->
    Addrs = resolve_all(Host),
    case Addrs of
        [] ->
            {error, connection_failed, ?REASON_CONNECTION};
        _ ->
            case lists:any(fun(IP) -> classify_ip(IP) =:= deny end, Addrs) of
                true ->
                    %% At least one resolved address is blocked infra. Deny the
                    %% whole request -- never connect to a host that resolves
                    %% (even partly) to IMDS/loopback/link-local.
                    {error, input_invalid, ?REASON_URL_NOT_ALLOWED};
                false ->
                    %% All addresses allowed: pin to the first and connect there.
                    PinIP = inet:ntoa(hd(Addrs)),
                    {ok, pin_url(Url, PinIP), Host}
            end
    end.

%% Resolve a hostname to all IPv4 + IPv6 addresses (best-effort per family).
resolve_all(Host) ->
    V4 =
        case inet:getaddrs(Host, inet) of
            {ok, A4} -> A4;
            {error, _} -> []
        end,
    V6 =
        case inet:getaddrs(Host, inet6) of
            {ok, A6} -> A6;
            {error, _} -> []
        end,
    V4 ++ V6.

%% Rewrite the URL to connect to the pinned IP, keeping scheme/port/path/query.
%% uri_string:recompose brackets an IPv6 host on its own. The original hostname
%% is carried separately (build_request adds the Host header, ssl_http_opt sets
%% SNI) so vhost routing and cert hostname verification still target the real
%% name, not the pinned IP.
pin_url(Url, PinHost) ->
    Rebuilt = uri_string:recompose(maps:without([url_string], Url#{host => PinHost})),
    Url#{url_string => Rebuilt}.

%% Map an httpc transport error to a fixed category. A TLS/cert failure is
%% reported as tls_failed; everything else (refused, DNS, timeout, closed) is
%% connection_failed. We never echo the raw reason (R4).
classify_http_error(Reason) ->
    case is_tls_error(Reason) of
        true -> {error, tls_failed, ?REASON_TLS_HANDSHAKE};
        false -> {error, connection_failed, ?REASON_CONNECTION}
    end.

%% Recursively scan an httpc error term for the markers of a TLS-layer failure
%% (tls_alert, or a certificate/handshake atom). httpc wraps these as
%% {failed_connect, [..., {inet, [inet], {tls_alert, _}}]} and similar.
is_tls_error(Term) when is_tuple(Term) ->
    case element(1, Term) of
        tls_alert -> true;
        Other when is_atom(Other) -> is_tls_atom(Other) orelse is_tls_error(tuple_to_list(Term));
        _ -> is_tls_error(tuple_to_list(Term))
    end;
is_tls_error([H | T]) ->
    is_tls_error(H) orelse is_tls_error(T);
is_tls_error(Atom) when is_atom(Atom) ->
    is_tls_atom(Atom);
is_tls_error(_) ->
    false.

is_tls_atom(A) ->
    lists:member(A, [
        tls_alert,
        certificate_expired,
        bad_certificate,
        unknown_ca,
        handshake_failure,
        certificate_unknown,
        no_peercert
    ]).

%% Build the httpc Request tuple for the configured method. For GET the query
%% goes in the URL; for POST it is a form-encoded body, matching
%% rabbit_auth_backend_http's request shape (R12 request-shape parity). The
%% Host header carries the ORIGINAL hostname (the URL host is the pinned IP), so
%% the auth server sees the name it expects -- needed for name-based vhosts.
build_request(get, UrlStr, Query, Host) ->
    Sep =
        case Query of
            "" -> "";
            _ -> "?"
        end,
    {UrlStr ++ Sep ++ Query, [{"host", Host}]};
build_request(post, UrlStr, Query, Host) ->
    {UrlStr, [{"host", Host}], "application/x-www-form-urlencoded", Query}.

%% Only attach ssl options for https targets; httpc ignores them for http.
%% server_name_indication is forced to the ORIGINAL hostname (not the pinned
%% IP) so SNI and certificate hostname verification validate against the name
%% the customer configured -- unless the caller set sni explicitly, which
%% translate_ssl_opts already honoured.
ssl_http_opt(#{scheme := "https"}, Host, SslOpts) ->
    [{ssl, with_default_sni(SslOpts, Host)}];
ssl_http_opt(_Url, _Host, _SslOpts) ->
    [].

with_default_sni(SslOpts, Host) ->
    case lists:keymember(server_name_indication, 1, SslOpts) of
        true -> SslOpts;
        false -> [{server_name_indication, Host} | SslOpts]
    end.

%% Representative, clearly-synthetic query params per path type, mirroring the
%% fields rabbit_auth_backend_http sends so a conformant server returns a 2xx
%% (allow or deny) rather than a 400 for missing params. The username is an
%% obvious placeholder so an operator reading their auth-server logs can see it
%% was a validation probe, not a real login attempt.
query_for(Key) ->
    uri_string:compose_query(params_for(Key)).

-define(PROBE_USER, "__rabbitmq_config_validation_probe__").
-define(PROBE_VHOST, "/").

params_for(<<"user_path">>) ->
    [{"username", ?PROBE_USER}];
params_for(<<"vhost_path">>) ->
    [{"username", ?PROBE_USER}, {"vhost", ?PROBE_VHOST}, {"ip", "127.0.0.1"}];
params_for(<<"resource_path">>) ->
    [
        {"username", ?PROBE_USER},
        {"vhost", ?PROBE_VHOST},
        {"resource", "queue"},
        {"name", "validation-probe"},
        {"permission", "read"}
    ];
params_for(<<"topic_path">>) ->
    [
        {"username", ?PROBE_USER},
        {"vhost", ?PROBE_VHOST},
        {"resource", "topic"},
        {"name", "validation-probe"},
        {"permission", "read"},
        {"routing_key", "#"}
    ].

%%--------------------------------------------------------------------
%% TLS option shaping (ports the LDAP backend's resolution, wrapped for httpc)
%%--------------------------------------------------------------------

%% Resolve cacertfile_arn (if present) and translate the validated ssl_options
%% map into an Erlang ssl proplist for httpc. ARN resolution happens here, in
%% the network phase, after all pure validation has passed (ARN-first
%% ordering). A resolution failure maps to input_invalid, matching the LDAP
%% backend.
build_client_ssl_opts(#{ssl_options := Map}) ->
    case resolve_cacerts(maps:get(<<"cacertfile_arn">>, Map, undefined)) of
        {error, _, _} = Err ->
            Err;
        {ok, CacertOpts} ->
            Opts = CacertOpts ++ translate_ssl_opts(Map),
            {ok, apply_verify_default(Opts)}
    end.

resolve_cacerts(undefined) ->
    {ok, []};
resolve_cacerts(Arn) when is_binary(Arn) ->
    case resolve_arn(Arn) of
        {ok, Pem} ->
            case decode_pem_cacerts(Pem) of
                skip -> {ok, []};
                Certs -> {ok, [{cacerts, Certs}]}
            end;
        {error, _} ->
            {error, input_invalid, ?REASON_ARN_RESOLVE}
    end.

%% Translate the non-cacert ssl_options keys. `sni' is the customer-facing
%% config key; ssl expects `server_name_indication', so translate it here.
translate_ssl_opts(Map) ->
    Pairs = [
        {verify, <<"verify">>, fun to_atom/1},
        {depth, <<"depth">>, fun to_integer/1},
        {versions, <<"versions">>, fun to_versions/1},
        {server_name_indication, <<"sni">>, fun to_list/1}
    ],
    lists:foldl(
        fun({SslKey, JsonKey, Fun}, Acc) ->
            case maps:get(JsonKey, Map, undefined) of
                undefined -> Acc;
                Value -> [{SslKey, Fun(Value)} | Acc]
            end
        end,
        [],
        Pairs
    ).

%% Same secure-default policy as the LDAP backend: when the caller omits
%% `verify', prefer verify_peer -- but only when a trust anchor is available
%% (caller cacerts or the OS trust store), else leave verify unset (parity with
%% a broker default of verify_none) rather than forcing a handshake that fails
%% with unknown_ca on a config the broker would accept.
apply_verify_default(Opts) ->
    case lists:keymember(verify, 1, Opts) of
        true ->
            Opts;
        false ->
            case trust_source(Opts) of
                {ok, Opts1} -> [{verify, verify_peer} | Opts1];
                none -> Opts
            end
    end.

trust_source(Opts) ->
    case lists:keymember(cacerts, 1, Opts) of
        true ->
            {ok, Opts};
        false ->
            case os_cacerts() of
                [] -> none;
                Certs -> {ok, [{cacerts, Certs} | Opts]}
            end
    end.

os_cacerts() ->
    try
        public_key:cacerts_get()
    catch
        _:_ -> []
    end.

decode_pem_cacerts(B) when is_binary(B) ->
    case public_key:pem_decode(B) of
        [] -> skip;
        Entries -> [public_key:pem_entry_decode(E) || E <- Entries]
    end.

to_list(B) when is_binary(B) -> binary_to_list(B);
to_list(L) when is_list(L) -> L.

to_atom(B) when is_binary(B) -> binary_to_existing_atom(B, utf8);
to_atom(A) when is_atom(A) -> A.

to_integer(I) when is_integer(I) -> I.

to_versions(L) when is_list(L) ->
    [to_atom(V) || V <- L].

%%--------------------------------------------------------------------
%% Shared helpers (mirror the LDAP backend)
%%--------------------------------------------------------------------

is_nonempty_binary(B) -> is_binary(B) andalso byte_size(B) > 0.

%% ARN resolution mutates the shared rabbitmq_aws region/credential singleton,
%% so serialize it across concurrent validations.
-spec resolve_arn(binary()) -> {ok, binary()} | {error, term()}.
resolve_arn(Arn) when is_binary(Arn) ->
    aws_auth_validate_arn_lock:with_lock(fun() ->
        aws_arn_util:resolve_arn(binary_to_list(Arn))
    end).

connection_timeout_ms() ->
    case application:get_env(aws, auth_validation_connection_timeout_ms) of
        {ok, Ms} when is_integer(Ms), Ms > 0 -> Ms;
        _ -> ?DEFAULT_TIMEOUT_MS
    end.
