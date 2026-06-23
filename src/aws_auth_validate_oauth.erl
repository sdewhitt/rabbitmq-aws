%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% OAuth 2.0 auth-backend reachability validation.
%%
%% Validates a `rabbitmq_auth_backend_oauth2' configuration (the oauth2.*
%% settings a customer would put in rabbitmq.conf) without a broker restart.
%% Mirrors the HTTP backend's shape: pure input validation runs first, secret
%% ARNs are resolved only after, and every outcome collapses to a fixed
%% category so the response leaks no target URL, response body, or raw httpc
%% error.
%%
%% Scope: REACHABILITY + JWKS well-formedness (deliberate first cut). WITHOUT a
%% real token we cannot assert end-to-end token verification. We CAN confirm
%% the signing-key source the broker would use is reachable, TLS-valid, and
%% serves a well-formed JWKS. Concretely, an `ok' (204) means:
%%
%%   - every configured HTTPS endpoint resolved + connected over TLS, and
%%   - the JWKS endpoint returned HTTP 200 with a JSON object containing a
%%     non-empty "keys" array (a syntactically valid JWKS).
%%
%% It does NOT mean any particular token will validate (no aud/scope/signature
%% assertion against a live JWT). This limitation MUST be reflected in customer
%% docs so the result is not over-trusted -- same caveat the LDAP dn_lookup_base
%% and HTTP reachability checks carry.
%%
%% A future credentialed mode (accept a real access token + assert full
%% decode/verify against the fetched keys, with verify_aud/resource_server_id)
%% is explicitly out of scope; noted as an open follow-up.
%%
%% Category mapping (reuses the existing aws_auth_validate_backend categories;
%% no new category is introduced, per R4 "keep the set small"):
%%   * input_invalid    (400) -- bad URL / bad ssl_options / ARN resolve fail /
%%                               SSRF-denied target.
%%   * connection_failed (400) -- host unreachable / DNS / connection refused /
%%                                timeout.
%%   * tls_failed        (400) -- TLS handshake / cert verification failure.
%%   * auth_failed       (422) -- endpoint reached but not a JWKS / discovery
%%                                doc.
%%     NOTE: auth_failed is borrowed for "endpoint did not return a usable
%%     JWKS/OIDC document". If this proves too coarse, introduce a dedicated
%%     `endpoint_unverified' category (requires extending
%%     aws_auth_validate_backend:error_category/0 and the handler's
%%     status_for_category/1).
-module(aws_auth_validate_oauth).

-behaviour(aws_auth_validate_backend).

-export([method_name/0, validate/1, allowed_fields/0]).

-ifdef(TEST).
%% Exposed for unit tests: pure helpers that a test needs to exercise without
%% network. Mirrors the HTTP/LDAP backends' -ifdef(TEST) export blocks.
-export([
    parse_input/1,
    parse_url/1,
    classify_ip/1,
    in_cidr/2,
    url_allowed/1,
    is_valid_jwks/1
]).
-endif.

%% Default per-request timeout (ms) when auth_validation_connection_timeout_ms
%% is unset. Matches the LDAP/HTTP backends' default.
-define(DEFAULT_TIMEOUT_MS, 5_000).

%% ssl_options surface, identical to the HTTP backend's (auth_oauth2.ssl_options.*
%% has the same shape as auth_http.ssl_options.*).
-define(SSL_OPTION_KEYS, [
    <<"cacertfile_arn">>,
    <<"certfile_arn">>,
    <<"keyfile_arn">>,
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
-define(REASON_MISSING_URL, <<"at least one of jwks_uri or issuer must be present">>).
-define(REASON_BAD_URL, <<"a configured URL is not a valid https URL">>).
-define(REASON_URL_NOT_ALLOWED, <<"a configured URL targets a disallowed address">>).
-define(REASON_BAD_RESOURCE_SERVER_ID, <<"resource_server_id must be a non-empty string">>).
-define(REASON_BAD_SSL_OPTIONS, <<"ssl_options must be an object">>).
-define(REASON_UNKNOWN_SSL_OPTION, <<
    "ssl_options contains an unknown key; allowed keys are cacertfile_arn, "
    "certfile_arn, keyfile_arn, verify, depth, versions, sni"
>>).
-define(REASON_BAD_SSL_VERIFY, <<"ssl_options.verify must be verify_peer or verify_none">>).
-define(REASON_BAD_SSL_DEPTH, <<"ssl_options.depth must be a non-negative integer">>).
-define(REASON_BAD_SSL_VERSIONS, <<"ssl_options.versions must be a list of known TLS versions">>).
-define(REASON_BAD_SSL_SNI, <<"ssl_options.sni must be a string">>).
-define(REASON_BAD_SSL_CACERT_ARN, <<"ssl_options.cacertfile_arn must be a non-empty string">>).
-define(REASON_BAD_SSL_CERT_ARN, <<"ssl_options.certfile_arn must be a non-empty string">>).
-define(REASON_BAD_SSL_KEY_ARN, <<"ssl_options.keyfile_arn must be a non-empty string">>).
-define(REASON_CLIENT_CERT_INCOMPLETE,
    <<"ssl_options.certfile_arn and keyfile_arn must be supplied together">>
).
-define(REASON_NO_TRUST_ANCHOR,
    <<"verify_peer requested but no CA trust anchor is available; supply cacertfile_arn">>
).
-define(REASON_CONNECTION, <<"could not connect to OAuth endpoint">>).
-define(REASON_TLS_HANDSHAKE, <<"TLS handshake failed">>).
-define(REASON_ENDPOINT, <<"endpoint did not return a valid JWKS document">>).
-define(REASON_DISCOVERY, <<"issuer discovery did not return a valid OpenID configuration">>).
-define(REASON_ARN_RESOLVE, <<"failed to resolve ARN">>).

%% SSRF: https-only scheme allowlist (stricter than the HTTP backend's http+https).
-define(ALLOWED_SCHEMES, ["https"]).

%% Always-denied address ranges -- the broker's own privileged infrastructure.
%% Mirrors the HTTP backend's policy. RFC1918 / unique-local are NOT denied:
%% a customer's IdP may live in their VPC.
-define(DENIED_V4_CIDRS, [
    %% loopback 127.0.0.0/8
    {{127, 0, 0, 0}, 8},
    %% link-local 169.254.0.0/16 (contains IMDS 169.254.169.254)
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

%% Profile pool for ephemeral httpc profiles (same sizing rationale as HTTP backend).
-define(PROFILE_POOL_SIZE, 128).

%%--------------------------------------------------------------------
%% Behaviour callbacks
%%--------------------------------------------------------------------

method_name() ->
    <<"oauth">>.

allowed_fields() ->
    [
        <<"jwks_uri">>,
        <<"issuer">>,
        <<"resource_server_id">>,
        <<"ssl_options">>
    ].

-spec validate(map()) -> aws_auth_validate_backend:result().
validate(Body) when is_map(Body) ->
    %% Same ARN-first ordering as the LDAP/HTTP backends: all pure,
    %% network-free validation (URL shape, ssl_options values, and the SSRF
    %% guard) runs before any cacertfile_arn is resolved or any request is made.
    case parse_input(Body) of
        {error, _, _} = Err ->
            Err;
        {ok, Params} ->
            do_oauth_validate(Params)
    end.

%%--------------------------------------------------------------------
%% Input parsing (pure, no network)
%%--------------------------------------------------------------------

parse_input(Body) ->
    Steps = [
        fun parse_urls/2,
        fun parse_resource_server_id/2,
        fun parse_ssl_options/2,
        %% SSRF guard runs in the pure phase so a disallowed target is rejected
        %% before any ARN resolution or outbound request.
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

%% Parse jwks_uri and issuer. At least one must be present and a valid https URL.
parse_urls(Body, Acc) ->
    JwksRaw = maps:get(<<"jwks_uri">>, Body, undefined),
    IssuerRaw = maps:get(<<"issuer">>, Body, undefined),
    case {parse_optional_url(JwksRaw), parse_optional_url(IssuerRaw)} of
        {{error, _}, _} ->
            {error, input_invalid, ?REASON_BAD_URL};
        {_, {error, _}} ->
            {error, input_invalid, ?REASON_BAD_URL};
        {none, none} ->
            {error, input_invalid, ?REASON_MISSING_URL};
        {JwksResult, IssuerResult} ->
            Acc1 =
                case JwksResult of
                    none -> Acc#{jwks_uri => undefined};
                    {ok, JwksUrl} -> Acc#{jwks_uri => JwksUrl}
                end,
            Acc2 =
                case IssuerResult of
                    none -> Acc1#{issuer => undefined};
                    {ok, IssuerUrl} -> Acc1#{issuer => IssuerUrl}
                end,
            {ok, Acc2}
    end.

%% Parse an optional URL field: undefined -> none, valid -> {ok, Parsed}, invalid -> {error, _}.
parse_optional_url(undefined) ->
    none;
parse_optional_url(V) when is_binary(V), byte_size(V) > 0 ->
    parse_url(V);
parse_optional_url(_) ->
    {error, bad_url}.

%% Parse + validate an https URL. Returns a normalized representation the probe
%% and the SSRF guard can both use.
parse_url(Bin) when is_binary(Bin) ->
    Str = binary_to_list(Bin),
    case uri_string:parse(Str) of
        #{scheme := Scheme, host := Host} = Parsed when
            Host =/= [], Scheme =:= "https"
        ->
            %% Reject:
            %%   * out-of-range port (else httpc crashes at request time)
            %%   * userinfo (embedded credentials)
            %%   * pre-existing query string (OIDC discovery appends well-known path)
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

parse_resource_server_id(Body, Acc) ->
    case maps:get(<<"resource_server_id">>, Body, undefined) of
        undefined ->
            {ok, Acc};
        V when is_binary(V), byte_size(V) > 0 ->
            {ok, Acc};
        _ ->
            {error, input_invalid, ?REASON_BAD_RESOURCE_SERVER_ID}
    end.

%% ssl_options parsing: validate both keys and values in the pure phase so a
%% mis-typed value cannot be silently dropped and re-defaulted.
parse_ssl_options(Body, Acc) ->
    case maps:get(<<"ssl_options">>, Body, undefined) of
        undefined ->
            {ok, Acc#{ssl_options => #{}}};
        Map when is_map(Map) ->
            case [K || K <- maps:keys(Map), not lists:member(K, ?SSL_OPTION_KEYS)] of
                [_ | _] ->
                    {error, input_invalid, ?REASON_UNKNOWN_SSL_OPTION};
                [] ->
                    %% Client cert + key are an inseparable pair: one without
                    %% the other cannot build an mTLS identity. Reject in the
                    %% pure phase before resolving either ARN.
                    HasCert = maps:is_key(<<"certfile_arn">>, Map),
                    HasKey = maps:is_key(<<"keyfile_arn">>, Map),
                    case HasCert =:= HasKey of
                        false -> {error, input_invalid, ?REASON_CLIENT_CERT_INCOMPLETE};
                        true -> validate_ssl_values(maps:to_list(Map), Acc, Map)
                    end
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
    end;
valid_ssl_value(<<"certfile_arn">>, V) ->
    case is_nonempty_binary(V) of
        true -> ok;
        false -> {error, input_invalid, ?REASON_BAD_SSL_CERT_ARN}
    end;
valid_ssl_value(<<"keyfile_arn">>, V) ->
    case is_nonempty_binary(V) of
        true -> ok;
        false -> {error, input_invalid, ?REASON_BAD_SSL_KEY_ARN}
    end.

%%--------------------------------------------------------------------
%% SSRF guard
%%--------------------------------------------------------------------
%%
%% Same two-phase defense as the HTTP backend:
%%   * PURE phase (guard_urls/2): scheme allowlist (https-only) + literal-IP
%%     classification against the infra denylist.
%%   * NETWORK phase (resolve_and_pin/1): resolve hostname to all A/AAAA,
%%     deny if ANY is blocked infra, connect to pinned IP with Host/SNI
%%     preserved. No redirect following (autoredirect=false).

guard_urls(_Body, Acc) ->
    Urls = collect_guard_urls(Acc),
    case check_urls(Urls) of
        ok -> {ok, Acc};
        {error, _, _} = Err -> Err
    end.

collect_guard_urls(#{jwks_uri := undefined, issuer := undefined}) ->
    [];
collect_guard_urls(#{jwks_uri := undefined, issuer := IssuerUrl}) ->
    [IssuerUrl];
collect_guard_urls(#{jwks_uri := JwksUrl, issuer := undefined}) ->
    [JwksUrl];
collect_guard_urls(#{jwks_uri := JwksUrl, issuer := IssuerUrl}) ->
    [JwksUrl, IssuerUrl].

check_urls([]) ->
    ok;
check_urls([Url | Rest]) ->
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
%% ranges only. IPv6 notations that embed a v4 address are unwrapped and
%% re-classified (DNS-rebinding defense via v6-encoded addresses).
classify_ip({0, 0, 0, 0, 0, 16#ffff, W1, W2}) ->
    %% IPv4-mapped ::ffff:a.b.c.d
    classify_ip(v4_from_words(W1, W2));
classify_ip({0, 0, 0, 0, 0, 0, W1, W2}) when {W1, W2} =/= {0, 0}, {W1, W2} =/= {0, 1} ->
    %% IPv4-compatible ::a.b.c.d (RFC4291-deprecated). Guard lets :: and ::1
    %% fall through to the v6 denylist.
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
%% Network phase: fetch JWKS (and optionally discover via issuer)
%%--------------------------------------------------------------------
%%
%% The whole network section runs inside a try/catch collapsing any raise to
%% connection_failed, so a resolved secret can never reach a crash report (R6).
%% All probe requests run on a dedicated ephemeral httpc profile (R3).

do_oauth_validate(Params) ->
    Profile = probe_profile_name(),
    case start_probe_profile(Profile) of
        false ->
            {error, connection_failed, ?REASON_CONNECTION};
        true ->
            try
                case build_client_ssl_opts(Params) of
                    {error, _, _} = Err ->
                        Err;
                    {ok, SslOpts} ->
                        do_fetch_jwks(Params, SslOpts, Profile)
                end
            catch
                _Class:_Reason:_Stack ->
                    {error, connection_failed, ?REASON_CONNECTION}
            after
                stop_probe_profile(Profile)
            end
    end.

%% Determine the JWKS URI (given directly or derived via issuer discovery)
%% and fetch + validate it.
do_fetch_jwks(#{jwks_uri := JwksUrl, issuer := _Issuer, timeout := Timeout}, SslOpts, Profile) when
    JwksUrl =/= undefined
->
    %% jwks_uri is given directly -- fetch it.
    fetch_and_validate_jwks(JwksUrl, SslOpts, Timeout, Profile);
do_fetch_jwks(#{jwks_uri := undefined, issuer := IssuerUrl, timeout := Timeout}, SslOpts, Profile) ->
    %% Only issuer given: discover jwks_uri from the OIDC discovery endpoint.
    case discover_jwks_uri(IssuerUrl, SslOpts, Timeout, Profile) of
        {error, _, _} = Err ->
            Err;
        {ok, DerivedUrl} ->
            %% SSRF-guard + resolve_and_pin the derived URL before fetching it.
            case url_allowed(DerivedUrl) of
                {error, _, _} = Err ->
                    Err;
                ok ->
                    fetch_and_validate_jwks(DerivedUrl, SslOpts, Timeout, Profile)
            end
    end.

%% Fetch {issuer}/.well-known/openid-configuration, JSON-decode, extract jwks_uri.
discover_jwks_uri(IssuerUrl, SslOpts, Timeout, Profile) ->
    %% Build the discovery URL by appending the well-known path.
    %% Strip any trailing slash from the issuer to avoid double-slash paths
    %% (e.g. "https://idp.example.com//" which some IdPs reject with 404).
    DiscoveryUrlStr =
        strip_trailing_slash(maps:get(url_string, IssuerUrl)) ++
            "/.well-known/openid-configuration",
    case resolve_and_pin(IssuerUrl) of
        {error, _, _} = Err ->
            Err;
        {ok, PinnedUrl, Host} ->
            PinnedDiscoveryStr =
                strip_trailing_slash(maps:get(url_string, PinnedUrl)) ++
                    "/.well-known/openid-configuration",
            HttpOpts =
                [
                    {timeout, Timeout},
                    {connect_timeout, Timeout},
                    {autoredirect, false}
                ] ++ ssl_http_opt(Host, SslOpts),
            Request = {PinnedDiscoveryStr, [{"host", Host}]},
            case httpc:request(get, Request, HttpOpts, [{body_format, binary}], Profile) of
                {ok, {{_Vsn, 200, _Phrase}, _Headers, Body}} ->
                    parse_discovery_doc(Body, DiscoveryUrlStr);
                {ok, {{_Vsn, _Code, _Phrase}, _Headers, _Body}} ->
                    {error, auth_failed, ?REASON_DISCOVERY};
                {error, Reason} ->
                    classify_http_error(Reason)
            end
    end.

%% Parse the OIDC discovery document and extract jwks_uri.
parse_discovery_doc(Body, _DiscoveryUrlStr) ->
    case rabbit_json:try_decode(Body) of
        {ok, Map} when is_map(Map) ->
            case maps:get(<<"jwks_uri">>, Map, undefined) of
                JwksUriBin when is_binary(JwksUriBin), byte_size(JwksUriBin) > 0 ->
                    case parse_url(JwksUriBin) of
                        {ok, Parsed} -> {ok, Parsed};
                        {error, _} -> {error, auth_failed, ?REASON_DISCOVERY}
                    end;
                _ ->
                    {error, auth_failed, ?REASON_DISCOVERY}
            end;
        _ ->
            {error, auth_failed, ?REASON_DISCOVERY}
    end.

%% Fetch the JWKS endpoint and validate the response is a well-formed JWKS.
fetch_and_validate_jwks(JwksUrl, SslOpts, Timeout, Profile) ->
    case resolve_and_pin(JwksUrl) of
        {error, _, _} = Err ->
            Err;
        {ok, PinnedUrl, Host} ->
            UrlStr = maps:get(url_string, PinnedUrl),
            HttpOpts =
                [
                    {timeout, Timeout},
                    {connect_timeout, Timeout},
                    {autoredirect, false}
                ] ++ ssl_http_opt(Host, SslOpts),
            Request = {UrlStr, [{"host", Host}]},
            case httpc:request(get, Request, HttpOpts, [{body_format, binary}], Profile) of
                {ok, {{_Vsn, 200, _Phrase}, _Headers, Body}} ->
                    case is_valid_jwks(Body) of
                        true -> ok;
                        false -> {error, auth_failed, ?REASON_ENDPOINT}
                    end;
                {ok, {{_Vsn, _Code, _Phrase}, _Headers, _Body}} ->
                    {error, auth_failed, ?REASON_ENDPOINT};
                {error, Reason} ->
                    classify_http_error(Reason)
            end
    end.

%% Validate that a response body is a well-formed JWKS: a JSON object whose
%% "keys" field is a non-empty array.
is_valid_jwks(Body) when is_binary(Body) ->
    case rabbit_json:try_decode(Body) of
        {ok, Map} when is_map(Map) ->
            case maps:get(<<"keys">>, Map, undefined) of
                Keys when is_list(Keys), Keys =/= [] -> true;
                _ -> false
            end;
        _ ->
            false
    end.

%%--------------------------------------------------------------------
%% DNS resolve-and-pin (SSRF network-phase defense)
%%--------------------------------------------------------------------

%% Resolve the URL's host to all addresses, deny if ANY is a blocked infra
%% address, and return the URL rewritten to connect to a single pinned IP plus
%% the original host (for the Host header / SNI).
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
                    {error, input_invalid, ?REASON_URL_NOT_ALLOWED};
                false ->
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
pin_url(Url, PinHost) ->
    Rebuilt = uri_string:recompose(maps:without([url_string], Url#{host => PinHost})),
    Url#{url_string => Rebuilt}.

%% Strip a single trailing slash from a URL string to avoid producing
%% double-slash paths when appending "/.well-known/..." to an issuer URL
%% that already ends with "/".
strip_trailing_slash(S) ->
    case lists:reverse(S) of
        [$/ | Rest] -> lists:reverse(Rest);
        _ -> S
    end.

%%--------------------------------------------------------------------
%% httpc error classification
%%--------------------------------------------------------------------

classify_http_error(Reason) ->
    case is_tls_error(Reason) of
        true -> {error, tls_failed, ?REASON_TLS_HANDSHAKE};
        false -> {error, connection_failed, ?REASON_CONNECTION}
    end.

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

%%--------------------------------------------------------------------
%% Ephemeral httpc profile management
%%--------------------------------------------------------------------

probe_profile_name() ->
    Slot = erlang:phash2(make_ref(), ?PROFILE_POOL_SIZE),
    list_to_atom("aws_auth_validate_oauth_" ++ integer_to_list(Slot)).

start_probe_profile(Profile) ->
    case inets:start(httpc, [{profile, Profile}]) of
        {ok, _Pid} ->
            set_probe_profile_opts(Profile),
            true;
        {error, {already_started, _}} ->
            _ = inets:stop(httpc, Profile),
            case inets:start(httpc, [{profile, Profile}]) of
                {ok, _Pid} ->
                    set_probe_profile_opts(Profile),
                    true;
                _ ->
                    false
            end;
        _ ->
            false
    end.

set_probe_profile_opts(Profile) ->
    _ = httpc:set_options(
        [{max_sessions, 0}, {max_keep_alive_length, 0}, {keep_alive_timeout, 0}],
        Profile
    ),
    ok.

stop_probe_profile(Profile) ->
    _ = inets:stop(httpc, Profile),
    ok.

%%--------------------------------------------------------------------
%% TLS option shaping (mirrors the HTTP backend's resolution, for httpc)
%%--------------------------------------------------------------------

%% Only attach ssl options for https targets (which is all of them for OAuth,
%% since we enforce https-only). server_name_indication is forced to the
%% ORIGINAL hostname (not the pinned IP) so SNI and certificate hostname
%% verification validate against the name the customer configured.
ssl_http_opt(Host, SslOpts) ->
    [{ssl, with_default_sni(SslOpts, Host)}].

with_default_sni(SslOpts, Host) ->
    case lists:keymember(server_name_indication, 1, SslOpts) of
        true -> SslOpts;
        false -> [{server_name_indication, Host} | SslOpts]
    end.

%% Resolve the ARN-backed TLS material (CA bundle, and the client cert+key for
%% mTLS) and translate the validated ssl_options map into an Erlang ssl
%% proplist for httpc. ARN resolution happens here, in the network phase, after
%% all pure validation has passed (ARN-first ordering).
build_client_ssl_opts(#{ssl_options := Map}) ->
    case resolve_cacerts(maps:get(<<"cacertfile_arn">>, Map, undefined)) of
        {error, _, _} = Err ->
            Err;
        {ok, CacertOpts} ->
            case resolve_client_cert(Map) of
                {error, _, _} = Err ->
                    Err;
                {ok, ClientOpts} ->
                    Opts = CacertOpts ++ ClientOpts ++ translate_ssl_opts(Map),
                    VerifyExplicit = maps:is_key(<<"verify">>, Map),
                    apply_verify_default(Opts, VerifyExplicit)
            end
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

resolve_client_cert(#{<<"certfile_arn">> := CertArn, <<"keyfile_arn">> := KeyArn}) when
    is_binary(CertArn), is_binary(KeyArn)
->
    case resolve_arn(CertArn) of
        {ok, CertPem} ->
            case decode_client_cert(CertPem) of
                {error, _, _} = Err ->
                    Err;
                {ok, CertOpt} ->
                    case resolve_arn(KeyArn) of
                        {ok, KeyPem} ->
                            case decode_client_key(KeyPem) of
                                {error, _, _} = Err -> Err;
                                {ok, KeyOpt} -> {ok, [CertOpt, KeyOpt]}
                            end;
                        {error, _} ->
                            {error, input_invalid, ?REASON_ARN_RESOLVE}
                    end
            end;
        {error, _} ->
            {error, input_invalid, ?REASON_ARN_RESOLVE}
    end;
resolve_client_cert(_Map) ->
    {ok, []}.

decode_client_cert(Pem) when is_binary(Pem) ->
    case [Der || {'Certificate', Der, not_encrypted} <- public_key:pem_decode(Pem)] of
        [] -> {error, input_invalid, ?REASON_ARN_RESOLVE};
        Ders -> {ok, {cert, Ders}}
    end.

decode_client_key(Pem) when is_binary(Pem) ->
    KeyEntries = [
        {Type, Der}
     || {Type, Der, not_encrypted} <- public_key:pem_decode(Pem),
        lists:member(Type, [
            'PrivateKeyInfo', 'RSAPrivateKey', 'ECPrivateKey', 'DSAPrivateKey'
        ])
    ],
    case KeyEntries of
        [{Type, Der} | _] -> {ok, {key, {Type, Der}}};
        [] -> {error, input_invalid, ?REASON_ARN_RESOLVE}
    end.

translate_ssl_opts(Map) ->
    Pairs = [
        {verify, <<"verify">>, fun to_verify/1},
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

%% Ensure verify_peer always has a trust anchor. Policy mirrors the HTTP backend:
%%   * EXPLICIT verify_peer + no cacerts -> OS store or FAIL.
%%   * DEFAULTED verify (caller omitted) -> verify_peer when anchor exists, else
%%     leave unset (broker-parity verify_none).
%%   * Explicit verify_none -> untouched.
apply_verify_default(Opts, VerifyExplicit) ->
    case lists:keyfind(verify, 1, Opts) of
        {verify, verify_peer} when VerifyExplicit ->
            case ensure_trust_anchor(Opts) of
                {ok, _} = Ok -> Ok;
                none -> {error, tls_failed, ?REASON_NO_TRUST_ANCHOR}
            end;
        {verify, verify_peer} ->
            case ensure_trust_anchor(Opts) of
                {ok, Opts1} -> {ok, Opts1};
                none -> {ok, lists:keyreplace(verify, 1, Opts, {verify, verify_none})}
            end;
        {verify, _Other} ->
            {ok, Opts};
        false ->
            case trust_source(Opts) of
                {ok, Opts1} -> {ok, [{verify, verify_peer} | Opts1]};
                none -> {ok, Opts}
            end
    end.

ensure_trust_anchor(Opts) ->
    case lists:keymember(cacerts, 1, Opts) of
        true ->
            {ok, Opts};
        false ->
            case os_cacerts() of
                [] -> none;
                Certs -> {ok, [{cacerts, Certs} | Opts]}
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

to_integer(I) when is_integer(I) -> I.

to_verify(<<"verify_peer">>) -> verify_peer;
to_verify(<<"verify_none">>) -> verify_none.

to_versions(L) when is_list(L) ->
    [to_version(V) || V <- L].

to_version(<<"tlsv1.3">>) -> 'tlsv1.3';
to_version(<<"tlsv1.2">>) -> 'tlsv1.2';
to_version(<<"tlsv1.1">>) -> 'tlsv1.1';
to_version(<<"tlsv1">>) -> tlsv1.

%%--------------------------------------------------------------------
%% Shared helpers
%%--------------------------------------------------------------------

is_nonempty_binary(B) -> is_binary(B) andalso byte_size(B) > 0.

%% ARN resolution: threaded state, no global singleton mutation. See the HTTP
%% backend's identical resolve_arn/1 for the full rationale (R3, R6).
-spec resolve_arn(binary()) -> {ok, binary()} | {error, term()}.
resolve_arn(Arn) when is_binary(Arn) ->
    State = aws_lib:new(),
    case aws_arn_util:resolve_arn(binary_to_list(Arn), State) of
        {ok, Data, _State1} -> {ok, Data};
        {error, _} = Error -> Error
    end.

connection_timeout_ms() ->
    case application:get_env(aws, auth_validation_connection_timeout_ms) of
        {ok, Ms} when is_integer(Ms), Ms > 0 -> Ms;
        _ -> ?DEFAULT_TIMEOUT_MS
    end.
