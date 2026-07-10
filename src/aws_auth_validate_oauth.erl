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
    is_valid_jwks/1,
    parse_scopes/1,
    build_grant_body/3,
    has_access_token/1
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
-define(REASON_CONNECTION, <<"could not connect to OAuth endpoint">>).
-define(REASON_TLS_HANDSHAKE, <<"TLS handshake failed">>).
-define(REASON_ENDPOINT, <<"endpoint did not return a valid JWKS document">>).
%% client_credentials token-fetch tier (optional, activates when token_endpoint
%% is present). Fixed R4 reasons: no URL, client_id, secret, or token echoed.
-define(REASON_BAD_TOKEN_ENDPOINT, <<"token_endpoint is not a valid https URL">>).
-define(REASON_MISSING_GRANT_FIELDS, <<
    "token_endpoint requires client_id and client_secret_arn"
>>).
-define(REASON_BAD_CLIENT_ID, <<"client_id must be a non-empty string">>).
-define(REASON_BAD_CLIENT_SECRET_ARN, <<"client_secret_arn must be a non-empty string">>).
-define(REASON_BAD_SCOPES, <<"scopes must be a string or a list of non-empty strings">>).
-define(REASON_GRANT_REJECTED, <<"token endpoint rejected the client_credentials grant">>).
-define(REASON_DISCOVERY, <<"issuer discovery did not return a valid OpenID configuration">>).
-define(REASON_ASSUME_ROLE, <<"failed to assume the configured role">>).
-define(REASON_NO_ASSUME_ROLE, <<
    "auth validation requires an assume_role to be configured; "
    "set aws.arns.assume_role_arn"
>>).

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

%% Ephemeral httpc profile-name prefix for this backend's pool (shared pool
%% machinery in aws_auth_validate_httpc). Disjoint from the http prefix so the
%% two backends' pools never collide.
-define(PROFILE_PREFIX, "aws_auth_validate_oauth_").

%% Per-backend surface passed to the shared aws_auth_validate_ssl helpers.
%% Identical shape to the HTTP backend's (both accept the mTLS pair and use the
%% <<"sni">> key); only this backend's fixed R4 reason strings differ, kept here.
ssl_opts() ->
    #{
        arn_keys => [<<"cacertfile_arn">>, <<"certfile_arn">>, <<"keyfile_arn">>],
        %% client_secret_arn is a top-level (non-ssl_options) ARN-backed secret:
        %% referencing it forces the assume_role guardrail just like a TLS ARN.
        %% The key matches how parse_grant/2 stores it in the accumulator (atom).
        param_arn_keys => [client_secret_arn],
        ssl_option_keys => ?SSL_OPTION_KEYS,
        sni_key => <<"sni">>,
        client_cert => true,
        reasons => #{
            no_assume_role => ?REASON_NO_ASSUME_ROLE,
            assume_role => ?REASON_ASSUME_ROLE,
            unknown_ssl_option => ?REASON_UNKNOWN_SSL_OPTION,
            client_cert_incomplete => ?REASON_CLIENT_CERT_INCOMPLETE,
            bad_ssl_options => ?REASON_BAD_SSL_OPTIONS,
            bad_ssl_verify => ?REASON_BAD_SSL_VERIFY,
            bad_ssl_depth => ?REASON_BAD_SSL_DEPTH,
            bad_ssl_versions => ?REASON_BAD_SSL_VERSIONS,
            bad_ssl_sni => ?REASON_BAD_SSL_SNI,
            bad_ssl_cacert_arn => ?REASON_BAD_SSL_CACERT_ARN,
            bad_ssl_cert_arn => ?REASON_BAD_SSL_CERT_ARN,
            bad_ssl_key_arn => ?REASON_BAD_SSL_KEY_ARN
        }
    }.

%% SSRF policy passed to the shared aws_auth_validate_net guard: this backend's
%% infra denylists, its scheme allowlist (https-only -- stricter than the HTTP
%% backend), and the fixed reason strings for a disallowed target / an
%% unreachable host.
net_policy() ->
    #{
        denied_v4 => ?DENIED_V4_CIDRS,
        denied_v6 => ?DENIED_V6_CIDRS,
        allowed_schemes => ?ALLOWED_SCHEMES,
        reason_not_allowed => ?REASON_URL_NOT_ALLOWED,
        reason_connection => ?REASON_CONNECTION
    }.

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
        <<"ssl_options">>,
        %% Optional client_credentials token-fetch tier. Present token_endpoint
        %% activates the grant; client_id + client_secret_arn are then required.
        <<"token_endpoint">>,
        <<"client_id">>,
        <<"client_secret_arn">>,
        <<"scopes">>
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
            case resolve_request_state(Params) of
                {error, _, _} = Err -> Err;
                {ok, Params1} -> do_oauth_validate(Params1)
            end
    end.

%% Build the per-request aws_lib state used for every ARN fetch in this request
%% (ssl_options.cacertfile_arn / certfile_arn / keyfile_arn), and thread it into
%% Params. Resolving an ARN triggers an STS AssumeRole call (ARN-first ordering).
%%
%% Mirrors the LDAP/HTTP backends' guardrail (resolve_request_state/1 there):
%% when the request resolves ANY ARN, a configured `aws.arns.assume_role_arn' is
%% MANDATORY. We assume that role -- the SAME role the plugin already assumes at
%% boot to resolve every configured ARN (aws_arn_config:maybe_assume_role/1) --
%% into a request-local aws_lib state and resolve the TLS-material ARNs under it.
%% This is operator config, not caller input, so it raises no confused-deputy
%% concern.
%%
%% When NO role is configured we do NOT fall back to a default aws_lib state:
%% that would resolve ARNs with the broker's ambient (EC2 instance) credentials,
%% which on Amazon MQ can be far more privileged than the role a customer would
%% attach to their own secret/bucket, so a validate request could resolve ARNs
%% the caller's intended role never could -- a least-privilege pitfall. We never
%% use the instance role: with an ARN referenced and no assume_role configured,
%% refuse with config_conflict before any secret fetch or outbound connection.
%%
%% A plain reachability probe that references no ARN performs no AWS call, so it
%% needs no role and gets a default state that is never used to resolve an ARN --
%% preserving the credential-free JWKS reachability check.
resolve_request_state(Params) ->
    aws_auth_validate_ssl:resolve_request_state(Params, ssl_opts()).

%%--------------------------------------------------------------------
%% Input parsing (pure, no network)
%%--------------------------------------------------------------------

parse_input(Body) ->
    Steps = [
        fun parse_urls/2,
        fun parse_resource_server_id/2,
        fun parse_ssl_options/2,
        %% parse_grant is pure: it shape-checks the optional client_credentials
        %% fields but performs no ARN resolution or network I/O.
        fun parse_grant/2,
        %% SSRF guard runs in the pure phase so a disallowed target (including the
        %% token_endpoint) is rejected before any ARN resolution or outbound request.
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

%% ssl_options parsing (keys + values, mTLS pairing) is shared across backends;
%% delegate to aws_auth_validate_ssl with this backend's surface (ssl_opts/0).
parse_ssl_options(Body, Acc) ->
    aws_auth_validate_ssl:parse_ssl_options(
        maps:get(<<"ssl_options">>, Body, undefined), Acc, ssl_opts()
    ).

%% Parse the optional client_credentials token-fetch fields (pure phase; no ARN
%% resolution, no network). The tier ACTIVATES only when token_endpoint is
%% present; then client_id and client_secret_arn are REQUIRED. When absent, the
%% accumulator carries grant => none and behaviour is unchanged (pure JWKS
%% reachability). The client_secret_arn is stored under the atom key
%% `client_secret_arn' so resolve_request_state/1 (via param_arn_keys) detects
%% the ARN reference and enforces the assume_role guardrail. The secret VALUE is
%% NOT resolved here.
parse_grant(Body, Acc) ->
    case maps:get(<<"token_endpoint">>, Body, undefined) of
        undefined ->
            {ok, Acc#{grant => none}};
        TokenEndpointRaw ->
            case parse_optional_url(TokenEndpointRaw) of
                {ok, TokenUrl} ->
                    parse_grant_fields(Body, Acc, TokenUrl);
                _ ->
                    {error, input_invalid, ?REASON_BAD_TOKEN_ENDPOINT}
            end
    end.

parse_grant_fields(Body, Acc, TokenUrl) ->
    ClientId = maps:get(<<"client_id">>, Body, undefined),
    SecretArn = maps:get(<<"client_secret_arn">>, Body, undefined),
    %% Precedence: a MISSING required field (undefined) is reported as the
    %% generic "requires client_id and client_secret_arn" first; only a PRESENT
    %% but malformed value gets the field-specific reason.
    %% Guards may not call the local is_nonempty_binary/1, so the non-empty
    %% binary test is inlined here (is_binary/1 + byte_size/1 are guard BIFs).
    if
        ClientId =:= undefined orelse SecretArn =:= undefined ->
            {error, input_invalid, ?REASON_MISSING_GRANT_FIELDS};
        not (is_binary(ClientId) andalso byte_size(ClientId) > 0) ->
            {error, input_invalid, ?REASON_BAD_CLIENT_ID};
        not (is_binary(SecretArn) andalso byte_size(SecretArn) > 0) ->
            {error, input_invalid, ?REASON_BAD_CLIENT_SECRET_ARN};
        true ->
            case parse_scopes(maps:get(<<"scopes">>, Body, undefined)) of
                {ok, Scopes} ->
                    {ok, Acc#{
                        grant => #{
                            token_endpoint => TokenUrl,
                            client_id => ClientId,
                            scopes => Scopes
                        },
                        %% Stored top-level so param_arn_keys detects the ARN.
                        client_secret_arn => SecretArn
                    }};
                {error, _, _} = Err ->
                    Err
            end
    end.

%% scopes may be absent (none), a single space-delimited string, or a list of
%% non-empty strings. Normalize to a single space-delimited binary (or none).
parse_scopes(undefined) ->
    {ok, none};
parse_scopes(V) when is_binary(V), byte_size(V) > 0 ->
    {ok, V};
parse_scopes(List) when is_list(List), List =/= [] ->
    case lists:all(fun is_nonempty_binary/1, List) of
        true -> {ok, iolist_to_binary(lists:join(<<" ">>, List))};
        false -> {error, input_invalid, ?REASON_BAD_SCOPES}
    end;
parse_scopes(_) ->
    {error, input_invalid, ?REASON_BAD_SCOPES}.

is_nonempty_binary(V) -> is_binary(V) andalso byte_size(V) > 0.

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

%% Collect every URL that must pass the pure SSRF guard: the JWKS/issuer
%% endpoint(s) and, when the client_credentials tier is active, the token
%% endpoint too. undefined slots are dropped.
collect_guard_urls(Acc) ->
    JwksIssuer = [
        U
     || U <- [maps:get(jwks_uri, Acc, undefined), maps:get(issuer, Acc, undefined)],
        U =/= undefined
    ],
    case maps:get(grant, Acc, none) of
        #{token_endpoint := TokenUrl} -> [TokenUrl | JwksIssuer];
        _ -> JwksIssuer
    end.

check_urls([]) ->
    ok;
check_urls([Url | Rest]) ->
    case aws_auth_validate_net:url_allowed(Url, net_policy()) of
        ok -> check_urls(Rest);
        {error, _, _} = Err -> Err
    end.

-ifdef(TEST).
%% TEST-only wrappers exposing the shared SSRF guard under this backend's policy,
%% so the module's -ifdef(TEST) export contract stays stable. Production code
%% calls aws_auth_validate_net directly.
url_allowed(Url) -> aws_auth_validate_net:url_allowed(Url, net_policy()).
classify_ip(IP) -> aws_auth_validate_net:classify_ip(IP, net_policy()).
in_cidr(IP, Cidr) -> aws_auth_validate_net:in_cidr(IP, Cidr).
-endif.

%%--------------------------------------------------------------------
%% Network phase: fetch JWKS (and optionally discover via issuer)
%%--------------------------------------------------------------------
%%
%% The whole network section runs inside a try/catch collapsing any raise to
%% connection_failed, so a resolved secret can never reach a crash report (R6).
%% All probe requests run on a dedicated ephemeral httpc profile (R3).

do_oauth_validate(Params) ->
    case aws_auth_validate_httpc:claim_probe_profile(?PROFILE_PREFIX) of
        none ->
            %% Could not obtain an isolated profile; fail safe rather than fall
            %% back to the shared default profile (which would reintroduce the
            %% session-reuse hazard). Unreachable in practice -- the semaphore
            %% caps concurrency below the pool size -- but must be handled.
            {error, connection_failed, ?REASON_CONNECTION};
        {ok, Profile} ->
            try
                case build_client_ssl_opts(Params) of
                    {error, _, _} = Err ->
                        Err;
                    {ok, SslOpts} ->
                        %% Always validate the JWKS source first (reachability +
                        %% well-formedness). Only if that passes AND a grant is
                        %% configured do we attempt the client_credentials fetch.
                        case do_fetch_jwks(Params, SslOpts, Profile) of
                            ok -> maybe_fetch_token(Params, SslOpts, Profile);
                            {error, _, _} = Err -> Err
                        end
                end
            catch
                _Class:_Reason:_Stack ->
                    {error, connection_failed, ?REASON_CONNECTION}
            after
                %% Only ever stop the profile THIS request started (claimed).
                aws_auth_validate_httpc:stop_probe_profile(Profile)
            end
    end.

%% When the client_credentials tier is inactive (grant => none), JWKS
%% reachability alone is the result. When active, resolve the client secret
%% (ARN, under the assume_role guardrail) and POST the grant to the pinned
%% token endpoint.
maybe_fetch_token(#{grant := none}, _SslOpts, _Profile) ->
    ok;
maybe_fetch_token(#{grant := Grant, timeout := Timeout} = Params, SslOpts, Profile) ->
    case resolve_client_secret(Params) of
        {error, _, _} = Err ->
            Err;
        {ok, Secret} ->
            do_token_grant(Grant, Secret, SslOpts, Profile, Timeout)
    end.

%% Resolve client_secret_arn via the shared ARN path. The threaded aws_state was
%% built by resolve_request_state/1 under the configured assume_role (mandatory
%% because client_secret_arn is a param_arn_key). A resolve failure collapses to
%% input_invalid with a fixed reason -- neither the ARN nor the secret is echoed.
resolve_client_secret(#{client_secret_arn := Arn} = Params) ->
    State = maps:get(aws_state, Params, none),
    case aws_auth_validate_ssl:resolve_arn(Arn, State) of
        {ok, Secret} when is_binary(Secret) -> {ok, Secret};
        {error, _} -> {error, input_invalid, ?REASON_BAD_CLIENT_SECRET_ARN}
    end.

%% POST grant_type=client_credentials to the pinned token endpoint. The resolved
%% secret is used ONLY to build the form body and is never logged or returned.
%% A 200 carrying a non-empty access_token -> ok; an IdP rejection (any non-200,
%% or a 200 without a usable token) -> auth_failed. Connection/TLS errors are
%% classified as elsewhere. No redirects are followed.
do_token_grant(
    #{token_endpoint := TokenUrl, client_id := ClientId, scopes := Scopes},
    Secret,
    SslOpts,
    Profile,
    Timeout
) ->
    case aws_auth_validate_net:resolve_and_pin(TokenUrl, net_policy()) of
        {error, _, _} = Err ->
            Err;
        {ok, PinnedUrl, Host} ->
            UrlStr = maps:get(url_string, PinnedUrl),
            FormBody = build_grant_body(ClientId, Secret, Scopes),
            HttpOpts =
                [
                    {timeout, Timeout},
                    {connect_timeout, Timeout},
                    {autoredirect, false}
                ] ++ ssl_http_opt(Host, SslOpts),
            Headers = [{"host", Host}],
            ContentType = "application/x-www-form-urlencoded",
            Request = {UrlStr, Headers, ContentType, FormBody},
            case httpc:request(post, Request, HttpOpts, [{body_format, binary}], Profile) of
                {ok, {{_Vsn, 200, _Phrase}, _RespHeaders, RespBody}} ->
                    case has_access_token(RespBody) of
                        true -> ok;
                        false -> {error, auth_failed, ?REASON_GRANT_REJECTED}
                    end;
                {ok, {{_Vsn, _Code, _Phrase}, _RespHeaders, _RespBody}} ->
                    {error, auth_failed, ?REASON_GRANT_REJECTED};
                {error, Reason} ->
                    classify_http_error(Reason)
            end
    end.

%% Build the x-www-form-urlencoded grant body. Every value is percent-encoded so
%% the secret cannot break out of the field or corrupt the request. The returned
%% binary is handed straight to httpc and is not retained or logged.
build_grant_body(ClientId, Secret, Scopes) ->
    Base = [
        {"grant_type", "client_credentials"},
        {"client_id", binary_to_list(ClientId)},
        {"client_secret", binary_to_list(Secret)}
    ],
    Pairs =
        case Scopes of
            none -> Base;
            _ -> Base ++ [{"scope", binary_to_list(Scopes)}]
        end,
    Encoded = [K ++ "=" ++ percent_encode(V) || {K, V} <- Pairs],
    list_to_binary(lists:join("&", Encoded)).

%% RFC 3986 percent-encoding for application/x-www-form-urlencoded values.
percent_encode(Str) ->
    uri_string:quote(Str).

%% True when the token response is a JSON object carrying a non-empty
%% access_token string. The token itself is inspected only for presence and is
%% never logged or returned (R6).
has_access_token(Body) when is_binary(Body) ->
    case rabbit_json:try_decode(Body) of
        {ok, Map} when is_map(Map) ->
            case maps:get(<<"access_token">>, Map, undefined) of
                Tok when is_binary(Tok), byte_size(Tok) > 0 -> true;
                _ -> false
            end;
        _ ->
            false
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
            case aws_auth_validate_net:url_allowed(DerivedUrl, net_policy()) of
                {error, _, _} = Err ->
                    Err;
                ok ->
                    fetch_and_validate_jwks(DerivedUrl, SslOpts, Timeout, Profile)
            end
    end.

%% Fetch {issuer}/.well-known/openid-configuration, JSON-decode, extract jwks_uri.
discover_jwks_uri(IssuerUrl, SslOpts, Timeout, Profile) ->
    case aws_auth_validate_net:resolve_and_pin(IssuerUrl, net_policy()) of
        {error, _, _} = Err ->
            Err;
        {ok, PinnedUrl, Host} ->
            %% Build the discovery URL by appending the well-known path to the
            %% pinned URL. Strip any trailing slash from the issuer to avoid
            %% double-slash paths (e.g. "https://idp.example.com//" which some
            %% IdPs reject with 404).
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
                    parse_discovery_doc(Body);
                {ok, {{_Vsn, _Code, _Phrase}, _Headers, _Body}} ->
                    {error, auth_failed, ?REASON_DISCOVERY};
                {error, Reason} ->
                    classify_http_error(Reason)
            end
    end.

%% Parse the OIDC discovery document and extract jwks_uri.
parse_discovery_doc(Body) ->
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
    case aws_auth_validate_net:resolve_and_pin(JwksUrl, net_policy()) of
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

%% Shared classifier: TLS/cert failure -> tls_failed, else connection_failed.
%% The raw reason is never echoed (R4).
classify_http_error(Reason) ->
    aws_auth_validate_ssl:classify_http_error(
        Reason, ?REASON_TLS_HANDSHAKE, ?REASON_CONNECTION
    ).

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

%% Resolve the ARN-backed TLS material (CA bundle + optional mTLS client cert)
%% and translate the validated ssl_options into an ssl proplist for httpc. The
%% resolution, decoding, and verify-default policy are shared
%% (aws_auth_validate_ssl); only the SNI key spelling (<<"sni">>) is
%% backend-specific.
build_client_ssl_opts(#{ssl_options := Map} = Params) ->
    %% aws_state was built once per request by resolve_request_state/1 (under the
    %% configured assume_role when any ARN is referenced) and is threaded into
    %% every ARN fetch here. A request that references no ARN carries a default
    %% state that is never used to resolve one.
    State = maps:get(aws_state, Params, none),
    case
        aws_auth_validate_ssl:resolve_cacerts(maps:get(<<"cacertfile_arn">>, Map, undefined), State)
    of
        {error, _, _} = Err ->
            Err;
        {ok, CacertOpts} ->
            case aws_auth_validate_ssl:resolve_client_cert(Map, State) of
                {error, _, _} = Err ->
                    Err;
                {ok, ClientOpts} ->
                    Opts =
                        CacertOpts ++ ClientOpts ++
                            aws_auth_validate_ssl:translate_ssl_opts(Map, <<"sni">>),
                    VerifyExplicit = maps:is_key(<<"verify">>, Map),
                    aws_auth_validate_ssl:apply_verify_default(Opts, VerifyExplicit)
            end
    end.

connection_timeout_ms() ->
    aws_auth_validate_ssl:connection_timeout_ms(#{default => ?DEFAULT_TIMEOUT_MS, max => 60_000}).
