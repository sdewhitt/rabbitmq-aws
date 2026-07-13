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
%% Scope: REACHABILITY + JWKS well-formedness (the base check). At minimum an
%% `ok' (204) means:
%%
%%   - every configured HTTPS endpoint resolved + connected over TLS, and
%%   - the JWKS endpoint returned HTTP 200 with a JSON object containing a
%%     non-empty "keys" array (a syntactically valid JWKS).
%%
%% Base reachability alone does NOT prove any particular token will validate.
%% To close that gap WITHOUT accepting a client secret (and without the
%% confused-deputy / secret-exfil surface a broker-side grant would add), the
%% caller may OPTIONALLY supply their OWN access token via `access_token'. The
%% customer mints it out of band (a single curl to their IdP's token endpoint --
%% see the tutorial), so no secret ever transits this endpoint. When present,
%% the token is verified against the just-fetched JWKS:
%%
%%   - the JWS `alg' must be in a fixed asymmetric allowlist (RS*/ES*/PS*);
%%     `none' and any HMAC (HS*) alg are refused, closing the alg-confusion /
%%     "sign with the public key as an HMAC secret" attack;
%%   - the signature is verified with jose_jwt:verify_strict/3 (algorithm
%%     PINNED to the header alg) against the JWKS key whose `kid' matches;
%%   - `exp'/`nbf' are checked (same semantics as rabbit_auth_backend_oauth2);
%%   - when `resource_server_id' is supplied, the token `aud' must include it.
%%
%% This reuses the broker's own crypto library (jose) so the signature decision
%% matches what rabbit_auth_backend_oauth2 would compute -- a decision-parity
%% claim analogous to the LDAP backend's, scoped to signature + exp/nbf/aud. It
%% does NOT assert scope authorization; that stays an over-trust caveat for the
%% customer docs, same as the LDAP dn_lookup_base and HTTP reachability checks.
%%
%% A broker-side `client_credentials' grant (the broker fetching a token itself
%% from a supplied token_endpoint + client_secret_arn) was considered and
%% deliberately NOT implemented: it validates a client capability rather than
%% the broker's resource-server config, duplicates what the customer already did
%% to obtain the token they supply here, and would introduce a secret-exfil
%% surface (caller supplies both the secret ARN and an arbitrary destination
%% URL). The customer-supplied `access_token' path gives the same end-to-end
%% signature confidence with no secret transiting the endpoint.
%%
%% Category mapping:
%%   * input_invalid    (400) -- bad URL / bad ssl_options / ARN resolve fail /
%%                               SSRF-denied target / malformed access_token /
%%                               unsupported token alg.
%%   * connection_failed (400) -- host unreachable / DNS / connection refused /
%%                                timeout.
%%   * tls_failed        (400) -- TLS handshake / cert verification failure.
%%   * auth_failed       (422) -- endpoint reached but not a JWKS / discovery
%%                                doc; also a token audience mismatch.
%%     NOTE: auth_failed is borrowed for "endpoint did not return a usable
%%     JWKS/OIDC document".
%%   * token_invalid    (422) -- a supplied access_token failed signature
%%                               verification, or no fetched JWKS key matched its
%%                               kid. A REAL config mismatch: the JWKS the broker
%%                               fetches would also reject live tokens.
%%   * token_expired    (422) -- a supplied access_token is expired (exp) or not
%%                               yet valid (nbf). TRANSIENT, not a config bug --
%%                               re-mint the token and retry.
%%   token_invalid / token_expired are safe to distinguish (unlike the coarse
%%   reachability categories) because they describe the caller's own token, not
%%   the broker's infra or an SSRF target, so they leak nothing R4 guards.
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
    parse_access_token/1,
    token_header/1,
    verify_token/3,
    select_jwk/2
]).
-endif.

%% Asymmetric JWS algorithms accepted for customer-supplied token verification.
%% Deliberately excludes `none' and every HMAC (HS*) algorithm: a JWKS carries
%% only public keys, so an HS* token would be "verified" by HMAC-ing with the
%% public key as the shared secret -- the classic alg-confusion forgery. The
%% allowlist is passed to jose_jwt:verify_strict/3, which refuses any token
%% whose header `alg' is not a member.
-define(ALLOWED_TOKEN_ALGS, [
    <<"RS256">>,
    <<"RS384">>,
    <<"RS512">>,
    <<"ES256">>,
    <<"ES384">>,
    <<"ES512">>,
    <<"PS256">>,
    <<"PS384">>,
    <<"PS512">>
]).

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
-define(REASON_DISCOVERY, <<"issuer discovery did not return a valid OpenID configuration">>).
%% Customer-supplied access-token verification (optional, activates when
%% access_token is present). Fixed R4 reasons: no token content, claim value,
%% or key material echoed. Pure-phase shape problems are input_invalid (400);
%% verification outcomes use the token_invalid / token_expired categories (422)
%% so an operator can tell a real config mismatch (token_invalid: bad signature
%% or no matching JWKS key -- the broker will reject live tokens) from a
%% transient, non-config problem (token_expired: just re-mint and retry).
-define(REASON_BAD_ACCESS_TOKEN, <<"access_token must be a non-empty string">>).
-define(REASON_TOKEN_MALFORMED, <<"access_token is not a well-formed JWT">>).
-define(REASON_TOKEN_ALG_NOT_ALLOWED, <<
    "access_token is signed with an unsupported algorithm; "
    "an asymmetric algorithm (RS*/ES*/PS*) is required"
>>).
-define(REASON_TOKEN_NO_MATCHING_KEY, <<
    "no JWKS key matches the access_token's key id"
>>).
-define(REASON_TOKEN_SIGNATURE_INVALID, <<"access_token signature verification failed">>).
-define(REASON_TOKEN_EXPIRED, <<"access_token is expired or not yet valid">>).
-define(REASON_TOKEN_AUDIENCE, <<"access_token audience does not include resource_server_id">>).
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
        %% Optional customer-supplied access token. Present access_token
        %% activates signature + exp/nbf/aud verification against the fetched
        %% JWKS. Carries no secret (the customer minted it out of band).
        <<"access_token">>
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
        %% parse_access_token is pure: it shape-checks the optional customer-
        %% supplied token and pre-decodes its header so the alg allowlist can be
        %% enforced without network I/O. No verification happens here.
        fun parse_access_token/2,
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
            %% Keep the slot present-but-undefined so the token aud check knows
            %% no resource_server_id was supplied (aud is then not asserted).
            {ok, Acc#{resource_server_id => undefined}};
        V when is_binary(V), byte_size(V) > 0 ->
            {ok, Acc#{resource_server_id => V}};
        _ ->
            {error, input_invalid, ?REASON_BAD_RESOURCE_SERVER_ID}
    end.

%% ssl_options parsing (keys + values, mTLS pairing) is shared across backends;
%% delegate to aws_auth_validate_ssl with this backend's surface (ssl_opts/0).
parse_ssl_options(Body, Acc) ->
    aws_auth_validate_ssl:parse_ssl_options(
        maps:get(<<"ssl_options">>, Body, undefined), Acc, ssl_opts()
    ).

%% Parse the optional customer-supplied access_token (pure phase; no network,
%% no crypto beyond a header base64url-decode). When absent, the accumulator
%% carries token => none and behaviour is unchanged. When present it must be a
%% non-empty string, a well-formed three-segment JWT, and carry a header `alg'
%% in the asymmetric allowlist -- so an unsupported-alg (or `none') token is
%% rejected in the pure phase, before any JWKS is fetched. The parsed header
%% (kid/alg) and the raw token are stashed for the verification step.
parse_access_token(Body, Acc) ->
    case maps:get(<<"access_token">>, Body, undefined) of
        undefined ->
            {ok, Acc#{token => none}};
        Raw when is_binary(Raw), byte_size(Raw) > 0 ->
            case parse_access_token(Raw) of
                {ok, Header} ->
                    {ok, Acc#{token => #{raw => Raw, header => Header}}};
                {error, Category, Reason} ->
                    {error, Category, Reason}
            end;
        _ ->
            {error, input_invalid, ?REASON_BAD_ACCESS_TOKEN}
    end.

%% Pure shape check of a raw JWT string: exactly three non-empty segments, a
%% base64url-decodable JSON-object header, and a header `alg' in the asymmetric
%% allowlist. Returns the decoded header map on success.
-spec parse_access_token(binary()) ->
    {ok, map()} | {error, aws_auth_validate_backend:error_category(), binary()}.
parse_access_token(Raw) when is_binary(Raw) ->
    case token_header(Raw) of
        {ok, Header} ->
            case maps:get(<<"alg">>, Header, undefined) of
                Alg when is_binary(Alg) ->
                    case lists:member(Alg, ?ALLOWED_TOKEN_ALGS) of
                        true -> {ok, Header};
                        false -> {error, input_invalid, ?REASON_TOKEN_ALG_NOT_ALLOWED}
                    end;
                _ ->
                    {error, input_invalid, ?REASON_TOKEN_ALG_NOT_ALLOWED}
            end;
        {error, _} ->
            {error, input_invalid, ?REASON_TOKEN_MALFORMED}
    end.

%% Decode the first JWT segment (the protected header) into a JSON object map.
%% Uses unpadded base64url (JWT compact serialization). Any decode/JSON failure
%% is a malformed token.
-spec token_header(binary()) -> {ok, map()} | {error, malformed}.
token_header(Raw) ->
    case binary:split(Raw, <<".">>, [global]) of
        [HeaderSeg, PayloadSeg, SigSeg] when
            byte_size(HeaderSeg) > 0, byte_size(PayloadSeg) > 0, byte_size(SigSeg) > 0
        ->
            case b64url_decode(HeaderSeg) of
                {ok, Json} ->
                    case rabbit_json:try_decode(Json) of
                        {ok, Map} when is_map(Map) -> {ok, Map};
                        _ -> {error, malformed}
                    end;
                error ->
                    {error, malformed}
            end;
        _ ->
            {error, malformed}
    end.

%% Unpadded base64url decode (RFC 7515 JWT segments carry no `=' padding).
b64url_decode(Seg) ->
    try
        {ok, base64:decode(Seg, #{mode => urlsafe, padding => false})}
    catch
        _:_ -> error
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

%% Collect every URL that must pass the pure SSRF guard: the JWKS/issuer
%% endpoint(s). undefined slots are dropped.
collect_guard_urls(Acc) ->
    [
        U
     || U <- [maps:get(jwks_uri, Acc, undefined), maps:get(issuer, Acc, undefined)],
        U =/= undefined
    ].

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
                        %% Validate the JWKS source first (reachability +
                        %% well-formedness), capturing its keys. If a
                        %% customer-supplied access_token is present, verify it
                        %% against those keys (no extra network). Either step's
                        %% failure short-circuits.
                        case do_fetch_jwks(Params, SslOpts, Profile) of
                            {ok, Keys} ->
                                maybe_verify_token(Params, Keys);
                            {error, _, _} = Err ->
                                Err
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

%%--------------------------------------------------------------------
%% Customer-supplied access-token verification (no network)
%%--------------------------------------------------------------------
%%
%% Runs after the JWKS is fetched. The customer minted the token out of band, so
%% no secret transits this endpoint. Verification reuses the broker's own crypto
%% library (jose) so the signature decision matches what
%% rabbit_auth_backend_oauth2 computes.

%% When no access_token was supplied (token => none), this layer is a no-op.
maybe_verify_token(#{token := none}, _Keys) ->
    ok;
maybe_verify_token(#{token := #{raw := Raw, header := Header}} = Params, Keys) ->
    ResourceServerId = maps:get(resource_server_id, Params, undefined),
    verify_token(Raw, Header, {Keys, ResourceServerId}).

%% Verify a customer-supplied JWT against the fetched JWKS. Steps, in order:
%%   1. select the JWKS key whose `kid' matches the token header (or, if the
%%      token has no `kid' and the JWKS holds exactly one key, that key);
%%   2. verify the signature with jose_jwt:verify_strict/3, algorithm PINNED to
%%      the header alg (already allowlisted in the pure phase) so no alg
%%      substitution is possible;
%%   3. check exp/nbf (same semantics as rabbit_auth_backend_oauth2);
%%   4. if a resource_server_id was supplied, require it in the token `aud'.
%% Failures map to fixed categories (no claim value, key material, or token
%% content echoed -- R6): a bad signature or no matching JWKS key -> token_invalid
%% (a real config mismatch the broker would also reject); an expired/not-yet-valid
%% token -> token_expired (transient, just re-mint); an audience mismatch stays
%% auth_failed. verify_token/3 takes the pre-decoded header so the -ifdef(TEST)
%% export can exercise it directly.
-spec verify_token(binary(), map(), {list(), binary() | undefined}) ->
    ok | {error, aws_auth_validate_backend:error_category(), binary()}.
verify_token(Raw, Header, {Keys, ResourceServerId}) ->
    Alg = maps:get(<<"alg">>, Header),
    Kid = maps:get(<<"kid">>, Header, undefined),
    case select_jwk(Kid, Keys) of
        {error, _, _} = Err ->
            Err;
        {ok, JwkMap} ->
            case verify_signature(Alg, JwkMap, Raw) of
                {error, _, _} = Err ->
                    Err;
                {ok, Claims} ->
                    case check_token_expiry(Claims) of
                        {error, _, _} = Err -> Err;
                        ok -> check_token_audience(Claims, ResourceServerId)
                    end
            end
    end.

%% Select the JWKS entry matching the token's `kid'. When the token carries no
%% `kid', accept a single-key JWKS (unambiguous); otherwise a missing kid on a
%% multi-key set is unresolvable. A malformed (non-object) key entry is skipped.
select_jwk(undefined, [Key]) when is_map(Key) ->
    {ok, Key};
select_jwk(undefined, _Keys) ->
    {error, token_invalid, ?REASON_TOKEN_NO_MATCHING_KEY};
select_jwk(Kid, Keys) when is_binary(Kid) ->
    case [K || K <- Keys, is_map(K), maps:get(<<"kid">>, K, undefined) =:= Kid] of
        [Match | _] -> {ok, Match};
        [] -> {error, token_invalid, ?REASON_TOKEN_NO_MATCHING_KEY}
    end.

%% Verify the JWS signature with the algorithm pinned to the header alg.
%% jose_jwt:verify_strict/3 refuses any token whose alg is not the allowed one,
%% and jose_jwk:from_map/1 builds the public key from the JWKS entry. Any raise
%% (malformed key material, unsupported curve) is caught and treated as a
%% signature failure -- never a crash report (R6). Returns the decoded claims.
verify_signature(Alg, JwkMap, Raw) ->
    try
        JWK = jose_jwk:from_map(JwkMap),
        case jose_jwt:verify_strict(JWK, [Alg], Raw) of
            {true, {jose_jwt, Claims}, _JWS} when is_map(Claims) ->
                {ok, Claims};
            {true, JWT, _JWS} ->
                {ok, jwt_claims(JWT)};
            {false, _JWT, _JWS} ->
                {error, token_invalid, ?REASON_TOKEN_SIGNATURE_INVALID}
        end
    catch
        _:_ -> {error, token_invalid, ?REASON_TOKEN_SIGNATURE_INVALID}
    end.

%% Extract the claims map from a #jose_jwt{} without needing the jose header
%% record in scope (the record's sole field is the claims map).
jwt_claims(JWT) when is_tuple(JWT), tuple_size(JWT) =:= 2 ->
    Fields = element(2, JWT),
    case is_map(Fields) of
        true -> Fields;
        false -> #{}
    end;
jwt_claims(_) ->
    #{}.

%% exp/nbf validation, matching rabbit_auth_backend_oauth2:validate_token_expiry/1
%% semantics: an exp at or before now is expired; a numeric nbf in the future is
%% not-yet-valid. Absent claims are permitted (nothing to assert). A present but
%% non-numeric exp/nbf is treated as expired (the token is malformed w.r.t. time).
check_token_expiry(Claims) ->
    Now = os:system_time(seconds),
    case check_exp(maps:get(<<"exp">>, Claims, undefined), Now) of
        ok -> check_nbf(maps:get(<<"nbf">>, Claims, undefined), Now);
        Err -> Err
    end.

check_exp(undefined, _Now) ->
    ok;
check_exp(Exp, Now) when is_number(Exp) ->
    case trunc(Exp) =< Now of
        true -> {error, token_expired, ?REASON_TOKEN_EXPIRED};
        false -> ok
    end;
check_exp(_Exp, _Now) ->
    {error, token_expired, ?REASON_TOKEN_EXPIRED}.

check_nbf(undefined, _Now) ->
    ok;
check_nbf(Nbf, Now) when is_number(Nbf) ->
    case trunc(Nbf) > Now of
        true -> {error, token_expired, ?REASON_TOKEN_EXPIRED};
        false -> ok
    end;
check_nbf(_Nbf, _Now) ->
    {error, token_expired, ?REASON_TOKEN_EXPIRED}.

%% When a resource_server_id was supplied, require it in the token `aud' (a
%% string or a list of strings, per RFC 7519). When none was supplied, the aud
%% is not asserted (signature + expiry only).
check_token_audience(_Claims, undefined) ->
    ok;
check_token_audience(Claims, ResourceServerId) ->
    case maps:get(<<"aud">>, Claims, undefined) of
        Aud when is_binary(Aud) ->
            audience_result(Aud =:= ResourceServerId);
        Auds when is_list(Auds) ->
            audience_result(lists:member(ResourceServerId, Auds));
        _ ->
            {error, auth_failed, ?REASON_TOKEN_AUDIENCE}
    end.

audience_result(true) -> ok;
audience_result(false) -> {error, auth_failed, ?REASON_TOKEN_AUDIENCE}.

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
%% On success returns {ok, Keys} -- the non-empty "keys" array -- so a supplied
%% access token can be verified against those keys without re-fetching.
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
                    case parse_jwks(Body) of
                        {ok, Keys} -> {ok, Keys};
                        error -> {error, auth_failed, ?REASON_ENDPOINT}
                    end;
                {ok, {{_Vsn, _Code, _Phrase}, _Headers, _Body}} ->
                    {error, auth_failed, ?REASON_ENDPOINT};
                {error, Reason} ->
                    classify_http_error(Reason)
            end
    end.

%% Parse a well-formed JWKS: a JSON object whose "keys" field is a non-empty
%% array. Returns {ok, Keys} or error.
parse_jwks(Body) when is_binary(Body) ->
    case rabbit_json:try_decode(Body) of
        {ok, Map} when is_map(Map) ->
            case maps:get(<<"keys">>, Map, undefined) of
                Keys when is_list(Keys), Keys =/= [] -> {ok, Keys};
                _ -> error
            end;
        _ ->
            error
    end.

-ifdef(TEST).
%% Boolean well-formedness predicate retained for the -ifdef(TEST) export
%% contract and existing unit tests. Production code calls parse_jwks/1
%% directly (it needs the keys), so this wrapper is test-only.
is_valid_jwks(Body) when is_binary(Body) ->
    case parse_jwks(Body) of
        {ok, _Keys} -> true;
        error -> false
    end.
-endif.

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
