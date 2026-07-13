%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% IAM auth-backend token VERIFICATION (not fetching).
%%
%% IAM authentication for Amazon MQ for RabbitMQ is OAuth2 under the hood: AWS
%% STS outbound web identity federation mints a JWT, and
%% rabbitmq_auth_backend_oauth2 verifies it against the account's STS JWKS. IAM
%% role ARNs map to RabbitMQ scopes via scope_aliases.
%%
%% This backend does NOT mint or fetch a token. Minting an STS web-identity token
%% requires assuming a request-supplied role via the broker's global credential
%% singleton -- a confused-deputy that is prohibited by design (see the project
%% security invariants; the same reason `assume_role' from request input is
%% never accepted). Instead, the OPERATOR mints the token themselves (with their
%% own credentials, e.g. `aws sts get-web-identity-token', OUTSIDE the broker's
%% trust boundary) and passes the resulting JWT to this endpoint. The endpoint
%% only VERIFIES the token against the JWKS the broker would use.
%%
%% Scope: full-verify against the signing keys. An `ok' (204) means the supplied
%% token's signature verifies against a key served by the (reachable, TLS-valid)
%% JWKS endpoint, the token is not expired, and -- when an `audience' is supplied
%% -- its `aud' claim matches. This is stronger than the oauth backend's
%% reachability-only check, because here we assert an actual token decodes and
%% verifies end to end.
%%
%% Category mapping (reuses the existing aws_auth_validate_backend categories; no
%% new category is introduced):
%%   * input_invalid    (400) -- bad token shape / bad URL / bad ssl_options /
%%                                ARN resolve fail / SSRF-denied target.
%%   * connection_failed (400) -- JWKS host unreachable / DNS / timeout.
%%   * tls_failed        (400) -- TLS handshake / cert verification failure.
%%   * auth_failed       (422) -- JWKS endpoint not a JWKS, OR the token failed
%%                                verification (bad signature / expired / aud
%%                                mismatch). The token detail is never echoed.
-module(aws_auth_validate_iam).

-behaviour(aws_auth_validate_backend).

-export([method_name/0, validate/1, allowed_fields/0]).

-ifdef(TEST).
-export([
    parse_input/1,
    parse_url/1,
    is_compact_jws/1,
    verify_token/3,
    jwks_keys/1
]).
-endif.

-define(DEFAULT_TIMEOUT_MS, 5_000).

-define(SSL_OPTION_KEYS, [
    <<"cacertfile_arn">>,
    <<"certfile_arn">>,
    <<"keyfile_arn">>,
    <<"verify">>,
    <<"depth">>,
    <<"versions">>,
    <<"sni">>
]).

%% Fixed R4 reason strings: no URL, host, token, claim value, or raw error echoed.
-define(REASON_MISSING_TOKEN, <<"token is required and must be a compact JWS">>).
-define(REASON_BAD_TOKEN, <<"token is not a well-formed compact JWS">>).
-define(REASON_MISSING_URL, <<"at least one of jwks_uri or issuer must be present">>).
-define(REASON_BAD_URL, <<"a configured URL is not a valid https URL">>).
-define(REASON_URL_NOT_ALLOWED, <<"a configured URL targets a disallowed address">>).
-define(REASON_BAD_AUDIENCE, <<"audience must be a non-empty string">>).
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
-define(REASON_CONNECTION, <<"could not connect to the JWKS endpoint">>).
-define(REASON_TLS_HANDSHAKE, <<"TLS handshake failed">>).
-define(REASON_ENDPOINT, <<"endpoint did not return a valid JWKS document">>).
-define(REASON_TOKEN_UNVERIFIED, <<"the supplied token did not verify against the JWKS">>).
-define(REASON_ASSUME_ROLE, <<"failed to assume the configured role">>).
-define(REASON_NO_ASSUME_ROLE, <<
    "auth validation requires an assume_role to be configured; "
    "set aws.arns.assume_role_arn"
>>).

%% https-only, mirroring the oauth backend (signing keys must travel over TLS).
-define(ALLOWED_SCHEMES, ["https"]).

%% Always-denied infra ranges -- identical to the oauth backend's policy.
-define(DENIED_V4_CIDRS, [
    {{127, 0, 0, 0}, 8},
    {{169, 254, 0, 0}, 16},
    {{0, 0, 0, 0}, 8}
]).
-define(DENIED_V6_CIDRS, [
    {{0, 0, 0, 0, 0, 0, 0, 1}, 128},
    {{16#fe80, 0, 0, 0, 0, 0, 0, 0}, 10},
    {{16#fd00, 16#0ec2, 0, 0, 0, 0, 0, 16#0254}, 128},
    {{0, 0, 0, 0, 0, 0, 0, 0}, 128}
]).

%% Ephemeral httpc profile prefix -- disjoint from the http/oauth pools.
-define(PROFILE_PREFIX, "aws_auth_validate_iam_").

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
    <<"iam">>.

allowed_fields() ->
    [
        <<"token">>,
        <<"jwks_uri">>,
        <<"issuer">>,
        <<"audience">>,
        <<"resource_server_id">>,
        <<"ssl_options">>
    ].

-spec validate(map()) -> aws_auth_validate_backend:result().
validate(Body) when is_map(Body) ->
    %% ARN-first ordering: all pure, network-free validation runs before any ARN
    %% is resolved or any request is made.
    case parse_input(Body) of
        {error, _, _} = Err ->
            Err;
        {ok, Params} ->
            case resolve_request_state(Params) of
                {error, _, _} = Err -> Err;
                {ok, Params1} -> do_iam_validate(Params1)
            end
    end.

resolve_request_state(Params) ->
    aws_auth_validate_ssl:resolve_request_state(Params, ssl_opts()).

%%--------------------------------------------------------------------
%% Input parsing (pure, no network)
%%--------------------------------------------------------------------

parse_input(Body) ->
    Steps = [
        fun parse_token/2,
        fun parse_urls/2,
        fun parse_audience/2,
        fun parse_resource_server_id/2,
        fun parse_ssl_options/2,
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

%% token is REQUIRED and must be a compact JWS (three base64url segments). The
%% token is stored for the verification step but is NEVER logged.
parse_token(Body, Acc) ->
    case maps:get(<<"token">>, Body, undefined) of
        Token when is_binary(Token), byte_size(Token) > 0 ->
            case is_compact_jws(Token) of
                true -> {ok, Acc#{token => Token}};
                false -> {error, input_invalid, ?REASON_BAD_TOKEN}
            end;
        undefined ->
            {error, input_invalid, ?REASON_MISSING_TOKEN};
        _ ->
            {error, input_invalid, ?REASON_BAD_TOKEN}
    end.

%% Structural check only (no decode/verify): exactly three non-empty
%% base64url-charactered segments separated by '.'.
is_compact_jws(Token) when is_binary(Token) ->
    case binary:split(Token, <<".">>, [global]) of
        [H, P, S] ->
            lists:all(fun is_base64url_segment/1, [H, P, S]);
        _ ->
            false
    end.

is_base64url_segment(<<>>) ->
    false;
is_base64url_segment(Seg) when is_binary(Seg) ->
    lists:all(
        fun(C) ->
            (C >= $A andalso C =< $Z) orelse
                (C >= $a andalso C =< $z) orelse
                (C >= $0 andalso C =< $9) orelse
                C =:= $- orelse C =:= $_
        end,
        binary_to_list(Seg)
    ).

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

parse_optional_url(undefined) ->
    none;
parse_optional_url(V) when is_binary(V), byte_size(V) > 0 ->
    parse_url(V);
parse_optional_url(_) ->
    {error, bad_url}.

%% Parse + validate an https URL (same rules as the oauth backend).
parse_url(Bin) when is_binary(Bin) ->
    Str = binary_to_list(Bin),
    case uri_string:parse(Str) of
        #{scheme := Scheme, host := Host} = Parsed when
            Host =/= [], Scheme =:= "https"
        ->
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

parse_audience(Body, Acc) ->
    case maps:get(<<"audience">>, Body, undefined) of
        undefined ->
            {ok, Acc#{audience => undefined}};
        V when is_binary(V), byte_size(V) > 0 ->
            {ok, Acc#{audience => V}};
        _ ->
            {error, input_invalid, ?REASON_BAD_AUDIENCE}
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

parse_ssl_options(Body, Acc) ->
    aws_auth_validate_ssl:parse_ssl_options(
        maps:get(<<"ssl_options">>, Body, undefined), Acc, ssl_opts()
    ).

%%--------------------------------------------------------------------
%% SSRF guard (pure phase)
%%--------------------------------------------------------------------

guard_urls(_Body, Acc) ->
    Urls = collect_guard_urls(Acc),
    case check_urls(Urls) of
        ok -> {ok, Acc};
        {error, _, _} = Err -> Err
    end.

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

%%--------------------------------------------------------------------
%% Network phase: fetch JWKS, then verify the supplied token against it
%%--------------------------------------------------------------------
%%
%% The whole network+verify section runs inside a try/catch collapsing any raise
%% to connection_failed, so the token can never reach a crash report (R6). All
%% requests run on a dedicated ephemeral httpc profile (R3).

do_iam_validate(Params) ->
    case aws_auth_validate_httpc:claim_probe_profile(?PROFILE_PREFIX) of
        none ->
            {error, connection_failed, ?REASON_CONNECTION};
        {ok, Profile} ->
            try
                case build_client_ssl_opts(Params) of
                    {error, _, _} = Err ->
                        Err;
                    {ok, SslOpts} ->
                        case fetch_jwks_keys(Params, SslOpts, Profile) of
                            {error, _, _} = Err ->
                                Err;
                            {ok, Keys} ->
                                verify_supplied_token(Params, Keys)
                        end
                end
            catch
                _Class:_Reason:_Stack ->
                    {error, connection_failed, ?REASON_CONNECTION}
            after
                aws_auth_validate_httpc:stop_probe_profile(Profile)
            end
    end.

%% Determine the JWKS URI (given directly, or derived from the STS issuer by
%% appending /.well-known/jwks.json -- NOT OIDC discovery, which STS does not
%% serve), fetch it, and return the decoded "keys" list.
fetch_jwks_keys(#{jwks_uri := JwksUrl, timeout := Timeout}, SslOpts, Profile) when
    JwksUrl =/= undefined
->
    fetch_and_extract_keys(JwksUrl, SslOpts, Timeout, Profile);
fetch_jwks_keys(
    #{jwks_uri := undefined, issuer := IssuerUrl, timeout := Timeout}, SslOpts, Profile
) ->
    case derive_sts_jwks_url(IssuerUrl) of
        {error, _, _} = Err ->
            Err;
        {ok, DerivedUrl} ->
            case aws_auth_validate_net:url_allowed(DerivedUrl, net_policy()) of
                {error, _, _} = Err -> Err;
                ok -> fetch_and_extract_keys(DerivedUrl, SslOpts, Timeout, Profile)
            end
    end.

%% Derive the STS JWKS URL from the issuer: {issuer}/.well-known/jwks.json.
derive_sts_jwks_url(#{url_string := IssuerStr}) ->
    DerivedStr = strip_trailing_slash(IssuerStr) ++ "/.well-known/jwks.json",
    parse_url(list_to_binary(DerivedStr));
derive_sts_jwks_url(_) ->
    {error, input_invalid, ?REASON_BAD_URL}.

fetch_and_extract_keys(JwksUrl, SslOpts, Timeout, Profile) ->
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
                    case jwks_keys(Body) of
                        {ok, Keys} -> {ok, Keys};
                        error -> {error, auth_failed, ?REASON_ENDPOINT}
                    end;
                {ok, {{_Vsn, _Code, _Phrase}, _Headers, _Body}} ->
                    {error, auth_failed, ?REASON_ENDPOINT};
                {error, Reason} ->
                    classify_http_error(Reason)
            end
    end.

%% Decode a JWKS body to its non-empty "keys" list.
jwks_keys(Body) when is_binary(Body) ->
    case rabbit_json:try_decode(Body) of
        {ok, Map} when is_map(Map) ->
            case maps:get(<<"keys">>, Map, undefined) of
                Keys when is_list(Keys), Keys =/= [] -> {ok, Keys};
                _ -> error
            end;
        _ ->
            error
    end.

%% Verify the caller-supplied token against the fetched keys. Success requires a
%% valid signature against one of the keys AND a non-expired token AND (when an
%% audience was supplied) a matching aud claim. Any verification failure -- or a
%% raise inside jose -- collapses to auth_failed; the token is never echoed.
verify_supplied_token(#{token := Token, audience := Audience}, Keys) ->
    try verify_token(Token, Keys, Audience) of
        ok -> ok;
        {error, _, _} = Err -> Err
    catch
        _Class:_Reason:_Stack ->
            {error, auth_failed, ?REASON_TOKEN_UNVERIFIED}
    end.

%% Try each JWKS key until one verifies the token's signature; then check exp and
%% (optional) aud. Returns ok or a fixed-category auth_failed.
verify_token(Token, Keys, Audience) ->
    case first_verifying_key(Token, Keys) of
        {ok, Fields} ->
            case not_expired(Fields) andalso audience_ok(Fields, Audience) of
                true -> ok;
                false -> {error, auth_failed, ?REASON_TOKEN_UNVERIFIED}
            end;
        error ->
            {error, auth_failed, ?REASON_TOKEN_UNVERIFIED}
    end.

first_verifying_key(_Token, []) ->
    error;
first_verifying_key(Token, [KeyMap | Rest]) ->
    case try_verify_with_key(Token, KeyMap) of
        {ok, Fields} -> {ok, Fields};
        error -> first_verifying_key(Token, Rest)
    end.

try_verify_with_key(Token, KeyMap) when is_map(KeyMap) ->
    try
        Jwk = jose_jwk:from_map(KeyMap),
        case jose_jwt:verify(Jwk, Token) of
            {true, {jose_jwt, Fields}, _} when is_map(Fields) -> {ok, Fields};
            _ -> error
        end
    catch
        _Class:_Reason:_Stack -> error
    end;
try_verify_with_key(_Token, _KeyMap) ->
    error.

%% exp is seconds since the epoch. A token with no exp is treated as expired
%% (STS web-identity tokens always carry exp; a missing exp is suspicious).
not_expired(#{<<"exp">> := Exp}) when is_integer(Exp) ->
    Exp > erlang:system_time(second);
not_expired(_Fields) ->
    false.

%% When no audience was supplied, do not assert aud. When supplied, the token's
%% aud (a string or a list of strings) must contain it.
audience_ok(_Fields, undefined) ->
    true;
audience_ok(#{<<"aud">> := Aud}, Expected) when is_binary(Aud) ->
    Aud =:= Expected;
audience_ok(#{<<"aud">> := Auds}, Expected) when is_list(Auds) ->
    lists:member(Expected, Auds);
audience_ok(_Fields, _Expected) ->
    false.

strip_trailing_slash(S) ->
    case lists:reverse(S) of
        [$/ | Rest] -> lists:reverse(Rest);
        _ -> S
    end.

%%--------------------------------------------------------------------
%% httpc error classification / TLS option shaping (shared helpers)
%%--------------------------------------------------------------------

classify_http_error(Reason) ->
    aws_auth_validate_ssl:classify_http_error(
        Reason, ?REASON_TLS_HANDSHAKE, ?REASON_CONNECTION
    ).

ssl_http_opt(Host, SslOpts) ->
    [{ssl, with_default_sni(SslOpts, Host)}].

with_default_sni(SslOpts, Host) ->
    case lists:keymember(server_name_indication, 1, SslOpts) of
        true -> SslOpts;
        false -> [{server_name_indication, Host} | SslOpts]
    end.

build_client_ssl_opts(#{ssl_options := Map} = Params) ->
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
