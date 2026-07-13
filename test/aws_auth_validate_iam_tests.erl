%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% Unit tests for the IAM auth-validation backend's pure phase and its token
%% verification logic (no real network). Covers: token shape checks, URL
%% presence/scheme enforcement, audience/ssl_options validation, SSRF
%% classification, JWKS decoding, and verify_token/3 against a locally signed
%% JWT (HS256 oct key, mirroring the oauth2 backend's test fixture).
-module(aws_auth_validate_iam_tests).

-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% Method identity
%%--------------------------------------------------------------------

method_name_test() ->
    ?assertEqual(<<"iam">>, aws_auth_validate_iam:method_name()).

allowed_fields_test() ->
    Fields = aws_auth_validate_iam:allowed_fields(),
    %% token + the JWKS source + verification knobs + ssl_options.
    lists:foreach(
        fun(F) -> ?assert(lists:member(F, Fields)) end,
        [
            <<"token">>,
            <<"jwks_uri">>,
            <<"issuer">>,
            <<"audience">>,
            <<"resource_server_id">>,
            <<"ssl_options">>
        ]
    ).

%%--------------------------------------------------------------------
%% Pure phase: token shape
%%--------------------------------------------------------------------

%% token is required.
missing_token_test() ->
    Body = #{<<"jwks_uri">> => <<"https://idp.example.com/jwks">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_iam:validate(Body)).

%% A token that is not three base64url segments is rejected in the pure phase.
malformed_token_test() ->
    Body = #{
        <<"token">> => <<"not-a-jwt">>,
        <<"jwks_uri">> => <<"https://idp.example.com/jwks">>
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_iam:validate(Body)).

%% is_compact_jws/1: exactly three non-empty base64url segments.
is_compact_jws_accepts_three_segments_test() ->
    ?assert(aws_auth_validate_iam:is_compact_jws(<<"aaa.bbb.ccc">>)).

is_compact_jws_rejects_two_segments_test() ->
    ?assertNot(aws_auth_validate_iam:is_compact_jws(<<"aaa.bbb">>)).

is_compact_jws_rejects_empty_segment_test() ->
    ?assertNot(aws_auth_validate_iam:is_compact_jws(<<"aaa..ccc">>)).

is_compact_jws_rejects_non_base64url_test() ->
    %% '+' and '/' are base64 (not base64url) and must be rejected.
    ?assertNot(aws_auth_validate_iam:is_compact_jws(<<"aa+.bb/.cc=">>)).

%%--------------------------------------------------------------------
%% Pure phase: JWKS source URL
%%--------------------------------------------------------------------

%% At least one of jwks_uri / issuer is required.
missing_both_urls_test() ->
    Body = #{<<"token">> => <<"aaa.bbb.ccc">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_iam:validate(Body)).

%% A plain http:// jwks_uri is rejected (https-only for signing keys).
http_jwks_uri_rejected_test() ->
    Body = #{
        <<"token">> => <<"aaa.bbb.ccc">>,
        <<"jwks_uri">> => <<"http://idp.example.com/jwks">>
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_iam:validate(Body)).

%% A jwks_uri whose literal host is IMDS is rejected by the SSRF guard.
ssrf_imds_jwks_uri_test() ->
    Body = #{
        <<"token">> => <<"aaa.bbb.ccc">>,
        <<"jwks_uri">> => <<"https://169.254.169.254/latest/meta-data/jwks">>
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_iam:validate(Body)).

%% A loopback jwks_uri is rejected by the SSRF guard.
ssrf_loopback_jwks_uri_test() ->
    Body = #{
        <<"token">> => <<"aaa.bbb.ccc">>,
        <<"jwks_uri">> => <<"https://127.0.0.1/jwks">>
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_iam:validate(Body)).

%% A bad audience type is rejected in the pure phase.
bad_audience_test() ->
    Body = #{
        <<"token">> => <<"aaa.bbb.ccc">>,
        <<"jwks_uri">> => <<"https://idp.example.com/jwks">>,
        <<"audience">> => 123
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_iam:validate(Body)).

%%--------------------------------------------------------------------
%% JWKS decoding (jwks_keys/1)
%%--------------------------------------------------------------------

jwks_keys_valid_test() ->
    Body = rabbit_json:encode(#{<<"keys">> => [#{<<"kty">> => <<"oct">>}]}),
    ?assertMatch({ok, [_ | _]}, aws_auth_validate_iam:jwks_keys(Body)).

jwks_keys_empty_test() ->
    Body = rabbit_json:encode(#{<<"keys">> => []}),
    ?assertEqual(error, aws_auth_validate_iam:jwks_keys(Body)).

jwks_keys_no_keys_field_test() ->
    Body = rabbit_json:encode(#{<<"something">> => <<"else">>}),
    ?assertEqual(error, aws_auth_validate_iam:jwks_keys(Body)).

jwks_keys_non_json_test() ->
    ?assertEqual(error, aws_auth_validate_iam:jwks_keys(<<"not json">>)).

%%--------------------------------------------------------------------
%% Token verification (verify_token/3) against a locally signed JWT
%%--------------------------------------------------------------------
%%
%% Uses a symmetric HS256 `oct' key as both the signing key and the JWKS entry
%% (the same fixture shape the oauth2 backend's tests use). This keeps the test
%% self-contained: verify_token/3 receives the "keys" list exactly as the
%% network phase would after decoding a JWKS body.

%% A well-formed, unexpired token signed by the JWKS key verifies -> ok.
verify_valid_token_test() ->
    Jwk = fixture_jwk(),
    Token = sign(Jwk, claims(future_exp(), #{})),
    ?assertEqual(ok, aws_auth_validate_iam:verify_token(Token, [Jwk], undefined)).

%% An expired token -> auth_failed.
verify_expired_token_test() ->
    Jwk = fixture_jwk(),
    Token = sign(Jwk, claims(past_exp(), #{})),
    ?assertMatch(
        {error, auth_failed, _},
        aws_auth_validate_iam:verify_token(Token, [Jwk], undefined)
    ).

%% A token with no exp claim -> auth_failed (treated as expired).
verify_no_exp_token_test() ->
    Jwk = fixture_jwk(),
    Token = sign(Jwk, #{<<"sub">> => <<"someone">>}),
    ?assertMatch(
        {error, auth_failed, _},
        aws_auth_validate_iam:verify_token(Token, [Jwk], undefined)
    ).

%% A token signed by a DIFFERENT key than the JWKS serves -> auth_failed.
verify_bad_signature_test() ->
    SigningJwk = fixture_jwk(<<"k1">>, <<"c2lnbmluZ2tleQ">>),
    ServedJwk = fixture_jwk(<<"k2">>, <<"ZGlmZmVyZW50a2V5">>),
    Token = sign(SigningJwk, claims(future_exp(), #{})),
    ?assertMatch(
        {error, auth_failed, _},
        aws_auth_validate_iam:verify_token(Token, [ServedJwk], undefined)
    ).

%% audience supplied and matches the token's aud -> ok.
verify_audience_match_test() ->
    Jwk = fixture_jwk(),
    Token = sign(Jwk, claims(future_exp(), #{<<"aud">> => <<"rabbitmq">>})),
    ?assertEqual(
        ok,
        aws_auth_validate_iam:verify_token(Token, [Jwk], <<"rabbitmq">>)
    ).

%% audience supplied but the token's aud does not match -> auth_failed.
verify_audience_mismatch_test() ->
    Jwk = fixture_jwk(),
    Token = sign(Jwk, claims(future_exp(), #{<<"aud">> => <<"other">>})),
    ?assertMatch(
        {error, auth_failed, _},
        aws_auth_validate_iam:verify_token(Token, [Jwk], <<"rabbitmq">>)
    ).

%% audience supplied and the token's aud is a LIST containing it -> ok.
verify_audience_list_match_test() ->
    Jwk = fixture_jwk(),
    Token = sign(Jwk, claims(future_exp(), #{<<"aud">> => [<<"x">>, <<"rabbitmq">>]})),
    ?assertEqual(
        ok,
        aws_auth_validate_iam:verify_token(Token, [Jwk], <<"rabbitmq">>)
    ).

%% The first (non-matching) key is skipped and a later matching key verifies.
verify_second_key_matches_test() ->
    WrongJwk = fixture_jwk(<<"k1">>, <<"d3JvbmdrZXk">>),
    RightJwk = fixture_jwk(<<"k2">>, <<"cmlnaHRrZXk">>),
    Token = sign(RightJwk, claims(future_exp(), #{})),
    ?assertEqual(
        ok,
        aws_auth_validate_iam:verify_token(Token, [WrongJwk, RightJwk], undefined)
    ).

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

%% A symmetric HS256 oct JWK usable as both signer and JWKS entry. Mirrors the
%% oauth2 backend's fixture_jwk/2 shape.
fixture_jwk() ->
    fixture_jwk(<<"token-key">>, <<"dG9rZW5rZXk">>).

fixture_jwk(Kid, K) ->
    #{
        <<"alg">> => <<"HS256">>,
        <<"k">> => K,
        <<"kid">> => Kid,
        <<"kty">> => <<"oct">>,
        <<"use">> => <<"sig">>
    }.

claims(Exp, Extra) ->
    maps:merge(#{<<"sub">> => <<"someone">>, <<"exp">> => Exp}, Extra).

future_exp() ->
    os:system_time(second) + 3600.

past_exp() ->
    os:system_time(second) - 3600.

%% Sign claims with the given JWK, producing a compact JWS. jose derives the
%% signing key from the oct JWK; HS256 is set explicitly to match the fixture.
sign(Jwk, Claims) ->
    Jws = #{<<"alg">> => <<"HS256">>},
    Signed = jose_jwt:sign(jose_jwk:from_map(Jwk), Jws, Claims),
    {_, Compact} = jose_jws:compact(Signed),
    Compact.
