%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% Shared OAuth test helpers used by both the eunit suite
%% (aws_auth_validate_oauth_tests, on the CT node) and the management CT suite
%% (aws_auth_validate_mgmt_SUITE, whose authz cases run these on the broker node
%% via rpc). Kept in a helper module -- not duplicated per suite -- so the JWT
%% minting recipe and the httpc-request-tuple destructuring live in one place.
%% This module carries no test cases; it is not an eunit suite.
-module(aws_auth_validate_oauth_test_helpers).

-export([rsa_signer/1, oauth_authz_mint/0, request_url/1]).

%% Generate a fresh RSA keypair via jose and return:
%%   * jwk_pub -- the PUBLIC key as a JWKS-style map, tagged with Kid, and
%%   * sign    -- a fun(ClaimsMap) -> compact RS256 JWT signed by the private key.
%% Each call produces a DISTINCT key, so "wrong key" tests just call it twice.
rsa_signer(Kid) ->
    Priv = jose_jwk:generate_key({rsa, 2048}),
    {_, PubMap0} = jose_jwk:to_public_map(Priv),
    PubMap = PubMap0#{<<"kid">> => Kid},
    Sign = fun(Claims) ->
        JWS = #{<<"alg">> => <<"RS256">>, <<"kid">> => Kid},
        {_, Token} = jose_jws:compact(jose_jwt:sign(Priv, JWS, Claims)),
        Token
    end,
    #{jwk_pub => PubMap, sign => Sign}.

%% Mint a fresh RS256 token whose scope grants `read' on any vhost/resource
%% (aud=rabbitmq so the backend's audience check passes), returning
%% {Token, JwksJson} where JwksJson is the PUBLIC key as a one-key JWKS document
%% the network stub serves. Built on rsa_signer/1 so the keypair + signing recipe
%% is not re-implemented. Intended to run ON THE BROKER NODE: minting there
%% guarantees the signing key matches the JWKS the backend fetches.
oauth_authz_mint() ->
    #{jwk_pub := PubMap, sign := Sign} = rsa_signer(<<"k1">>),
    Claims = #{
        <<"sub">> => <<"alice">>,
        <<"aud">> => <<"rabbitmq">>,
        <<"exp">> => os:system_time(seconds) + 3600,
        <<"scope">> => <<"rabbitmq.read:*/*">>
    },
    Token = Sign(Claims),
    JwksJson = rabbit_json:encode(#{<<"keys">> => [PubMap]}),
    {Token, JwksJson}.

%% Extract the URL string from an httpc Request tuple (GET or POST form).
request_url({Url, _Headers}) -> Url;
request_url({Url, _Headers, _ContentType, _Body}) -> Url.
