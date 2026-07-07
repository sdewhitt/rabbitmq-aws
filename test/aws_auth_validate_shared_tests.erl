%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% Cross-backend equivalence tests for the shared validation modules
%% (aws_auth_validate_ssl / aws_auth_validate_net / aws_auth_validate_httpc).
%%
%% These lock in the property that the http and oauth backends behave
%% IDENTICALLY where they share code -- the whole point of the extraction. If a
%% future change makes one backend diverge from the shared helper (the drift
%% these modules exist to prevent), one of these fails.
-module(aws_auth_validate_shared_tests).

-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% aws_auth_validate_ssl: value translators (backend-independent)
%%--------------------------------------------------------------------

to_verify_test() ->
    ?assertEqual(verify_peer, aws_auth_validate_ssl:to_verify(<<"verify_peer">>)),
    ?assertEqual(verify_none, aws_auth_validate_ssl:to_verify(<<"verify_none">>)).

to_versions_test() ->
    ?assertEqual(
        ['tlsv1.3', 'tlsv1.2', 'tlsv1.1', tlsv1],
        aws_auth_validate_ssl:to_versions([
            <<"tlsv1.3">>, <<"tlsv1.2">>, <<"tlsv1.1">>, <<"tlsv1">>
        ])
    ).

%% decode_pem_cacerts/1 must return raw DER (or skip), never pem_entry_decode
%% records -- the cacerts-DER contract the three backends depend on.
decode_pem_cacerts_skip_on_non_pem_test() ->
    ?assertEqual(skip, aws_auth_validate_ssl:decode_pem_cacerts(<<"not-a-pem">>)).

%% resolve_arn/2 fails closed on the `none' credential sentinel: it must NOT call
%% out to AWS. (aws_arn_util is not even loaded here; a call would error.)
resolve_arn_fails_closed_on_none_test() ->
    ?assertEqual(
        {error, no_credentials_state}, aws_auth_validate_ssl:resolve_arn(<<"arn:x">>, none)
    ).

%% connection_timeout_ms/1 caps at the supplied max and floors invalid values to
%% the default -- shared by all three backends.
connection_timeout_bounds_test() ->
    application:unset_env(aws, auth_validation_connection_timeout_ms),
    ?assertEqual(
        5000, aws_auth_validate_ssl:connection_timeout_ms(#{default => 5000, max => 60000})
    ),
    application:set_env(aws, auth_validation_connection_timeout_ms, 7000),
    ?assertEqual(
        7000, aws_auth_validate_ssl:connection_timeout_ms(#{default => 5000, max => 60000})
    ),
    %% Over the cap -> default.
    application:set_env(aws, auth_validation_connection_timeout_ms, 999999),
    ?assertEqual(
        5000, aws_auth_validate_ssl:connection_timeout_ms(#{default => 5000, max => 60000})
    ),
    application:unset_env(aws, auth_validation_connection_timeout_ms).

%%--------------------------------------------------------------------
%% aws_auth_validate_net: the SSRF classifier is identical for the http and
%% oauth policies (same infra denylist). Assert both backends' TEST wrappers
%% agree with each other and with the shared module for the full v4/v6 matrix.
%%--------------------------------------------------------------------

%% The infra addresses both backends must DENY, and the public address both must
%% ALLOW. classify_ip/1 on each backend delegates to the shared net module with
%% that backend's policy; the denylists are identical, so the verdicts must match.
ssrf_classify_ip_parity_test() ->
    application:unset_env(aws, auth_validation_allow_private_networks),
    Denied = [
        {127, 0, 0, 1},
        {169, 254, 169, 254},
        {0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 1},
        {16#fe80, 0, 0, 0, 0, 0, 0, 1},
        {16#fd00, 16#0ec2, 0, 0, 0, 0, 0, 16#0254},
        %% v6-encoded IMDS (v4-mapped) must also be denied.
        {0, 0, 0, 0, 0, 16#ffff, 16#a9fe, 16#a9fe}
    ],
    Allowed = [
        {8, 8, 8, 8},
        {10, 0, 0, 5},
        {172, 16, 0, 1},
        {192, 168, 1, 1},
        {2600, 16#1f18, 0, 0, 0, 0, 0, 1}
    ],
    [
        ?assertEqual(
            deny,
            aws_auth_validate_http:classify_ip(IP),
            {http_should_deny, IP}
        )
     || IP <- Denied
    ],
    [
        ?assertEqual(
            deny,
            aws_auth_validate_oauth:classify_ip(IP),
            {oauth_should_deny, IP}
        )
     || IP <- Denied
    ],
    [
        ?assertEqual(
            allow,
            aws_auth_validate_http:classify_ip(IP),
            {http_should_allow, IP}
        )
     || IP <- Allowed
    ],
    [
        ?assertEqual(
            allow,
            aws_auth_validate_oauth:classify_ip(IP),
            {oauth_should_allow, IP}
        )
     || IP <- Allowed
    ],
    %% Explicit http-vs-oauth agreement on every case.
    [
        ?assertEqual(
            aws_auth_validate_http:classify_ip(IP),
            aws_auth_validate_oauth:classify_ip(IP),
            {parity_mismatch, IP}
        )
     || IP <- Denied ++ Allowed
    ].

%% The loopback-relax flag must behave identically for both backends: loopback
%% flips allow, IMDS stays denied.
ssrf_loopback_flag_parity_test() ->
    application:set_env(aws, auth_validation_allow_private_networks, true),
    try
        ?assertEqual(allow, aws_auth_validate_http:classify_ip({127, 0, 0, 1})),
        ?assertEqual(allow, aws_auth_validate_oauth:classify_ip({127, 0, 0, 1})),
        %% IMDS is NOT relaxed for either.
        ?assertEqual(deny, aws_auth_validate_http:classify_ip({169, 254, 169, 254})),
        ?assertEqual(deny, aws_auth_validate_oauth:classify_ip({169, 254, 169, 254}))
    after
        application:unset_env(aws, auth_validation_allow_private_networks)
    end.

%% CIDR membership math is backend-independent; sanity-check via both wrappers.
in_cidr_parity_test() ->
    Cidr = {{169, 254, 0, 0}, 16},
    ?assertEqual(
        aws_auth_validate_http:in_cidr({169, 254, 169, 254}, Cidr),
        aws_auth_validate_oauth:in_cidr({169, 254, 169, 254}, Cidr)
    ),
    ?assert(aws_auth_validate_http:in_cidr({169, 254, 169, 254}, Cidr)),
    ?assertNot(aws_auth_validate_http:in_cidr({8, 8, 8, 8}, Cidr)).

%%--------------------------------------------------------------------
%% Scheme-allowlist divergence is INTENTIONAL: oauth is https-only, http allows
%% both. Lock that difference in so a refactor cannot accidentally unify it.
%%--------------------------------------------------------------------

scheme_policy_divergence_test() ->
    HttpUrl = #{scheme => "http", host => "example.com"},
    %% http backend allows http://
    ?assertEqual(ok, aws_auth_validate_http:url_allowed(HttpUrl)),
    %% oauth backend rejects http:// (https-only)
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:url_allowed(HttpUrl)),
    %% both allow https:// to a public host
    HttpsUrl = #{scheme => "https", host => "example.com"},
    ?assertEqual(ok, aws_auth_validate_http:url_allowed(HttpsUrl)),
    ?assertEqual(ok, aws_auth_validate_oauth:url_allowed(HttpsUrl)).
