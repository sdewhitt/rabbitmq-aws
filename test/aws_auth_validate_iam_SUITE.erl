%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% Integration tests for the IAM validation backend against a real, local stub
%% HTTPS server. These exercise the parts of aws_auth_validate_iam the unit
%% tests cannot: the actual httpc probe -> connect -> TLS handshake -> JWKS
%% fetch -> token verification path.
%%
%% Like the OAuth suite, the stub is an in-process `inets' httpd, needs `openssl'
%% on PATH to mint the TLS material (IAM is https-only), and returns {skip, _}
%% from init_per_suite if the stub cannot start -- the same graceful-skip posture
%% the LDAP/OAuth suites use.
%%
%% The stub serves, over TLS on loopback:
%%   * GET /jwks -> a JWKS whose single key is the symmetric HS256 oct key the
%%     test also signs tokens with, so a token signed by that key verifies.
%%   * GET /jwks-other -> a JWKS carrying a DIFFERENT key, so a token signed by
%%     the first key fails verification (auth_failed).
%%
%% SSRF note: the IAM backend hard-denies loopback in production; the test-only
%% auth_validation_allow_private_networks flag relaxes ONLY loopback so the probe
%% can reach the local stub. Production classify_ip is unchanged.
-module(aws_auth_validate_iam_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("inets/include/httpd.hrl").

%% The oct JWKS key the stub serves at /jwks and the test signs with.
-define(JWK_KID, <<"iam-test-key">>).
-define(JWK_K, <<"dG9rZW5rZXk">>).

all() ->
    [
        {group, iam}
    ].

groups() ->
    [
        {iam, [], [
            valid_token_returns_ok,
            tampered_token_returns_auth_failed,
            wrong_key_returns_auth_failed,
            token_not_in_result
        ]}
    ].

%%--------------------------------------------------------------------
%% Suite setup / teardown
%%--------------------------------------------------------------------

init_per_suite(Config0) ->
    Config = rabbit_ct_helpers:run_setup_steps(Config0),
    {ok, StartedInets} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ssl),
    {ok, _} = application:ensure_all_started(jose),
    PrivDir = ?config(priv_dir, Config),
    try
        {Pid, Port} = start_self_signed_stub(PrivDir),
        [
            {stub_pid, Pid},
            {stub_port, Port},
            {started_inets, lists:member(inets, StartedInets)}
            | Config
        ]
    catch
        _Class:Reason ->
            {skip, {iam_stub_unavailable, Reason}}
    end.

end_per_suite(Config) ->
    catch inets:stop(httpd, ?config(stub_pid, Config)),
    case ?config(started_inets, Config) of
        true -> application:stop(inets);
        _ -> ok
    end,
    rabbit_ct_helpers:run_teardown_steps(Config).

init_per_group(_Group, Config) ->
    %% Relax ONLY loopback so the probe reaches the local stub.
    application:set_env(aws, auth_validation_allow_private_networks, true),
    Config.

end_per_group(_Group, Config) ->
    application:unset_env(aws, auth_validation_allow_private_networks),
    Config.

init_per_testcase(TC, Config) ->
    rabbit_ct_helpers:testcase_started(Config, TC).

end_per_testcase(TC, Config) ->
    rabbit_ct_helpers:testcase_finished(Config, TC).

%%--------------------------------------------------------------------
%% Functional tests
%%--------------------------------------------------------------------

%% A valid, unexpired token signed by the JWKS key verifies -> ok.
valid_token_returns_ok(Config) ->
    Token = sign(fixture_jwk(), claims(future_exp())),
    Body = #{
        <<"token">> => Token,
        <<"jwks_uri">> => stub_url(Config, "/jwks"),
        <<"ssl_options">> => #{<<"verify">> => <<"verify_none">>}
    },
    ?assertEqual(ok, validate(Body)).

%% A token whose payload has been tampered with (signature no longer valid) ->
%% auth_failed.
tampered_token_returns_auth_failed(Config) ->
    Valid = sign(fixture_jwk(), claims(future_exp())),
    Tampered = tamper(Valid),
    Body = #{
        <<"token">> => Tampered,
        <<"jwks_uri">> => stub_url(Config, "/jwks"),
        <<"ssl_options">> => #{<<"verify">> => <<"verify_none">>}
    },
    ?assertMatch({error, auth_failed, _}, validate(Body)).

%% A token signed by the test key, but the JWKS endpoint serves a DIFFERENT key
%% -> auth_failed (signature does not verify against any served key).
wrong_key_returns_auth_failed(Config) ->
    Token = sign(fixture_jwk(), claims(future_exp())),
    Body = #{
        <<"token">> => Token,
        <<"jwks_uri">> => stub_url(Config, "/jwks-other"),
        <<"ssl_options">> => #{<<"verify">> => <<"verify_none">>}
    },
    ?assertMatch({error, auth_failed, _}, validate(Body)).

%% R6: the caller-supplied token must never appear in the rendered result.
token_not_in_result(Config) ->
    Token = sign(fixture_jwk(), claims(future_exp())),
    Body = #{
        <<"token">> => Token,
        <<"jwks_uri">> => stub_url(Config, "/jwks"),
        <<"ssl_options">> => #{<<"verify">> => <<"verify_none">>}
    },
    Result = validate(Body),
    Rendered = lists:flatten(io_lib:format("~p", [Result])),
    ?assertEqual(ok, Result),
    ?assertEqual(nomatch, string:find(Rendered, binary_to_list(Token))).

%%--------------------------------------------------------------------
%% Stub HTTPS server (in-process inets httpd)
%%--------------------------------------------------------------------

start_self_signed_stub(PrivDir) ->
    {CertFile, KeyFile} = gen_self_signed(PrivDir),
    {ok, Pid} = inets:start(httpd, [
        {port, 0},
        {server_name, "aws_iam_stub"},
        {server_root, PrivDir},
        {document_root, PrivDir},
        {bind_address, {127, 0, 0, 1}},
        {socket_type, {ssl, [{certfile, CertFile}, {keyfile, KeyFile}]}},
        {modules, [?MODULE]}
    ]),
    [{port, Port}] = httpd:info(Pid, [port]),
    {Pid, Port}.

%% inets httpd callback: respond purely from the request path.
do(Info) ->
    Path = hd(string:split(Info#mod.request_uri, "?")),
    {Status, Body, CT} =
        case Path of
            "/jwks" ->
                {200, rabbit_json:encode(#{<<"keys">> => [fixture_jwk()]}), "application/json"};
            "/jwks-other" ->
                Other = fixture_jwk(<<"other-key">>, <<"ZGlmZmVyZW50a2V5">>),
                {200, rabbit_json:encode(#{<<"keys">> => [Other]}), "application/json"};
            _ ->
                {404, <<"not found">>, "text/plain"}
        end,
    Head = [
        {code, Status},
        {content_type, CT},
        {content_length, integer_to_list(byte_size(Body))}
    ],
    {proceed, [{response, {response, Head, Body}}]}.

%%--------------------------------------------------------------------
%% Certificate generation (shells out to openssl, as the OAuth suite does)
%%--------------------------------------------------------------------

gen_self_signed(PrivDir) ->
    CertFile = filename:join(PrivDir, "iam-stub-cert.pem"),
    KeyFile = filename:join(PrivDir, "iam-stub-key.pem"),
    Cmd = lists:flatten(
        io_lib:format(
            "openssl req -x509 -newkey rsa:2048 -nodes "
            "-keyout ~ts -out ~ts -days 1 "
            "-subj /CN=127.0.0.1 2>/dev/null",
            [KeyFile, CertFile]
        )
    ),
    _ = os:cmd(Cmd),
    true = filelib:is_regular(CertFile) andalso filelib:is_regular(KeyFile),
    {CertFile, KeyFile}.

%%--------------------------------------------------------------------
%% Token / JWK helpers
%%--------------------------------------------------------------------

stub_url(Config, Path) ->
    Port = ?config(stub_port, Config),
    iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port), Path]).

%% Drive the backend exactly as the registry would: validate/1 on a body already
%% filtered to allowed_fields. The full request pipeline is covered by
%% aws_auth_validate_mgmt_SUITE.
validate(Body) ->
    aws_auth_validate_iam:validate(Body).

fixture_jwk() ->
    fixture_jwk(?JWK_KID, ?JWK_K).

fixture_jwk(Kid, K) ->
    #{
        <<"alg">> => <<"HS256">>,
        <<"k">> => K,
        <<"kid">> => Kid,
        <<"kty">> => <<"oct">>,
        <<"use">> => <<"sig">>
    }.

claims(Exp) ->
    #{<<"sub">> => <<"someone">>, <<"exp">> => Exp}.

future_exp() ->
    os:system_time(second) + 3600.

sign(Jwk, Claims) ->
    Jws = #{<<"alg">> => <<"HS256">>},
    Signed = jose_jwt:sign(jose_jwk:from_map(Jwk), Jws, Claims),
    {_, Compact} = jose_jws:compact(Signed),
    Compact.

%% Flip the middle (payload) segment to invalidate the signature while keeping a
%% well-formed 3-segment compact JWS.
tamper(Token) ->
    [H, P, S] = binary:split(Token, <<".">>, [global]),
    Tampered = tamper_segment(P),
    iolist_to_binary([H, <<".">>, Tampered, <<".">>, S]).

%% Swap the first character for a different base64url character so the payload
%% decodes to different bytes (breaking the signature) but stays base64url.
tamper_segment(<<C, Rest/binary>>) ->
    New =
        case C of
            $A -> $B;
            _ -> $A
        end,
    <<New, Rest/binary>>.
