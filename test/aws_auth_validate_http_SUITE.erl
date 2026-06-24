%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% Integration tests for the HTTP validation backend against a real, local
%% stub HTTP(S) server. These exercise the parts of aws_auth_validate_http
%% that the unit tests cannot: the actual httpc probe -> connect -> TLS
%% handshake -> response-classification path.
%%
%% Unlike the LDAP suite (which needs an external slapd), the stub server here
%% is an in-process `inets' httpd, so there is no external dependency and the
%% suite does not skip -- a green run always means the probe path executed.
%% Two listeners are started:
%%   * a plaintext HTTP listener that returns a configurable status per path
%%     (200/201 -> ok, 4xx/5xx -> auth_failed), and
%%   * an HTTPS listener with a SELF-SIGNED cert (for verify_peer -> tls_failed).
%% A closed port (nothing listening) drives connection_failed.
%%
%% SSRF note: the HTTP backend hard-denies loopback (127.0.0.0/8) with no
%% allow-private knob (its policy only ever permits customer VPC ranges, never
%% broker-local loopback). The stub necessarily listens on loopback, so this
%% suite mecks aws_auth_validate_http:classify_ip/1 to allow loopback for the
%% duration of the run -- the HTTP analogue of the LDAP suite's
%% auth_validation_allow_private_networks. Production classify_ip is unchanged.
-module(aws_auth_validate_http_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("inets/include/httpd.hrl").

all() ->
    [
        {group, http}
    ].

groups() ->
    [
        {http, [], [
            ok_200_returns_ok,
            ok_201_returns_ok,
            client_error_404_returns_auth_failed,
            server_error_500_returns_auth_failed,
            unreachable_port_returns_connection_failed,
            self_signed_under_verify_peer_returns_tls_failed,
            self_signed_under_verify_none_returns_ok
        ]}
    ].

%%--------------------------------------------------------------------
%% Suite setup / teardown
%%--------------------------------------------------------------------

init_per_suite(Config0) ->
    %% run_setup_steps/1 installs the long_running_testsuite_monitor that
    %% init_per_testcase's testcase_started/2 sends to (see the LDAP suite's
    %% note: without it every case auto-skips and `make ct' exits non-zero).
    Config = rabbit_ct_helpers:run_setup_steps(Config0),
    %% Track whether WE start the inets application so end_per_suite can leave
    %% the node as it found it. CT runs all suites in one node: if we leave
    %% inets running, a later suite that does `ok = inets:start()' (e.g.
    %% aws_auth_validate_mgmt_SUITE) hits {error,{already_started,inets}} and
    %% fails its init_per_suite. ensure_all_started returns the apps IT started.
    {ok, StartedInets} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ssl),
    PrivDir = ?config(priv_dir, Config),
    %% Start the plaintext stub: /ok200, /ok201, /denied404, /error500.
    {HttpPid, HttpPort} = start_http_stub(PrivDir),
    %% Start the HTTPS stub with a freshly-generated self-signed cert.
    {HttpsPid, HttpsPort} = start_https_stub(PrivDir),
    [
        {http_stub_pid, HttpPid},
        {http_port, HttpPort},
        {https_stub_pid, HttpsPid},
        {https_port, HttpsPort},
        {started_inets, lists:member(inets, StartedInets)}
        | Config
    ].

end_per_suite(Config) ->
    catch inets:stop(httpd, ?config(http_stub_pid, Config)),
    catch inets:stop(httpd, ?config(https_stub_pid, Config)),
    %% Only stop the inets application if this suite started it, so we leave
    %% the CT node exactly as we found it for later suites.
    case ?config(started_inets, Config) of
        true -> application:stop(inets);
        _ -> ok
    end,
    rabbit_ct_helpers:run_teardown_steps(Config).

init_per_group(_Group, Config) ->
    %% Allow loopback so the probe reaches the local stub (see module header).
    %% auth_validation_allow_private_networks relaxes ONLY loopback in
    %% classify_ip -- the HTTP analogue of the LDAP suite's local-slapd flag.
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
%% Functional tests -- the five probe outcomes
%%--------------------------------------------------------------------

ok_200_returns_ok(Config) ->
    ?assertEqual(ok, validate(http_body(Config, "/ok200"))).

ok_201_returns_ok(Config) ->
    ?assertEqual(ok, validate(http_body(Config, "/ok201"))).

client_error_404_returns_auth_failed(Config) ->
    ?assertMatch({error, auth_failed, _}, validate(http_body(Config, "/denied404"))).

server_error_500_returns_auth_failed(Config) ->
    ?assertMatch({error, auth_failed, _}, validate(http_body(Config, "/error500"))).

unreachable_port_returns_connection_failed(Config) ->
    %% Port 1 on loopback: nothing listens, so the connect fails fast.
    Body = #{
        <<"user_path">> => <<"http://127.0.0.1:1/ok200">>,
        <<"http_method">> => <<"get">>
    },
    ?assertMatch({error, connection_failed, _}, validate(Body)).

self_signed_under_verify_peer_returns_tls_failed(Config) ->
    %% The HTTPS stub serves a self-signed cert. Under verify_peer (with the
    %% host OS trust store, which does not trust it) the handshake must fail.
    Port = ?config(https_port, Config),
    Url = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port), "/ok200"]),
    Body = #{
        <<"user_path">> => Url,
        <<"http_method">> => <<"get">>,
        <<"ssl_options">> => #{<<"verify">> => <<"verify_peer">>}
    },
    ?assertMatch({error, tls_failed, _}, validate(Body)).

self_signed_under_verify_none_returns_ok(Config) ->
    %% Same self-signed HTTPS stub, but verify_none accepts any cert, so the
    %% 200 from /ok200 classifies as ok. Proves the TLS path itself works.
    Port = ?config(https_port, Config),
    Url = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port), "/ok200"]),
    Body = #{
        <<"user_path">> => Url,
        <<"http_method">> => <<"get">>,
        <<"ssl_options">> => #{<<"verify">> => <<"verify_none">>}
    },
    ?assertEqual(ok, validate(Body)).

%%--------------------------------------------------------------------
%% Request bodies + driver
%%--------------------------------------------------------------------

http_body(Config, Path) ->
    Port = ?config(http_port, Config),
    Url = iolist_to_binary(["http://127.0.0.1:", integer_to_list(Port), Path]),
    #{
        <<"user_path">> => Url,
        <<"http_method">> => <<"get">>
    }.

%% Drive the backend exactly as the registry would: validate/1 on a body
%% already filtered to allowed_fields. The full HTTP request pipeline (auth,
%% body cap, dispatch) is covered by aws_auth_validate_mgmt_SUITE.
validate(Body) ->
    aws_auth_validate_http:validate(Body).

%%--------------------------------------------------------------------
%% Stub HTTP(S) servers (in-process inets httpd)
%%--------------------------------------------------------------------

%% A mod that maps the request path to a fixed status code, so each test can
%% target a path that yields the outcome it asserts.
start_http_stub(PrivDir) ->
    {ok, Pid} = inets:start(httpd, [
        {port, 0},
        {server_name, "aws_http_stub"},
        {server_root, PrivDir},
        {document_root, PrivDir},
        {bind_address, {127, 0, 0, 1}},
        {modules, [?MODULE]}
    ]),
    [{port, Port}] = httpd:info(Pid, [port]),
    {Pid, Port}.

start_https_stub(PrivDir) ->
    {CertFile, KeyFile} = gen_self_signed(PrivDir),
    {ok, Pid} = inets:start(httpd, [
        {port, 0},
        {server_name, "aws_https_stub"},
        {server_root, PrivDir},
        {document_root, PrivDir},
        {bind_address, {127, 0, 0, 1}},
        {socket_type, {ssl, [{certfile, CertFile}, {keyfile, KeyFile}]}},
        {modules, [?MODULE]}
    ]),
    [{port, Port}] = httpd:info(Pid, [port]),
    {Pid, Port}.

%% inets httpd callback module: respond purely from the request path. The probe
%% appends a query string (e.g. /ok200?username=probe) for GET, so match on the
%% path component only, before the "?".
do(Info) ->
    Path = hd(string:split(Info#mod.request_uri, "?")),
    Status =
        case Path of
            "/ok200" -> 200;
            "/ok201" -> 201;
            "/denied404" -> 404;
            "/error500" -> 500;
            _ -> 404
        end,
    Body = "stub",
    Head = [
        {code, Status},
        {content_type, "text/plain"},
        {content_length, integer_to_list(length(Body))}
    ],
    {proceed, [{response, {response, Head, Body}}]}.

%%--------------------------------------------------------------------
%% Self-signed certificate generation (for the TLS listener)
%%--------------------------------------------------------------------

%% Generate a self-signed RSA cert + key into PrivDir and return their paths.
%% Uses the same approach rabbitmq test suites use: shell out to openssl, which
%% is available wherever the broker test toolchain runs.
gen_self_signed(PrivDir) ->
    CertFile = filename:join(PrivDir, "stub-cert.pem"),
    KeyFile = filename:join(PrivDir, "stub-key.pem"),
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
