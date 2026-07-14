%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% HTTP-level tests for the auth validation endpoint
%%   PUT /api/aws/auth/validate/:method
%% These exercise the request pipeline (auth, body parsing, dispatch,
%% feature toggle) without requiring a real LDAP server. The actual
%% bind/connect/TLS paths are covered in aws_auth_validate_ldap_SUITE.
-module(aws_auth_validate_mgmt_SUITE).

-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    feature_disabled_returns_404/1,
    unknown_method_returns_404/1,
    bad_json_returns_400/1,
    body_too_large_returns_400/1,
    config_conflict_returns_422/1,
    missing_servers_returns_400/1,
    capacity_exhausted_returns_503/1,
    enabled_without_worker_returns_503/1,
    method_disabled_returns_404/1,
    backend_raise_returns_500_without_leak/1,
    custom_tag_insufficient_returns_401/1,
    custom_tag_unauthenticated_put_returns_401/1,
    custom_tag_options_preflight_allowed/1,
    options_returns_allowed_methods/1,
    get_returns_405/1,
    password_not_in_response/1,
    success_returns_204/1,
    oauth_disabled_by_default_returns_404/1,
    oauth_success_returns_204/1,
    oauth_response_no_secret/1
]).

%% Invoked on the broker node via rpc to hold a semaphore slot.
-export([hold_slot/1]).

%% Invoked on the broker node via rpc to stub/unstub the registry dispatch.
-export([mock_dispatch_ok/0, mock_dispatch_raise/1, unmock_dispatch/0]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("rabbitmq_ct_helpers/include/rabbit_mgmt_test.hrl").
-include("aws.hrl").

-define(API, "/aws/auth/validate/ldap").
-define(OAUTH_API, "/aws/auth/validate/oauth").

%% A unique secret-shaped sentinel that a backend raise carries in scope. If the
%% handler's crash-dump guard ever let it escape, it would surface in the HTTP
%% response body; backend_raise_returns_500_without_leak asserts it does not.
-define(LEAK_SENTINEL, <<"S3cr3t-Sentinel-Handler-Leak-DO-NOT-LEAK">>).

all() ->
    [
        {group, feature_disabled},
        {group, feature_enabled},
        {group, feature_enabled_custom_tag},
        {group, oauth_method}
    ].

groups() ->
    [
        {feature_disabled, [], [
            feature_disabled_returns_404
        ]},
        {feature_enabled, [], [
            unknown_method_returns_404,
            bad_json_returns_400,
            body_too_large_returns_400,
            config_conflict_returns_422,
            missing_servers_returns_400,
            capacity_exhausted_returns_503,
            enabled_without_worker_returns_503,
            method_disabled_returns_404,
            backend_raise_returns_500_without_leak,
            options_returns_allowed_methods,
            get_returns_405,
            password_not_in_response,
            success_returns_204
        ]},
        %% A non-administrator required_user_tag exercises the authorize_tag/3
        %% branch: a user lacking the tag gets 401, while an OPTIONS preflight
        %% (unauthenticated, user=undefined) must still be allowed through.
        {feature_enabled_custom_tag, [], [
            custom_tag_insufficient_returns_401,
            custom_tag_unauthenticated_put_returns_401,
            custom_tag_options_preflight_allowed
        ]},
        %% OAuth method tests: opt-in behaviour (disabled by default -> 404),
        %% and success/no-secret when enabled with mocked dispatch.
        {oauth_method, [], [
            oauth_disabled_by_default_returns_404,
            oauth_success_returns_204,
            oauth_response_no_secret
        ]}
    ].

init_per_suite(Config) ->
    ok = inets:start(),
    rabbit_ct_helpers:log_environment(),
    Config.

end_per_suite(Config) ->
    inets:stop(),
    Config.

init_per_group(feature_disabled, Config) ->
    setup_broker(Config, [{auth_validation_enabled, false}]);
init_per_group(feature_enabled, Config) ->
    setup_broker(Config, [
        {auth_validation_enabled, true},
        {auth_validation_max_concurrent, 1},
        {auth_validation_max_body_size, 1024},
        %% base_body/0 uses a loopback server (127.0.0.1); without this the
        %% SSRF filter (is_allowed_server/1) rejects it with input_invalid in
        %% parse_servers BEFORE later pipeline stages run, so cases that assert
        %% a later outcome (e.g. config_conflict_returns_422) would wrongly see
        %% a 400. These tests never open a real connection, so allowing private
        %% ranges here is safe and exercises the intended code path.
        {auth_validation_allow_private_networks, true}
    ]);
init_per_group(feature_enabled_custom_tag, Config) ->
    setup_broker(Config, [
        {auth_validation_enabled, true},
        {auth_validation_max_concurrent, 1},
        {auth_validation_max_body_size, 1024},
        {auth_validation_allow_private_networks, true},
        %% guest has the administrator tag but not monitoring, so the
        %% authorize_tag/3 membership check fails -> 401.
        {auth_validation_required_user_tag, monitoring}
    ]);
init_per_group(oauth_method, Config) ->
    %% OAuth is opt-in; enable validation but do NOT add oauth to
    %% enabled_methods so the default (disabled) applies for the
    %% disabled-by-default case. Individual testcases that need the method
    %% enabled will toggle it in init_per_testcase.
    setup_broker(Config, [
        {auth_validation_enabled, true},
        {auth_validation_max_concurrent, 1},
        {auth_validation_max_body_size, 1024}
    ]).

end_per_group(_Group, Config) ->
    rabbit_ct_helpers:run_teardown_steps(
        Config,
        rabbit_ct_broker_helpers:teardown_steps()
    ).

init_per_testcase(method_disabled_returns_404 = TC, Config) ->
    rabbit_ct_broker_helpers:rpc(
        Config,
        0,
        application,
        set_env,
        [aws, auth_validation_enabled_methods, [{<<"ldap">>, false}]]
    ),
    rabbit_ct_helpers:testcase_started(Config, TC);
init_per_testcase(success_returns_204 = TC, Config) ->
    %% This suite has no live LDAP server, so make the backend dispatch return
    %% the success result (`ok') directly. meck runs ON THE BROKER NODE so the
    %% handler's call to aws_auth_validate_registry:dispatch/2 sees the stub.
    ok = rabbit_ct_broker_helpers:rpc(
        Config, 0, ?MODULE, mock_dispatch_ok, []
    ),
    rabbit_ct_helpers:testcase_started(Config, TC);
init_per_testcase(backend_raise_returns_500_without_leak = TC, Config) ->
    %% Drive the registry dispatch to RAISE with a secret-bearing term, so the
    %% handler's with_semaphore/6 defence-in-depth catch (the R6 crash-dump guard)
    %% is exercised through the real Cowboy pipeline. The mock runs ON THE BROKER
    %% NODE so the handler sees it.
    ok = rabbit_ct_broker_helpers:rpc(
        Config, 0, ?MODULE, mock_dispatch_raise, [?LEAK_SENTINEL]
    ),
    rabbit_ct_helpers:testcase_started(Config, TC);
init_per_testcase(oauth_success_returns_204 = TC, Config) ->
    %% Enable the oauth method and mock dispatch to return ok.
    rabbit_ct_broker_helpers:rpc(
        Config,
        0,
        application,
        set_env,
        [aws, auth_validation_enabled_methods, [{<<"oauth">>, true}]]
    ),
    ok = rabbit_ct_broker_helpers:rpc(
        Config, 0, ?MODULE, mock_dispatch_ok, []
    ),
    rabbit_ct_helpers:testcase_started(Config, TC);
init_per_testcase(oauth_response_no_secret = TC, Config) ->
    %% Enable the oauth method and mock dispatch to return ok.
    rabbit_ct_broker_helpers:rpc(
        Config,
        0,
        application,
        set_env,
        [aws, auth_validation_enabled_methods, [{<<"oauth">>, true}]]
    ),
    ok = rabbit_ct_broker_helpers:rpc(
        Config, 0, ?MODULE, mock_dispatch_ok, []
    ),
    rabbit_ct_helpers:testcase_started(Config, TC);
init_per_testcase(TC, Config) ->
    rabbit_ct_helpers:testcase_started(Config, TC).

end_per_testcase(method_disabled_returns_404 = TC, Config) ->
    rabbit_ct_broker_helpers:rpc(
        Config, 0, application, unset_env, [aws, auth_validation_enabled_methods]
    ),
    rabbit_ct_helpers:testcase_finished(Config, TC);
end_per_testcase(success_returns_204 = TC, Config) ->
    ok = rabbit_ct_broker_helpers:rpc(
        Config, 0, ?MODULE, unmock_dispatch, []
    ),
    rabbit_ct_helpers:testcase_finished(Config, TC);
end_per_testcase(backend_raise_returns_500_without_leak = TC, Config) ->
    ok = rabbit_ct_broker_helpers:rpc(
        Config, 0, ?MODULE, unmock_dispatch, []
    ),
    rabbit_ct_helpers:testcase_finished(Config, TC);
end_per_testcase(oauth_success_returns_204 = TC, Config) ->
    ok = rabbit_ct_broker_helpers:rpc(
        Config, 0, ?MODULE, unmock_dispatch, []
    ),
    rabbit_ct_broker_helpers:rpc(
        Config, 0, application, unset_env, [aws, auth_validation_enabled_methods]
    ),
    rabbit_ct_helpers:testcase_finished(Config, TC);
end_per_testcase(oauth_response_no_secret = TC, Config) ->
    ok = rabbit_ct_broker_helpers:rpc(
        Config, 0, ?MODULE, unmock_dispatch, []
    ),
    rabbit_ct_broker_helpers:rpc(
        Config, 0, application, unset_env, [aws, auth_validation_enabled_methods]
    ),
    rabbit_ct_helpers:testcase_finished(Config, TC);
end_per_testcase(TC, Config) ->
    rabbit_ct_helpers:testcase_finished(Config, TC).

%%--------------------------------------------------------------------
%% Feature-disabled group
%%--------------------------------------------------------------------

feature_disabled_returns_404(Config) ->
    %% with feature disabled, resource_exists/2 -> false -> 404.
    Body = base_body(),
    {ok, {{_, Code, _}, _Headers, _ResBody}} = put_request(Config, ?API, Body),
    ?assertEqual(404, Code).

%%--------------------------------------------------------------------
%% Feature-enabled group
%%--------------------------------------------------------------------

unknown_method_returns_404(Config) ->
    Body = base_body(),
    Path = "/aws/auth/validate/no-such-method",
    {ok, {{_, Code, _}, _, _}} = put_request(Config, Path, Body),
    ?assertEqual(404, Code).

bad_json_returns_400(Config) ->
    rabbit_mgmt_test_util:http_put_raw(Config, ?API, "{not valid json", 400).

body_too_large_returns_400(Config) ->
    Big = binary:copy(<<"x">>, 4096),
    Body = (base_body())#{<<"user_dn">> => Big},
    {ok, {{_, Code, _}, _, _}} = put_request(Config, ?API, Body),
    ?assertEqual(400, Code).

config_conflict_returns_422(Config) ->
    Body = (base_body())#{<<"use_ssl">> => true, <<"use_starttls">> => true},
    {ok, {{_, Code, _}, _, ResBody}} = put_request(Config, ?API, Body),
    ?assertEqual(422, Code),
    ?assertMatch(#{<<"error">> := <<"config_conflict">>}, decode(ResBody)).

missing_servers_returns_400(Config) ->
    Body = maps:remove(<<"servers">>, base_body()),
    {ok, {{_, Code, _}, _, ResBody}} = put_request(Config, ?API, Body),
    ?assertEqual(400, Code),
    ?assertMatch(#{<<"error">> := <<"input_invalid">>}, decode(ResBody)).

capacity_exhausted_returns_503(Config) ->
    %% Hold the only semaphore slot for the duration of the HTTP request.
    %%
    %% A plain rpc(..., aws_auth_validate_semaphore, acquire, []) does NOT
    %% work: erpc runs acquire/0 in a transient worker process that exits as
    %% soon as the call returns, and the semaphore monitors its holder and
    %% auto-releases the slot on that worker's DOWN -- so the slot would be
    %% free again before our request arrives. Instead spawn a long-lived
    %% holder process ON THE BROKER NODE (via ?MODULE:hold_slot/1, which puts
    %% this suite on the broker's code path) that acquires and then blocks
    %% until told to release.
    Holder = rabbit_ct_broker_helpers:rpc(Config, 0, ?MODULE, hold_slot, [self()]),
    ok = wait_for_current(Config, 1, 50),
    try
        Body = base_body(),
        {ok, {{_, Code, _}, _, _}} = put_request(Config, ?API, Body),
        ?assertEqual(503, Code)
    after
        Holder ! release,
        _ = wait_for_current(Config, 0, 50)
    end.

method_disabled_returns_404(Config) ->
    Body = base_body(),
    {ok, {{_, Code, _}, _, _}} = put_request(Config, ?API, Body),
    ?assertEqual(404, Code).

%% R5/R6 (crash-dump leakage): the handler's with_semaphore/6 wraps the backend
%% dispatch in a try/catch whose sole purpose is to keep an escaping exception --
%% which would carry the request BodyMap (and any resolved secret) into a Cowboy
%% crash report -- from ever surfacing. Nothing exercised that catch before: the
%% success/error paths all RETURN a value, so the class:reason:stack discard was
%% asserted nowhere.
%%
%% Here we force dispatch to RAISE with a secret-bearing term (the worst case for
%% a crash-report leak) and drive a real PUT through the handler. We assert:
%%   1. the caller gets the fixed 500 internal_error response (the catch fired --
%%      the request did not 500 with a stacktrace or hang), and
%%   2. neither the sentinel secret nor the raised reason leaks into the response
%%      body -- it is a fixed category + message only.
%% The submitted-password no-leak on the response is covered by
%% password_not_in_response; this is specifically the RAISE path through the
%% handler boundary that the design doc flagged as unproven.
backend_raise_returns_500_without_leak(Config) ->
    Body = (base_body())#{<<"password">> => ?LEAK_SENTINEL},
    {ok, {{_, Code, _}, _Headers, ResBody}} = put_request(Config, ?API, Body),
    ?assertEqual(500, Code),
    Decoded = decode(ResBody),
    ?assertMatch(#{<<"error">> := <<"internal_error">>}, Decoded),
    %% The fixed message is the only detail; no raised reason / stacktrace.
    ?assertMatch(
        #{<<"message">> := <<"Internal error during validation">>}, Decoded
    ),
    %% The secret the raise carried in scope must not appear anywhere in the body.
    RawResBody = iolist_to_binary(ResBody),
    ?assertEqual(nomatch, binary:match(RawResBody, ?LEAK_SENTINEL)).

%% Feature reads enabled but the semaphore worker is not running (the
%% runtime-enable-without-restart / supervisor-gave-up case). The handler
%% must return a graceful 503, not an opaque 500 from a noproc gen_server
%% call. We simulate the missing worker by terminating the supervised child,
%% then restore it so later cases are unaffected.
enabled_without_worker_returns_503(Config) ->
    ok = rabbit_ct_broker_helpers:rpc(
        Config, 0, supervisor, terminate_child, [aws_sup, aws_auth_validate_semaphore]
    ),
    try
        Body = base_body(),
        {ok, {{_, Code, _}, _, ResBody}} = put_request(Config, ?API, Body),
        ?assertEqual(503, Code),
        ?assertMatch(#{<<"error">> := <<"capacity_exhausted">>}, decode(ResBody))
    after
        {ok, _} = rabbit_ct_broker_helpers:rpc(
            Config, 0, supervisor, restart_child, [aws_sup, aws_auth_validate_semaphore]
        )
    end.

%%--------------------------------------------------------------------
%% Feature-enabled-custom-tag group (required_user_tag = monitoring)
%%--------------------------------------------------------------------

%% guest authenticates but lacks the monitoring tag, so authorize_tag/3's
%% membership check fails and the PUT is rejected with 401.
custom_tag_insufficient_returns_401(Config) ->
    Body = base_body(),
    {ok, {{_, Code, _}, _, ResBody}} = put_request(Config, ?API, Body),
    ?assertEqual(401, Code),
    ?assertMatch(#{<<"error">> := <<"insufficient_user_tag">>}, decode(ResBody)).

%% R2 confirmatory test: the authorize_tag/3 `user = undefined' clause
%% (aws_auth_validate_mgmt.erl) lets a request through WITHOUT a user, on the
%% documented assumption that only an unauthenticated OPTIONS preflight can reach
%% it (rabbit_mgmt_util short-circuits OPTIONS to {true, _, undefined} before
%% authenticating). The safety of the whole custom-tag branch rests on that
%% clause being UNREACHABLE by a state-changing PUT. This asserts the invariant:
%% an UNAUTHENTICATED PUT (no auth header) is stopped with 401 by is_authorized/2
%% BEFORE authorize_tag/3 is reached -- it must never dispatch. If a future
%% refactor let an anonymous PUT reach the user=undefined pass-through, this
%% would see a 2xx/4xx-from-dispatch instead of the 401 and fail (CWE-862/863).
custom_tag_unauthenticated_put_returns_401(Config) ->
    Body = binary_to_list(rabbit_json:encode(base_body())),
    %% No auth_header/2 credential -- an anonymous request.
    {ok, {{_, Code, _}, _Headers, _ResBody}} = rabbit_mgmt_test_util:req(
        Config,
        0,
        put,
        ?API,
        [{"content-type", "application/json"}],
        Body
    ),
    ?assertEqual(401, Code).

%% An OPTIONS preflight is unauthenticated (user=undefined) but must still be
%% allowed through on the custom-tag branch -- regression test for the bug
%% where authorize_tag/3 fell through to 401 on the preflight.
custom_tag_options_preflight_allowed(Config) ->
    {ok, {{_, Code, _}, Headers, _}} = rabbit_mgmt_test_util:req(
        Config,
        0,
        options,
        ?API,
        [rabbit_mgmt_test_util:auth_header("guest", "guest")]
    ),
    ?assertEqual(200, Code),
    Allow = string:to_upper(proplists:get_value("allow", Headers, "")),
    ?assert(string:str(Allow, "PUT") > 0),
    ?assert(string:str(Allow, "OPTIONS") > 0).

options_returns_allowed_methods(Config) ->
    {ok, {{_, Code, _}, Headers, _}} = rabbit_mgmt_test_util:req(
        Config,
        0,
        options,
        ?API,
        [rabbit_mgmt_test_util:auth_header("guest", "guest")]
    ),
    ?assertEqual(200, Code),
    Allow = string:to_upper(proplists:get_value("allow", Headers, "")),
    ?assert(string:str(Allow, "PUT") > 0),
    ?assert(string:str(Allow, "OPTIONS") > 0).

get_returns_405(Config) ->
    {ok, {{_, Code, _}, _, _}} = rabbit_mgmt_test_util:req(
        Config,
        0,
        get,
        ?API,
        [rabbit_mgmt_test_util:auth_header("guest", "guest")]
    ),
    ?assertEqual(405, Code).

password_not_in_response(Config) ->
    %% Property 6: response body must never contain the submitted password.
    Password = <<"super-secret-pAssw0rd!">>,
    Body = (base_body())#{
        <<"password">> => Password,
        <<"servers">> => [<<"127.0.0.1">>],
        <<"port">> => 1
    },
    {ok, {{_, _Code, _}, _, ResBody}} = put_request(Config, ?API, Body),
    ?assertEqual(nomatch, binary:match(iolist_to_binary(ResBody), Password)).

%% A successful validation (backend returns `ok') must surface as a 204 with an
%% empty body. The other cases only exercise the error responses; the 204 path
%% (respond(ok, ...)) was otherwise reached only via direct validate/1 calls in
%% the LDAP integration suite, never through the HTTP handler. The backend is
%% stubbed (see init_per_testcase) because this suite has no live LDAP server.
success_returns_204(Config) ->
    Body = base_body(),
    {ok, {{_, Code, _}, _Headers, ResBody}} = put_request(Config, ?API, Body),
    ?assertEqual(204, Code),
    ?assertEqual(<<>>, iolist_to_binary(ResBody)).

%%--------------------------------------------------------------------
%% OAuth method group
%%--------------------------------------------------------------------

%% OAuth is an opt-in method (in ?OPT_IN_METHODS). Without explicit enablement
%% it defaults to disabled, so any PUT to /aws/auth/validate/oauth returns 404.
oauth_disabled_by_default_returns_404(Config) ->
    Body = oauth_body(),
    {ok, {{_, Code, _}, _, _}} = put_request(Config, ?OAUTH_API, Body),
    ?assertEqual(404, Code).

%% With the method enabled and dispatch mocked, the handler returns 204.
oauth_success_returns_204(Config) ->
    Body = oauth_body(),
    {ok, {{_, Code, _}, _Headers, ResBody}} = put_request(Config, ?OAUTH_API, Body),
    ?assertEqual(204, Code),
    ?assertEqual(<<>>, iolist_to_binary(ResBody)).

%% The 204 response must carry no secret material. We submit a body that
%% contains a plausible secret field and verify it does not appear in the
%% response (R6).
oauth_response_no_secret(Config) ->
    Secret = <<"oauth-client-secret-DO-NOT-LEAK-1234">>,
    Body = (oauth_body())#{<<"client_secret">> => Secret},
    {ok, {{_, _Code, _}, _, ResBody}} = put_request(Config, ?OAUTH_API, Body),
    ?assertEqual(nomatch, binary:match(iolist_to_binary(ResBody), Secret)).

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

%% Run ON THE BROKER NODE (invoked via rpc). Stub the registry dispatch so it
%% returns the success result without touching a real LDAP server. meck is
%% loaded onto the broker node by setup_meck/1 during setup_broker/2.
mock_dispatch_ok() ->
    ok = meck:new(aws_auth_validate_registry, [passthrough, no_link]),
    ok = meck:expect(aws_auth_validate_registry, dispatch, fun(_Method, _Body) -> ok end),
    ok.

%% Run ON THE BROKER NODE (invoked via rpc). Stub the registry dispatch so it
%% RAISES with the given secret-bearing term, exercising the handler's
%% with_semaphore/6 crash-dump guard. The secret is embedded in the raised reason
%% -- the worst case for a crash-report leak.
mock_dispatch_raise(Secret) ->
    ok = meck:new(aws_auth_validate_registry, [passthrough, no_link]),
    ok = meck:expect(aws_auth_validate_registry, dispatch, fun(_Method, _Body) ->
        erlang:error({boom, Secret})
    end),
    ok.

unmock_dispatch() ->
    catch meck:unload(aws_auth_validate_registry),
    ok.

setup_broker(Config0, ExtraEnv) ->
    Config1 = rabbit_ct_helpers:set_config(Config0, [
        {rmq_nodename_suffix, ?MODULE}
    ]),
    Config2 = rabbit_ct_helpers:merge_app_env(Config1, {aws, ExtraEnv}),
    Config3 = rabbit_ct_helpers:run_setup_steps(
        Config2,
        rabbit_ct_broker_helpers:setup_steps()
    ),
    case Config3 of
        {skip, _} = Skip ->
            Skip;
        _ ->
            %% Load meck onto the broker node so success_returns_204 can stub
            %% the registry dispatch there.
            ok = rabbit_ct_broker_helpers:setup_meck(Config3),
            Config3
    end.

%% Runs ON THE BROKER NODE (invoked via rpc with Module=?MODULE). Spawns a
%% persistent process that acquires the only semaphore slot and blocks until
%% told to release, so the slot stays held across an HTTP request issued from
%% the CT node. Returns the holder pid (on the broker node).
hold_slot(Parent) ->
    spawn(fun() ->
        {ok, _Ref} = aws_auth_validate_semaphore:acquire(),
        Parent ! slot_held,
        receive
            release -> ok
        after 30_000 -> ok
        end
    end).

%% Poll the semaphore's current holder count until it reaches Target.
wait_for_current(_Config, Target, 0) ->
    {error, {timeout_waiting_for_current, Target}};
wait_for_current(Config, Target, N) ->
    case rabbit_ct_broker_helpers:rpc(Config, 0, aws_auth_validate_semaphore, current, []) of
        Target ->
            ok;
        _ ->
            timer:sleep(20),
            wait_for_current(Config, Target, N - 1)
    end.

base_body() ->
    #{
        <<"servers">> => [<<"127.0.0.1">>],
        <<"port">> => 389,
        <<"user_dn">> => <<"cn=test,dc=example,dc=com">>,
        <<"password">> => <<"unused">>
    }.

put_request(Config, Path, BodyMap) ->
    Body = binary_to_list(rabbit_json:encode(BodyMap)),
    rabbit_mgmt_test_util:req(
        Config,
        0,
        put,
        Path,
        [
            rabbit_mgmt_test_util:auth_header("guest", "guest"),
            {"content-type", "application/json"}
        ],
        Body
    ).

oauth_body() ->
    #{
        <<"jwks_uri">> => <<"https://idp.example.com/.well-known/jwks.json">>
    }.

decode(ResBody) ->
    case rabbit_json:try_decode(iolist_to_binary(ResBody)) of
        {ok, Map} -> Map;
        _ -> #{}
    end.
