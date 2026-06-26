%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

-module(aws_arn_config_tests).

-include_lib("eunit/include/eunit.hrl").
-include("aws_lib.hrl").

%% A handler module name used by the boot-path tests. The functions are
%% installed with meck (non_strict) per test, so the module itself need not
%% exist on disk.
-define(HANDLER, aws_arn_config_test_handler).

parse_arn_s3_test() ->
    Arn = "arn:aws:s3:::private-ca-42/cacertfile.pem",
    {ok, Parsed} = aws_arn_util:parse_arn(Arn),
    ?assertEqual("aws", maps:get(partition, Parsed)),
    ?assertEqual("s3", maps:get(service, Parsed)),
    ?assertEqual("", maps:get(region, Parsed)),
    ?assertEqual("", maps:get(account, Parsed)),
    ?assertEqual("private-ca-42/cacertfile.pem", maps:get(resource, Parsed)).

parse_arn_s3_nested_path_test() ->
    Arn = "arn:aws:s3:::my-bucket/path/to/cert.pem",
    {ok, Parsed} = aws_arn_util:parse_arn(Arn),
    ?assertEqual("my-bucket/path/to/cert.pem", maps:get(resource, Parsed)).

parse_arn_invalid_test() ->
    ?assertMatch({error, {invalid_arn_format, _}}, aws_arn_util:parse_arn("invalid")).

parse_arn_empty_test() ->
    ?assertMatch({error, {invalid_arn_format, _}}, aws_arn_util:parse_arn("")).

parse_arn_incomplete_test() ->
    ?assertMatch({error, {invalid_arn_format, _}}, aws_arn_util:parse_arn("arn:aws:s3")).

replace_in_env_test() ->
    ExpectedOtherKeyValue = "value",
    Expected = [<<"cacertdata">>],
    ok = application:set_env(
        rabbitmq_auth_backend_oauth2,
        key_config,
        [{other_key, ExpectedOtherKeyValue}, {cacertfile, "/tmp/ca.pem"}]
    ),

    ok = aws_arn_env:replace(
        rabbitmq_auth_backend_oauth2, key_config, cacertfile, cacerts, {ok, Expected}
    ),

    {ok, KeyConfig} = application:get_env(rabbitmq_auth_backend_oauth2, key_config),
    ?assertMatch(Expected, proplists:get_value(cacerts, KeyConfig)),
    ?assertMatch(ExpectedOtherKeyValue, proplists:get_value(other_key, KeyConfig)).

%%--------------------------------------------------------------------
%% Boot-path orchestration: assume-role + ARN-handler state threading
%%
%% process_arns/0 seeds an empty aws_lib:aws_state() and threads it through
%% maybe_assume_role/1, then through run_arn_handlers/2 (one resolve_arn/2
%% per ARN). These cases mock aws_iam:assume_role/2 and
%% aws_arn_util:resolve_arn/2 -- the only external calls -- so the pure
%% orchestration runs without a broker or AWS. The opaque state is observed
%% via the credentials it carries (aws_lib:get_credentials/1).
%%--------------------------------------------------------------------

boot_path_test_() ->
    {foreach, fun boot_setup/0, fun boot_teardown/1, [
        fun assume_role_not_configured_threads_state/0,
        fun assume_role_success_threads_assumed_credentials/0,
        fun assume_role_failure_short_circuits/0,
        fun resolved_state_propagates_across_arns/0,
        fun resolve_arn_error_short_circuits/0,
        fun self_resolving_handler_receives_state/0
    ]}.

boot_setup() ->
    ok = meck:new(aws_iam, [no_link]),
    ok = meck:new(aws_arn_util, [passthrough, no_link]),
    ok = meck:new(?HANDLER, [non_strict, no_link]),
    ok.

boot_teardown(_) ->
    catch meck:unload(?HANDLER),
    catch meck:unload(aws_arn_util),
    catch meck:unload(aws_iam),
    ok.

%% A state carrying these credentials is distinguishable, via
%% aws_lib:get_credentials/1, from the credential-free aws_lib:new().
-define(ASSUMED_KEY, "assumed-access-key").
-define(RESOLVE_KEY, "resolved-access-key").

assumed_state() ->
    {ok, S} = aws_lib:set_credentials(?ASSUMED_KEY, "secret", "token", aws_lib:new()),
    S.

access_key(State) ->
    case aws_lib:get_credentials(State) of
        {ok, #aws_credentials{access_key = Key}} -> Key;
        {error, undefined} -> undefined
    end.

%% No assume_role_arn configured: maybe_assume_role returns
%% {ok, not_assumed, State}, the seeded empty state is threaded onward, and
%% handlers run with no credentials. assume_role is never called.
assume_role_not_configured_threads_state() ->
    Self = self(),
    ok = meck:expect(aws_arn_util, resolve_arn, fun(_Arn, State) ->
        Self ! {resolved_state_key, access_key(State)},
        {ok, <<"data">>, State}
    end),
    ok = meck:expect(?HANDLER, run, fun(_Data, _Key, _Sub) -> ok end),
    ArnConfig = [{arns, [{?HANDLER, "arn:aws:s3:::b/k", some_key, [some_key, sub_key]}]}],
    Result = aws_arn_config:process_arn_config({handle_env_arn_config, {ok, ArnConfig}}),
    ?assertEqual({ok, {iam_role_result, not_assumed}}, Result),
    ?assertEqual(0, meck:num_calls(aws_iam, assume_role, '_')),
    ?assertEqual(undefined, flush_resolved_state_key()).

%% assume_role succeeds and returns a state carrying assumed credentials;
%% that state -- not the seeded empty one -- must reach the ARN handlers.
assume_role_success_threads_assumed_credentials() ->
    Self = self(),
    ok = meck:expect(aws_iam, assume_role, fun(_RoleArn, _State) ->
        {ok, assumed_state()}
    end),
    ok = meck:expect(aws_arn_util, resolve_arn, fun(_Arn, State) ->
        Self ! {resolved_state_key, access_key(State)},
        {ok, <<"data">>, State}
    end),
    ok = meck:expect(?HANDLER, run, fun(_Data, _Key, _Sub) -> ok end),
    ArnConfig = [
        {assume_role_arn, "arn:aws:iam::123456789012:role/r"},
        {arns, [{?HANDLER, "arn:aws:s3:::b/k", some_key, [some_key, sub_key]}]}
    ],
    Result = aws_arn_config:process_arn_config({handle_env_arn_config, {ok, ArnConfig}}),
    ?assertEqual({ok, {iam_role_result, assumed}}, Result),
    ?assertEqual(?ASSUMED_KEY, flush_resolved_state_key()).

%% assume_role fails: process_arns never reaches the handlers and reports
%% the failure with not_assumed.
assume_role_failure_short_circuits() ->
    ok = meck:expect(aws_iam, assume_role, fun(_RoleArn, _State) ->
        {error, boom}
    end),
    ok = meck:expect(aws_arn_util, resolve_arn, fun(_Arn, State) -> {ok, <<"data">>, State} end),
    ok = meck:expect(?HANDLER, run, fun(_Data, _Key, _Sub) -> ok end),
    ArnConfig = [
        {assume_role_arn, "arn:aws:iam::123456789012:role/r"},
        {arns, [{?HANDLER, "arn:aws:s3:::b/k", some_key, [some_key, sub_key]}]}
    ],
    Result = aws_arn_config:process_arn_config({handle_env_arn_config, {ok, ArnConfig}}),
    ?assertMatch(
        {error, {handle_assume_role, {error, {assume_role_failed, boom}}},
            {iam_role_result, not_assumed}},
        Result
    ),
    ?assertEqual(0, meck:num_calls(aws_arn_util, resolve_arn, '_')).

%% The updated state returned by resolve_arn/2 for ARN N must be the state
%% passed to resolve_arn/2 for ARN N+1 (run_arn_handlers threads State1, not
%% the original State). The first resolution stamps credentials onto the
%% threaded state; the second must observe them.
resolved_state_propagates_across_arns() ->
    Self = self(),
    ok = meck:expect(aws_arn_util, resolve_arn, fun(Arn, State) ->
        Self ! {seen, Arn, access_key(State)},
        case Arn of
            "arn:aws:s3:::b/first" ->
                {ok, S} = aws_lib:set_credentials(?RESOLVE_KEY, "secret", "token", State),
                {ok, <<"data1">>, S};
            _ ->
                {ok, <<"data2">>, State}
        end
    end),
    ok = meck:expect(?HANDLER, run, fun(_Data, _Key, _Sub) -> ok end),
    ArnConfig = [
        {arns, [
            {?HANDLER, "arn:aws:s3:::b/first", key1, [key1, sub1]},
            {?HANDLER, "arn:aws:s3:::b/second", key2, [key2, sub2]}
        ]}
    ],
    Result = aws_arn_config:process_arn_config({handle_env_arn_config, {ok, ArnConfig}}),
    ?assertEqual({ok, {iam_role_result, not_assumed}}, Result),
    %% First ARN sees the seeded empty state; second sees the credentials the
    %% first resolution stamped on, proving State1 propagated.
    ?assertEqual({"arn:aws:s3:::b/first", undefined}, flush_seen()),
    ?assertEqual({"arn:aws:s3:::b/second", ?RESOLVE_KEY}, flush_seen()).

%% A resolve_arn/2 error stops the handler chain at that ARN: the remaining
%% ARN is never resolved and the error is wrapped for the failing key.
resolve_arn_error_short_circuits() ->
    ok = meck:expect(aws_arn_util, resolve_arn, fun(Arn, _State) ->
        case Arn of
            "arn:aws:s3:::b/first" -> {error, not_found};
            _ -> erlang:error(second_arn_should_not_resolve)
        end
    end),
    ok = meck:expect(?HANDLER, run, fun(_Data, _Key, _Sub) -> ok end),
    ArnConfig = [
        {arns, [
            {?HANDLER, "arn:aws:s3:::b/first", first_key, [first_key, sub1]},
            {?HANDLER, "arn:aws:s3:::b/second", second_key, [second_key, sub2]}
        ]}
    ],
    Result = aws_arn_config:process_arn_config({handle_env_arn_config, {ok, ArnConfig}}),
    ?assertMatch(
        {error, {_ErrMsg, {error, not_found}}, {iam_role_result, not_assumed}},
        Result
    ),
    ?assertEqual(1, meck:num_calls(aws_arn_util, resolve_arn, '_')),
    ?assertEqual(0, meck:num_calls(?HANDLER, run, '_')).

%% The self-resolving handler (Arn = undefined) is invoked as
%% Mod:run(Args ++ [State]); it resolves its own ARNs, so the threaded state
%% must arrive as the trailing argument.
self_resolving_handler_receives_state() ->
    Self = self(),
    %% run/4: Args is [Key, ConfigKey, Map] (3 elements), State appended.
    ok = meck:expect(?HANDLER, run, fun(_Key, _ConfigKey, _Map, State) ->
        Self ! {self_resolving_state, access_key(State)},
        ok
    end),
    ArnConfig = [
        {arns, [{?HANDLER, undefined, the_key, [the_key, providers, #{<<"0">> => <<"arn">>}]}]}
    ],
    Result = aws_arn_config:process_arn_config({handle_env_arn_config, {ok, ArnConfig}}),
    ?assertEqual({ok, {iam_role_result, not_assumed}}, Result),
    %% No assume role configured, so the trailing state is the seeded empty one.
    receive
        {self_resolving_state, Key} -> ?assertEqual(undefined, Key)
    after 1000 -> erlang:error(handler_not_called)
    end.

flush_resolved_state_key() ->
    receive
        {resolved_state_key, Key} -> Key
    after 1000 -> erlang:error(resolve_arn_not_called)
    end.

flush_seen() ->
    receive
        {seen, Arn, Key} -> {Arn, Key}
    after 1000 -> erlang:error(resolve_arn_not_called)
    end.
