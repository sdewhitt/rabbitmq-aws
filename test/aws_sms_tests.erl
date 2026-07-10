%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

-module(aws_sms_tests).

-include_lib("eunit/include/eunit.hrl").
-include("aws_lib.hrl").

%%--------------------------------------------------------------------
%% End-to-end guard for the Secrets Manager response path (issue #131).
%%
%% Secrets Manager replies with the `application/x-amz-json-1.1' content
%% type, which aws_lib_response:maybe_decode_body/2 now decodes into a string-keyed
%% proplist (since #99). These cases mock gun so the real api_post_request
%% path runs, then assert fetch_secret/3 returns the secret without a second
%% decode. Before the fix a second rabbit_json:decode ran on the proplist and
%% crashed with badarg.
%%--------------------------------------------------------------------

fetch_secret_test_() ->
    {foreach, fun setup/0, fun teardown/1, [
        fun secret_string_is_returned/0,
        fun secret_binary_is_decoded/0,
        fun missing_secret_reports_error/0
    ]}.

setup() ->
    ok = meck:new(gun, []),
    meck:expect(gun, open, fun(_, _, _) -> {ok, self()} end),
    meck:expect(gun, close, fun(_) -> ok end),
    meck:expect(gun, await_up, fun(_, _) -> {ok, protocol} end),
    meck:expect(gun, post, fun(_, _, _, _, _) -> stream_ref end),
    meck:expect(gun, await, fun(_, _, _) ->
        {response, nofin, 200, [{<<"content-type">>, <<"application/x-amz-json-1.1">>}]}
    end),
    ok.

teardown(_) ->
    catch meck:unload(gun),
    ok.

%% A state that already carries credentials so ensure_credentials_valid does
%% not attempt to reach IMDS.
state() ->
    {ok, State} = aws_lib:set_credentials("AKID", "SECRET", "TOKEN", aws_lib:new()),
    State.

secret_string_is_returned() ->
    meck:expect(gun, await_body, fun(_, _, _) ->
        {ok, <<"{\"SecretString\": \"the-secret-value\"}">>}
    end),
    Result = aws_sms:fetch_secret(
        "arn:aws:secretsmanager:us-east-1:1:secret:s", "us-east-1", state()
    ),
    ?assertMatch({ok, <<"the-secret-value">>, _}, Result).

secret_binary_is_decoded() ->
    Encoded = base64:encode(<<"binary-secret">>),
    Body = <<"{\"SecretBinary\": \"", Encoded/binary, "\"}">>,
    meck:expect(gun, await_body, fun(_, _, _) -> {ok, Body} end),
    Result = aws_sms:fetch_secret(
        "arn:aws:secretsmanager:us-east-1:1:secret:s", "us-east-1", state()
    ),
    ?assertMatch({ok, <<"binary-secret">>, _}, Result).

missing_secret_reports_error() ->
    meck:expect(gun, await_body, fun(_, _, _) ->
        {ok, <<"{\"ARN\": \"arn:aws:secretsmanager:us-east-1:1:secret:s\"}">>}
    end),
    Result = aws_sms:fetch_secret(
        "arn:aws:secretsmanager:us-east-1:1:secret:s", "us-east-1", state()
    ),
    ?assertEqual({error, no_secret_value}, Result).
