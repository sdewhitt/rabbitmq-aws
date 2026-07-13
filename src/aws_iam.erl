%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

-module(aws_iam).

-export([assume_role/2]).

%% Export all for unit tests
-ifdef(TEST).
-compile(export_all).
-endif.

-spec assume_role(string() | binary(), aws_lib:aws_state()) ->
    {ok, aws_lib:aws_state()} | {error, term()}.
assume_role(RoleArn, State) when is_binary(RoleArn) ->
    assume_role(binary_to_list(RoleArn), State);
assume_role(RoleArn, State) ->
    SessionName = "rabbitmq-aws-" ++ integer_to_list(erlang:system_time(second)),
    Body =
        "Action=AssumeRole&RoleArn=" ++ uri_string:quote(RoleArn) ++
            "&RoleSessionName=" ++ uri_string:quote(SessionName) ++
            "&Version=2011-06-15",

    BaseHeaders = [
        {"content-type", "application/x-www-form-urlencoded"},
        {"accept", "application/json"}
    ],

    Headers = aws_sts:add_custom_headers(BaseHeaders),
    make_request(Body, Headers, State).

-spec parse_assume_role_response(any(), aws_lib:aws_state()) ->
    {ok, aws_lib:aws_state()}.
parse_assume_role_response(Body, State) ->
    [{"AssumeRoleResponse", ResponseData}] = Body,
    {"AssumeRoleResult", ResultData} = lists:keyfind("AssumeRoleResult", 1, ResponseData),
    {"Credentials", CredentialsData} = lists:keyfind("Credentials", 1, ResultData),
    {"AccessKeyId", AccessKey} = lists:keyfind("AccessKeyId", 1, CredentialsData),
    {"SecretAccessKey", SecretKey} = lists:keyfind("SecretAccessKey", 1, CredentialsData),
    {"SessionToken", SessionToken} = lists:keyfind("SessionToken", 1, CredentialsData),
    {ok, State1} = aws_lib:set_credentials(AccessKey, SecretKey, SessionToken, State),
    {ok, State1}.

make_request(Body, Headers, State) ->
    case aws_lib:api_post_request("sts", "/", Body, Headers, State) of
        {ok, ResponseBody, State1} ->
            parse_assume_role_response(ResponseBody, State1);
        {error, Reason, _State1} ->
            %% assume_role/2 runs before connection reuse is enabled (one-shot
            %% mode), so there is no connection to hand back; collapse the error
            %% to a 2-tuple and keep this module's public contract unchanged.
            {error, Reason}
    end.
