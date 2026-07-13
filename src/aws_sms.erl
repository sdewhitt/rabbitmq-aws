%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

-module(aws_sms).

-export([fetch_secret/3]).

-spec fetch_secret(string(), string(), aws_lib:aws_state()) ->
    {ok, binary(), aws_lib:aws_state()} | {error, term(), aws_lib:aws_state()}.
fetch_secret(Arn, Region, State) ->
    {ok, State1} = aws_lib:set_region(Region, State),
    RequestBody = rabbit_json:encode(#{
        <<"SecretId">> => rabbit_data_coercion:to_utf8_binary(Arn),
        <<"VersionStage">> => <<"AWSCURRENT">>
    }),
    Headers = [
        {"X-Amz-Target", "secretsmanager.GetSecretValue"},
        {"Content-Type", "application/x-amz-json-1.1"}
    ],
    make_request(RequestBody, Headers, State1).

make_request(RequestBody, Headers, State) ->
    case aws_lib:api_post_request("secretsmanager", "/", RequestBody, Headers, State) of
        {ok, ResponseBody, State1} ->
            case find_secret(ResponseBody) of
                {ok, Secret} ->
                    {ok, Secret, State1};
                {error, Reason} ->
                    {error, Reason, State1}
            end;
        {error, _Reason, _State1} = Error ->
            Error
    end.

%% api_post_request already decodes the JSON body (aws_lib_json:decode) into a
%% string-keyed proplist, so match it directly rather than decoding a second
%% time (issue #131).
find_secret(ResponseBody) ->
    case lists:keyfind("SecretString", 1, ResponseBody) of
        {"SecretString", SecretValue} ->
            {ok, rabbit_data_coercion:to_utf8_binary(SecretValue)};
        false ->
            case lists:keyfind("SecretBinary", 1, ResponseBody) of
                {"SecretBinary", SecretBinary} ->
                    {ok, base64:decode(SecretBinary)};
                false ->
                    {error, no_secret_value}
            end
    end.
