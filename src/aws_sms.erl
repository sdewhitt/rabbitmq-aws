%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

-module(aws_sms).

-export([fetch_secret/3]).

-spec fetch_secret(string(), string(), aws_lib:aws_state()) ->
    {ok, binary(), aws_lib:aws_state()} | {error, term()}.
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
            case rabbit_json:decode(ResponseBody) of
                #{<<"SecretString">> := SecretValue} ->
                    {ok, SecretValue, State1};
                #{<<"SecretBinary">> := SecretBinary} ->
                    {ok, base64:decode(SecretBinary), State1};
                _ ->
                    {error, no_secret_value}
            end;
        {error, _} = Error ->
            Error
    end.
