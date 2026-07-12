%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

-module(aws_s3).

-export([fetch_object/2]).

-spec fetch_object(string(), aws_lib:aws_state()) ->
    {ok, binary(), aws_lib:aws_state()} | {error, term(), aws_lib:aws_state()}.
fetch_object(Resource, State) ->
    %% Note: splits on the first / only
    %% https://www.erlang.org/doc/apps/stdlib/string.html#split/2
    [Bucket | Key] = string:split(Resource, "/"),
    Path = "/" ++ Bucket ++ "/" ++ Key,
    case aws_lib:api_get_request("s3", Path, State) of
        {ok, _Body, _State1} = Response ->
            Response;
        {error, _Reason, _State1} = Error ->
            Error
    end.
