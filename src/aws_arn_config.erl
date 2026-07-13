%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

-module(aws_arn_config).

-include("aws.hrl").

-export([process_arns/0]).

-ifdef(TEST).
-compile(export_all).
-endif.

-spec process_arns() -> ok.
%% @doc Fetch certificate files, secrets from Amazon S3 and Secret Manager and update application configuration to use them
%% @end
process_arns() ->
    try
        case process_arn_config({handle_env_arn_config, application:get_env(aws, arn_config)}) of
            {ok, {iam_role_result, assumed}} ->
                ?AWS_LOG_INFO("success");
            {ok, {iam_role_result, not_assumed}} ->
                ?AWS_LOG_INFO("success");
            {error, Error, {iam_role_result, assumed}} ->
                ?AWS_LOG_ERROR("~tp", [Error]);
            {error, Error, {iam_role_result, not_assumed}} ->
                ?AWS_LOG_ERROR("~tp", [Error])
        end
    catch
        Class:Reason:Stacktrace ->
            ?AWS_LOG_ERROR("~tp", [{Class, Reason}]),
            ?AWS_LOG_ERROR("~tp", [Stacktrace])
    end.

maybe_assume_role({arn_config, ArnConfig, State}) when is_list(ArnConfig) ->
    maybe_assume_role(
        {assume_role_arn_value, proplists:get_value(assume_role_arn, ArnConfig), State}
    );
maybe_assume_role({assume_role_arn_value, undefined, State}) ->
    % No assume role configured, use existing credentials
    ?AWS_LOG_WARNING("aws.arns.assume_role_arn is not present in configuration"),
    {ok, not_assumed, State};
maybe_assume_role({assume_role_arn_value, RoleArn, State}) ->
    case aws_iam:assume_role(RoleArn, State) of
        {error, Error} ->
            {error, {assume_role_failed, Error}};
        {ok, State1} ->
            {ok, assumed, State1}
    end.

process_arn_config({handle_env_arn_config, undefined}) ->
    ?AWS_LOG_INFO("no ARNs to process"),
    {ok, {iam_role_result, not_assumed}};
process_arn_config({handle_env_arn_config, {ok, ArnConfig}}) ->
    process_arn_config({handle_env_arns, proplists:get_value(arns, ArnConfig), ArnConfig});
process_arn_config({handle_env_arns, undefined, _}) ->
    ?AWS_LOG_INFO("no ARNs to process"),
    {ok, {iam_role_result, not_assumed}};
process_arn_config({handle_env_arns, ArnList, ArnConfig}) ->
    %% Start from an empty aws_state(). We deliberately do NOT seed a region
    %% here: aws_lib resolves the default region on its own during the first
    %% request -- do_refresh_credentials/1 (reached via ensure_credentials_valid
    %% inside every api_*_request) falls back to aws_lib_config:region/1 when the
    %% state region is undefined and stores the discovered region back into the
    %% threaded state. The sms/acm-pca leaves override the region per-ARN via
    %% aws_lib:set_region/2; s3 uses the default. Relying on aws_lib's discovery
    %% avoids coupling this boot module to the #aws_config{} record and keeps the
    %% region-resolution logic in one place (aws_lib).
    State = aws_lib:new(),
    % Assume role once, then process all ARNs with those credentials
    process_arn_config(
        {handle_assume_role, maybe_assume_role({arn_config, ArnConfig, State})}, ArnList
    ).

process_arn_config({handle_assume_role, {ok, AssumeRoleResult, State0}}, ArnList) ->
    State1 = aws_lib:enable_connection_reuse(State0),
    Result = run_arn_handlers(ArnList, State1),
    handle_arn_handlers_result(Result, AssumeRoleResult);
process_arn_config({handle_assume_role, {error, _}} = Error, _ArnList) ->
    {error, Error, {iam_role_result, not_assumed}}.

handle_arn_handlers_result({ok, State}, AssumeRoleResult) ->
    _ = aws_lib:close_reuse_connection(State),
    {ok, {iam_role_result, AssumeRoleResult}};
handle_arn_handlers_result({error, Error, State}, AssumeRoleResult) ->
    _ = aws_lib:close_reuse_connection(State),
    {error, Error, {iam_role_result, AssumeRoleResult}}.

run_arn_handlers([], State) ->
    {ok, State};
run_arn_handlers([{Mod, undefined, _SchemaKey, Args} | Rest], State) ->
    %% Pure-sink / self-resolving handler. The only such handler is the oauth2
    %% providers map (aws_arn_config_oauth2:run/4), which resolves a map of ARNs
    %% itself, so it needs the aws_state() threaded in as a trailing argument and
    %% returns the updated state as {ok, State1}. Thread State1 forward so a
    %% later handler sees any credentials this handler refreshed, mirroring the
    %% resolved-ARN clause below.
    case erlang:apply(Mod, run, Args ++ [State]) of
        {ok, State1} ->
            run_arn_handlers(Rest, State1);
        {error, _} = Error ->
            {error, Error, State}
    end;
run_arn_handlers([{Mod, Arn, SchemaKey, Args} | Rest], State) ->
    case aws_arn_util:resolve_arn(Arn, State) of
        {ok, ArnData, State1} ->
            case erlang:apply(Mod, run, [ArnData | Args]) of
                ok ->
                    run_arn_handlers(Rest, State1);
                {error, _} = Error ->
                    {error, Error, State1}
            end;
        {error, Reason, State1} ->
            {error, get_resolve_arn_error(Arn, SchemaKey, {error, Reason}), State1}
    end.

get_resolve_arn_error(Arn, SchemaKey, {error, E} = Error) ->
    ErrMsg0 = io_lib:format(
        "could not resolve ARN '~ts' for configuration '~ts', error: ~tp",
        [Arn, SchemaKey, E]
    ),
    ErrMsg1 = rabbit_data_coercion:to_utf8_binary(ErrMsg0),
    {ErrMsg1, Error}.
