%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

-module(aws_arn_config_oauth2).

-export([run/4]).

run(ArnData, _KeyStr, https, cacertfile) ->
    handle_content(cacertfile, ArnData);
run(_KeyStr, providers_https_cacertfile, OAuth2Map, State) when is_map(OAuth2Map) ->
    % Note:
    % In this case, the ARNs are the values of ArnMap, and the keys
    % are whatever key is necessary to handle the content.
    % maps:fold threads the aws_state() through each ARN resolution so the
    % updated state (and any refreshed credentials) propagates across entries.
    % The final state is returned to the caller (aws_arn_config:run_arn_handlers/2)
    % so subsequent handlers see credentials this handler refreshed.
    F = fun(MapKey, Arn, StateAcc) ->
        case aws_arn_util:resolve_arn(Arn, StateAcc) of
            {ok, Content, StateAcc1} ->
                case handle_oauth2_providers(MapKey, Content) of
                    ok ->
                        StateAcc1;
                    Error ->
                        throw(apply_error(MapKey, Arn, Error))
                end;
            Error ->
                throw(resolve_error(MapKey, Arn, Error))
        end
    end,
    try
        FinalState = maps:fold(F, State, OAuth2Map),
        {ok, FinalState}
    catch
        throw:{error, _} = Error ->
            Error
    end.

%% Wrap a resolve failure for an oauth2 provider ARN with context, matching the
%% {error, {BinaryMsg, OrigError}} shape aws_arn_config:get_resolve_arn_error/3
%% produces for the regular handlers, so both paths report errors uniformly.
resolve_error(ProviderKey, Arn, {error, E} = Error) ->
    wrap_error(
        io_lib:format(
            "could not resolve ARN '~ts' for oauth2 provider '~ts', error: ~tp",
            [Arn, ProviderKey, E]
        ),
        Error
    ).

%% Wrap a content-application failure: the ARN resolved, but decoding or storing
%% the certificate failed.
apply_error(ProviderKey, Arn, {error, E} = Error) ->
    wrap_error(
        io_lib:format(
            "resolved ARN '~ts' for oauth2 provider '~ts' but could not apply it, error: ~tp",
            [Arn, ProviderKey, E]
        ),
        Error
    ).

wrap_error(Msg, Error) ->
    {error, {rabbit_data_coercion:to_utf8_binary(Msg), Error}}.

%%--------------------------------------------------------------------------------------------------
%% rabbitmq_auth_backend_oauth2 plugin
%%
handle_content(cacertfile, PemData) ->
    %% Note: yes it's really key_config and not https like in the
    %% cuttlefish schema
    aws_arn_env:replace(
        rabbitmq_auth_backend_oauth2,
        key_config,
        cacertfile,
        cacerts,
        aws_pem_util:decode_data(PemData)
    ).

handle_oauth2_providers(Key, CaCertPemData) ->
    case aws_pem_util:decode_data(CaCertPemData) of
        {ok, CaCertsDerEncoded} ->
            handle_oauth2_providers_config(
                application:get_env(rabbitmq_auth_backend_oauth2, oauth_providers),
                Key,
                CaCertsDerEncoded
            );
        Error ->
            Error
    end.

handle_oauth2_providers_config({ok, Map0}, Key, CaCertsDerEncoded) when is_map_key(Key, Map0) ->
    % Note:
    % Example for 0th entry in oauth_providers
    % #{<<"0">> => [{https,[{cacertfile,"/tmp/dummycert.pem"}]}],
    Config0 = maps:get(Key, Map0),
    case proplists:get_value(https, Config0) of
        undefined ->
            ok;
        HttpsProplist0 ->
            HttpsProplist1 = proplists:delete(cacertfile, HttpsProplist0),
            HttpsProplist2 = [{cacerts, CaCertsDerEncoded} | HttpsProplist1],
            Config1 = lists:keyreplace(https, 1, Config0, {https, HttpsProplist2}),
            Map1 = Map0#{Key => Config1},
            ok = application:set_env(rabbitmq_auth_backend_oauth2, oauth_providers, Map1)
    end;
handle_oauth2_providers_config(_, _, _) ->
    ok.
