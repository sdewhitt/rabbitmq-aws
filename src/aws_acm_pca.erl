%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

-module(aws_acm_pca).

-export([fetch_certificate/3]).

-spec fetch_certificate(string(), string(), aws_lib:aws_state()) ->
    {ok, binary(), aws_lib:aws_state()} | {error, term()}.
fetch_certificate(CaArn, Region, State) ->
    {ok, State1} = aws_lib:set_region(Region, State),
    RequestBody = rabbit_json:encode(#{
        <<"CertificateAuthorityArn">> => rabbit_data_coercion:to_utf8_binary(CaArn)
    }),
    Headers = [
        {"X-Amz-Target", "ACMPrivateCA.GetCertificateAuthorityCertificate"},
        {"Content-Type", "application/x-amz-json-1.1"}
    ],
    make_request(RequestBody, Headers, State1).

make_request(RequestBody, Headers, State) ->
    case aws_lib:api_post_request("acm-pca", "/", RequestBody, Headers, State) of
        {ok, ResponseBody, State1} ->
            case rabbit_json:decode(ResponseBody) of
                #{<<"Certificate">> := Certificate} ->
                    {ok, Certificate, State1};
                _ ->
                    {error, no_certificate}
            end;
        {error, _} = Error ->
            Error
    end.
