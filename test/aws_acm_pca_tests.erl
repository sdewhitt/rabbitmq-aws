%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

-module(aws_acm_pca_tests).

-include_lib("eunit/include/eunit.hrl").
-include("aws_lib.hrl").

%%--------------------------------------------------------------------
%% End-to-end guard for the ACM Private CA response path (issue #131).
%%
%% ACM-PCA replies with the `application/x-amz-json-1.1' content type, which
%% aws_lib:maybe_decode_body/2 now decodes into a string-keyed proplist (since
%% #99). These cases mock gun so the real api_post_request path runs, then
%% assert fetch_certificate/3 returns the certificate without a second decode.
%% Before the fix a second rabbit_json:decode ran on the proplist and crashed
%% with badarg.
%%--------------------------------------------------------------------

fetch_certificate_test_() ->
    {foreach, fun setup/0, fun teardown/1, [
        fun certificate_is_returned/0,
        fun missing_certificate_reports_error/0
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

certificate_is_returned() ->
    meck:expect(gun, await_body, fun(_, _, _) ->
        {ok, <<"{\"Certificate\": \"-----BEGIN CERTIFICATE-----\"}">>}
    end),
    Arn = "arn:aws:acm-pca:us-east-1:1:certificate-authority/ca",
    Result = aws_acm_pca:fetch_certificate(Arn, "us-east-1", state()),
    ?assertMatch({ok, <<"-----BEGIN CERTIFICATE-----">>, _}, Result).

missing_certificate_reports_error() ->
    meck:expect(gun, await_body, fun(_, _, _) ->
        {ok, <<"{\"CertificateChain\": \"chain\"}">>}
    end),
    Arn = "arn:aws:acm-pca:us-east-1:1:certificate-authority/ca",
    Result = aws_acm_pca:fetch_certificate(Arn, "us-east-1", state()),
    ?assertEqual({error, no_certificate}, Result).
