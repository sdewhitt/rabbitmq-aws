%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% Property-based tests for the plugin's single URI parser, aws_lib_uri:parse/1,
%% and its accessors. These complement the example-based cases in
%% aws_lib_uri_tests. The central property, motivating issue #100, is that NO
%% input -- however malformed -- makes parse/1 crash: it returns a usable uri()
%% for an absolute URI, and {error, {malformed_uri, _}} otherwise.
-module(prop_aws_lib_uri_SUITE).

-compile(nowarn_export_all).
-compile(export_all).

-include_lib("proper/include/proper.hrl").
-include_lib("common_test/include/ct.hrl").

-define(ITERATIONS, 1000).

all() ->
    [
        prop_parse_never_crashes,
        prop_wellformed_roundtrips,
        prop_path_starts_with_slash,
        prop_target_preserves_query
    ].

%%--------------------------------------------------------------------
%% Generators
%%--------------------------------------------------------------------

scheme() ->
    elements(["http", "https"]).

%% A DNS-like host label: starts alnum, no dots/colons/slashes so it round-trips
%% through uri_string without ambiguity.
host() ->
    ?LET(
        {C, Rest},
        {alnum(), list(oneof([alnum(), $-]))},
        [C | Rest]
    ).

alnum() ->
    oneof([choose($a, $z), choose($A, $Z), choose($0, $9)]).

port() ->
    choose(1, 65535).

%% A path segment made of unreserved characters, so parsing does not
%% percent-encode it and the round-trip is exact.
segment() ->
    non_empty(list(oneof([alnum(), $-, $_, $.]))).

path() ->
    ?LET(Segs, list(segment()), "/" ++ string:join(Segs, "/")).

%% A well-formed absolute URI string plus the components it was built from, so a
%% property can assert the parse recovers them.
wellformed_uri() ->
    ?LET(
        {Scheme, Host, MaybePort, Path},
        {scheme(), host(), oneof([default, port()]), path()},
        begin
            {PortStr, ExpectedPort} = port_parts(Scheme, MaybePort),
            URI = Scheme ++ "://" ++ Host ++ PortStr ++ Path,
            {URI, Scheme, Host, ExpectedPort, Path}
        end
    ).

port_parts(Scheme, default) ->
    {"", default_port(Scheme)};
port_parts(_Scheme, Port) ->
    {":" ++ integer_to_list(Port), Port}.

default_port("http") -> 80;
default_port("https") -> 443.

%% Arbitrary junk: any 7-bit string. Most values are NOT valid absolute URIs.
any_string() ->
    ?LET(Chars, list(choose(0, 127)), Chars).

%%--------------------------------------------------------------------
%% Properties
%%--------------------------------------------------------------------

%% Issue #100: parsing arbitrary input never raises. It either yields a usable
%% uri() (host/1 returns a string) or a {error, {malformed_uri, _}} tuple.
prop_parse_never_crashes(_Config) ->
    rabbit_ct_proper_helpers:run_proper(
        fun() ->
            ?FORALL(
                S,
                any_string(),
                case aws_lib_uri:parse(S) of
                    {error, {malformed_uri, _}} -> true;
                    Uri -> is_list(aws_lib_uri:host(Uri))
                end
            )
        end,
        [],
        ?ITERATIONS
    ).

%% A well-formed scheme://host[:port]/path recovers its host and port (defaulted
%% by scheme when absent) through the accessors.
prop_wellformed_roundtrips(_Config) ->
    rabbit_ct_proper_helpers:run_proper(
        fun() ->
            ?FORALL(
                {URI, _Scheme, Host, ExpectedPort, _Path},
                wellformed_uri(),
                begin
                    Uri = aws_lib_uri:parse(URI),
                    aws_lib_uri:host(Uri) =:= Host andalso
                        aws_lib_uri:port(Uri) =:= ExpectedPort
                end
            )
        end,
        [],
        ?ITERATIONS
    ).

%% path/1 always begins with "/", so it is a usable request target regardless of
%% the input path.
prop_path_starts_with_slash(_Config) ->
    rabbit_ct_proper_helpers:run_proper(
        fun() ->
            ?FORALL(
                {URI, _Scheme, _Host, _Port, _Path},
                wellformed_uri(),
                case aws_lib_uri:path(aws_lib_uri:parse(URI)) of
                    [$/ | _] -> true;
                    _ -> false
                end
            )
        end,
        [],
        ?ITERATIONS
    ).

%% target/1 reattaches the query to the path (it is used directly as the Gun
%% request line, so the query must survive).
prop_target_preserves_query(_Config) ->
    rabbit_ct_proper_helpers:run_proper(
        fun() ->
            ?FORALL(
                {{URI, _Scheme, _Host, _Port, BasePath}, Key, Value},
                {wellformed_uri(), segment(), segment()},
                begin
                    Query = Key ++ "=" ++ Value,
                    Target = aws_lib_uri:target(aws_lib_uri:parse(URI ++ "?" ++ Query)),
                    Target =:= BasePath ++ "?" ++ Query
                end
            )
        end,
        [],
        ?ITERATIONS
    ).
