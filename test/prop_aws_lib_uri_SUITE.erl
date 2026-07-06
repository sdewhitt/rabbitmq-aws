%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% Property-based tests for the plugin's single URI parser, aws_lib_uri:parse/1,
%% and the aws_lib:parse_uri/1 adapter built on it. These complement the
%% example-based cases in aws_lib_uri_tests / aws_lib_tests. The central
%% property, motivating issue #100, is that NO input -- however malformed --
%% makes either function crash: it returns a #uri{} (or {Host, Port, Path}) for
%% a usable absolute URI, and {error, {malformed_uri, _}} otherwise.
-module(prop_aws_lib_uri_SUITE).

-compile(nowarn_export_all).
-compile(export_all).

-include_lib("proper/include/proper.hrl").
-include_lib("common_test/include/ct.hrl").

-include("aws_lib.hrl").

-define(ITERATIONS, 1000).

all() ->
    [
        prop_parse_never_crashes,
        prop_parse_uri_never_crashes,
        prop_wellformed_roundtrips,
        prop_parse_uri_path_starts_with_slash,
        prop_parse_uri_preserves_query
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

%% Arbitrary junk: any unicode string. Most values are NOT valid absolute URIs.
any_string() ->
    ?LET(Chars, list(choose(0, 127)), Chars).

%%--------------------------------------------------------------------
%% Properties
%%--------------------------------------------------------------------

%% Issue #100: parsing arbitrary input never raises. It either yields a #uri{}
%% record or a {error, {malformed_uri, _}} tuple.
prop_parse_never_crashes(_Config) ->
    rabbit_ct_proper_helpers:run_proper(
        fun() ->
            ?FORALL(
                S,
                any_string(),
                case aws_lib_uri:parse(S) of
                    #uri{} -> true;
                    {error, {malformed_uri, _}} -> true;
                    _ -> false
                end
            )
        end,
        [],
        ?ITERATIONS
    ).

%% The adapter shares the never-crash guarantee: {Host, Port, Path} or an error.
prop_parse_uri_never_crashes(_Config) ->
    rabbit_ct_proper_helpers:run_proper(
        fun() ->
            ?FORALL(
                S,
                any_string(),
                case aws_lib:parse_uri(S) of
                    {Host, Port, Path} when
                        is_list(Host), is_integer(Port), is_list(Path)
                    ->
                        true;
                    {error, {malformed_uri, _}} ->
                        true;
                    _ ->
                        false
                end
            )
        end,
        [],
        ?ITERATIONS
    ).

%% A well-formed scheme://host[:port]/path recovers its scheme, host, and port
%% (defaulted by scheme when absent) through the canonical parser.
prop_wellformed_roundtrips(_Config) ->
    rabbit_ct_proper_helpers:run_proper(
        fun() ->
            ?FORALL(
                {URI, Scheme, Host, ExpectedPort, _Path},
                wellformed_uri(),
                begin
                    #uri{scheme = S, authority = {_UserInfo, H, P}} =
                        aws_lib_uri:parse(URI),
                    S =:= Scheme andalso H =:= Host andalso P =:= ExpectedPort
                end
            )
        end,
        [],
        ?ITERATIONS
    ).

%% The adapter always returns a Path beginning with "/", so it is a usable Gun
%% request target regardless of the input path.
prop_parse_uri_path_starts_with_slash(_Config) ->
    rabbit_ct_proper_helpers:run_proper(
        fun() ->
            ?FORALL(
                {URI, _Scheme, _Host, _Port, _Path},
                wellformed_uri(),
                begin
                    {_H, _P, Path} = aws_lib:parse_uri(URI),
                    case Path of
                        [$/ | _] -> true;
                        _ -> false
                    end
                end
            )
        end,
        [],
        ?ITERATIONS
    ).

%% A query string on a well-formed URI is reattached to the adapter's Path (it
%% is used directly as the Gun request target, so the query must survive).
prop_parse_uri_preserves_query(_Config) ->
    rabbit_ct_proper_helpers:run_proper(
        fun() ->
            ?FORALL(
                {{URI, _Scheme, _Host, _Port, BasePath}, Key, Value},
                {wellformed_uri(), segment(), segment()},
                begin
                    Query = Key ++ "=" ++ Value,
                    {_H, _P, Path} = aws_lib:parse_uri(URI ++ "?" ++ Query),
                    %% The path retains its base and the query is present.
                    Path =:= BasePath ++ "?" ++ Query
                end
            )
        end,
        [],
        ?ITERATIONS
    ).
