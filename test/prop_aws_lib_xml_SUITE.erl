%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% Property-based tests for aws_lib_xml:parse/1. Complements the example-based
%% cases in aws_lib_xml_tests. A generated element tree is rendered to an XML
%% string, parsed back, and checked to round-trip: element names, attributes,
%% text, nesting, and repeated siblings are all recovered.
%%
%% The generator produces the well-formed subset the parser targets (see the
%% aws_lib_xml module doc): each element has EITHER text OR child elements, never
%% mixed content, and names/values avoid whitespace and XML metacharacters so no
%% escaping or whitespace-stripping is exercised. Those are the parser's
%% documented lossy behaviors and are covered by example tests, not here.
-module(prop_aws_lib_xml_SUITE).

-compile(nowarn_export_all).
-compile(export_all).

-include_lib("proper/include/proper.hrl").
-include_lib("common_test/include/ct.hrl").

%% 200 iterations is ample: names, values, and attribute names are drawn from
%% small fixed pools (see name/0, value/0), so the input space this explores is
%% modest. The tree generator is also depth- and breadth-bounded (see
%% element_tree/1) to keep each rendered document small; without those bounds a
%% recursive ?SIZED generator produces documents large enough to make the run
%% pathologically slow.
-define(ITERATIONS, 200).
-define(MAX_DEPTH, 4).
-define(MAX_CHILDREN, 4).

all() ->
    [
        prop_roundtrips
    ].

%%--------------------------------------------------------------------
%% Generators
%%--------------------------------------------------------------------

%% An XML name drawn from a small FIXED pool. xmerl_scan interns every element
%% and attribute name as an atom, and atoms are never garbage collected, so
%% generating unbounded distinct names over many iterations exhausts the atom
%% table and crashes the node. Real AWS responses use a bounded name vocabulary,
%% so a fixed pool keeps the property realistic while bounding the atom count.
%% Structure (nesting, repetition, attribute presence, text) still varies freely.
name() ->
    elements([
        "item",
        "volumeSet",
        "attachmentSet",
        "Credentials",
        "AccessKeyId",
        "node",
        "child",
        "Foo",
        "Bar",
        "region",
        "id",
        "status",
        "value"
    ]).

%% A non-empty value drawn from a small FIXED pool. Unlike element and attribute
%% NAMES (which xmerl_scan interns as atoms -- see name/0), attribute and text
%% VALUES are NOT interned, so a pool is not required here for atom safety. It is
%% used for simplicity and to keep values realistic: they contain no whitespace
%% or XML metacharacters, so they need no escaping and are not touched by the
%% parser's whitespace stripping.
value() ->
    elements([
        "vol-1111",
        "gp3",
        "in-use",
        "attached",
        "AKIDEXAMPLE",
        "us-east-1",
        "8",
        "16",
        "x",
        "value-1"
    ]).

%% Attributes: 0 to a few {Name, Value} pairs with unique names (XML forbids
%% duplicate attribute names on one element). Bounded so elements stay small.
attributes() ->
    ?LET(
        Pairs,
        resize(?MAX_CHILDREN, list({name(), value()})),
        lists:ukeysort(1, Pairs)
    ).

%% An element tree, explicitly bounded in depth (?MAX_DEPTH) and breadth
%% (?MAX_CHILDREN). A leaf carries text; a node carries 1..?MAX_CHILDREN child
%% elements. At depth 0 only leaves are produced so generation terminates.
element_tree() ->
    element_tree(?MAX_DEPTH).

element_tree(0) ->
    {name(), attributes(), {text, value()}};
element_tree(Depth) ->
    frequency([
        {2, {name(), attributes(), {text, value()}}},
        {3,
            ?LET(
                N,
                choose(1, ?MAX_CHILDREN),
                ?LET(
                    Children,
                    vector(N, element_tree(Depth - 1)),
                    {name(), attributes(), {children, Children}}
                )
            )}
    ]).

%%--------------------------------------------------------------------
%% Rendering: element tree -> XML string
%%--------------------------------------------------------------------

render({Name, Attrs, Body}) ->
    AttrStr = render_attrs(Attrs),
    case Body of
        {text, Text} ->
            "<" ++ Name ++ AttrStr ++ ">" ++ Text ++ "</" ++ Name ++ ">";
        {children, Children} ->
            "<" ++ Name ++ AttrStr ++ ">" ++
                lists:concat([render(C) || C <- Children]) ++
                "</" ++ Name ++ ">"
    end.

render_attrs(Attrs) ->
    lists:concat([" " ++ K ++ "=\"" ++ V ++ "\"" || {K, V} <- Attrs]).

%%--------------------------------------------------------------------
%% Expected decoded shape for a generated tree
%%--------------------------------------------------------------------

expected({Name, Attrs, Body}) ->
    {Name, expected_value(Attrs, Body)}.

expected_value([], {text, Text}) ->
    Text;
expected_value(Attrs, {text, Text}) ->
    [{'@attributes', Attrs}, {'#text', Text}];
expected_value([], {children, Children}) ->
    [expected(C) || C <- Children];
expected_value(Attrs, {children, Children}) ->
    [{'@attributes', Attrs} | [expected(C) || C <- Children]].

%%--------------------------------------------------------------------
%% Property
%%--------------------------------------------------------------------

prop_roundtrips(_Config) ->
    rabbit_ct_proper_helpers:run_proper(
        fun() ->
            ?FORALL(
                Tree,
                element_tree(),
                begin
                    Xml = render(Tree),
                    aws_lib_xml:parse(Xml) =:= [expected(Tree)]
                end
            )
        end,
        [],
        ?ITERATIONS
    ).
