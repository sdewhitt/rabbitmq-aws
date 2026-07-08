%% ====================================================================
%% @author Gavin M. Roy <gavinmroy@gmail.com>
%% @copyright 2016, Gavin M. Roy
%% @doc XML parser for AWS application/xml responses.
%%
%% Decodes an xmerl parse tree into a nested proplist keyed by element name.
%%
%% Contract:
%%   * An element with only text content and no attributes decodes to
%%     `{Name, Text}' (a string).
%%   * An element with child elements decodes to `{Name, Children}' where
%%     Children is a proplist in document order. Repeated same-named siblings
%%     appear as repeated keys, so a caller that expects a list (e.g. a
%%     `volumeSet' of `item's) can walk them, but `proplists:get_value/2' on a
%%     repeated key returns only the first -- a caller wanting all repeats must
%%     iterate the proplist.
%%   * Element attributes, when present, are collected under a reserved
%%     `'@attributes'' key at the head of the element's value proplist. When an
%%     element has attributes AND only text, the text moves under a reserved
%%     `'#text'' key so it can sit beside the attributes. Elements WITHOUT
%%     attributes are unaffected -- the historical text-or-proplist shape is
%%     preserved, so existing consumers (DescribeVolumes, STS AssumeRole) are
%%     unchanged.
%%
%% Known limitations (scoped to the AWS response shapes this plugin consumes):
%%   * Mixed content (text interleaved with child elements) is not modelled
%%     faithfully -- text and element nodes may be reordered or dropped.
%%   * This is not a general-purpose XML decoder; it targets the EC2
%%     DescribeVolumes and STS AssumeRole response shapes plus simple error
%%     documents.
%% @end
%% ====================================================================
-module(aws_lib_xml).

-export([parse/1]).

-include_lib("xmerl/include/xmerl.hrl").

%% Reserved keys. XML element and attribute names cannot begin with '@' or '#',
%% so these cannot collide with a real name.
-define(ATTRIBUTES_KEY, '@attributes').
-define(TEXT_KEY, '#text').

-spec parse(Value :: string() | binary()) -> list().
parse(Value) when is_binary(Value) ->
    parse(binary_to_list(Value));
parse(Value) ->
    {Element, _} = xmerl_scan:string(Value),
    parse_node(Element).

parse_node(#xmlElement{name = Name, attributes = Attributes, content = Content}) ->
    Value = parse_content(Content, []),
    FlatValue = flatten_value(Value, Value),
    [{atom_to_list(Name), with_attributes(Attributes, FlatValue)}].

%% Attach parsed attributes to an element's value. With no attributes the value
%% is returned unchanged (preserving the historical text-or-proplist shape).
%% With attributes the value becomes a proplist headed by '@attributes'; a bare
%% text value is relocated under '#text' so it can coexist with the attributes.
with_attributes([], Value) ->
    Value;
with_attributes(Attributes, Value) ->
    [{?ATTRIBUTES_KEY, parse_attributes(Attributes)} | as_proplist(Value)].

parse_attributes(Attributes) ->
    [
        {atom_to_list(Name), Value}
     || #xmlAttribute{name = Name, value = Value} <- Attributes
    ].

%% Coerce an element value into proplist form so it can carry an '@attributes'
%% entry: an empty value stays empty, a text string moves under '#text', and a
%% proplist of child elements is used as-is.
as_proplist([]) ->
    [];
as_proplist([H | _] = Text) when is_integer(H) ->
    [{?TEXT_KEY, Text}];
as_proplist(Proplist) when is_list(Proplist) ->
    Proplist.

flatten_text([], Value) ->
    Value;
flatten_text([{K, V} | T], Accum) when is_list(V) ->
    flatten_text(T, lists:append([{K, V}], Accum));
flatten_text([H | T], Accum) when is_list(H) ->
    flatten_text(T, lists:append(T, Accum)).

flatten_value([L], _) when is_list(L) -> L;
flatten_value(L, _) when is_list(L) -> flatten_text(L, []).

parse_content([], Value) ->
    Value;
parse_content(#xmlElement{} = Element, Accum) ->
    lists:append(parse_node(Element), Accum);
parse_content(#xmlText{value = Value}, Accum) ->
    case string:strip(Value) of
        "" -> Accum;
        "\n" -> Accum;
        Stripped -> lists:append([Stripped], Accum)
    end;
parse_content([H | T], Accum) ->
    parse_content(T, parse_content(H, Accum)).
