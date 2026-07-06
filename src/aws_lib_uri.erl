%% ====================================================================
%% @author Gavin M. Roy <gavinmroy@gmail.com>
%% @copyright 2016
%% @doc urilib is a RFC-3986 URI Library for Erlang
%%      https://github.com/gmr/urilib
%% @end
%% ====================================================================
-module(aws_lib_uri).

-export([
    build/1,
    build_query_string/1,
    parse/1,
    parse_userinfo/1,
    parse_userinfo_result/1
]).

%% Export all for unit tests
-ifdef(TEST).
-compile(export_all).
-endif.

-include("aws_lib.hrl").

-spec build(#uri{}) -> string().
%% @doc Build a URI string
%% @end
build(URI) ->
    {UserInfo, Host, Port} = URI#uri.authority,
    UriMap = #{
        scheme => to_list(URI#uri.scheme),
        host => Host
    },
    UriMap1 = maybe_put_userinfo(UserInfo, UriMap),
    UriMap2 = maybe_put_port(Port, UriMap1),
    UriMap3 = put_path(URI#uri.path, UriMap2),
    UriMap4 = maybe_put_query(URI#uri.query, UriMap3),
    UriMap5 = maybe_put_fragment(URI#uri.fragment, UriMap4),
    uri_string:recompose(UriMap5).

maybe_put_userinfo(undefined, Map) -> Map;
maybe_put_userinfo({User, undefined}, Map) -> Map#{userinfo => User};
maybe_put_userinfo({User, Password}, Map) -> Map#{userinfo => User ++ ":" ++ Password}.

maybe_put_port(undefined, Map) -> Map;
maybe_put_port(Port, Map) -> Map#{port => Port}.

%% The path is always set (an absent path becomes ""), so this is an
%% unconditional put rather than a maybe_put.
put_path(undefined, Map) -> Map#{path => ""};
put_path(Path, Map) -> Map#{path => prefix_path(Path)}.

%% uri_string:recompose/1 needs an absolute path; ensure a leading "/".
prefix_path([$/ | _] = Path) -> Path;
prefix_path(Path) -> "/" ++ Path.

maybe_put_query(undefined, Map) -> Map;
maybe_put_query("", Map) -> Map;
maybe_put_query(Query, Map) -> Map#{query => build_query_string(Query)}.

maybe_put_fragment(undefined, Map) -> Map;
maybe_put_fragment(Fragment, Map) -> Map#{fragment => Fragment}.

-spec parse(string()) -> #uri{} | {error, {malformed_uri, string()}}.
%% @doc Parse a URI string into a #uri{} record. This is the single URI parser
%% for the plugin -- every other component that needs URI components (the AWS
%% request signer, the EC2 instance-metadata client, and so on) goes through
%% here rather than splitting strings by hand. It is built on the RFC 3986
%% compliant uri_string:parse/1, so a scheme-less, relative, or otherwise
%% malformed input returns {error, {malformed_uri, _}} instead of crashing.
%% @end
parse(Value) ->
    case uri_string:parse(Value) of
        #{host := Host} = UriMap ->
            Scheme = maps:get(scheme, UriMap, "https"),
            DefaultPort =
                case Scheme of
                    "http" -> 80;
                    "https" -> 443;
                    _ -> undefined
                end,
            Port = maps:get(port, UriMap, DefaultPort),
            UserInfo = parse_userinfo(maps:get(userinfo, UriMap, undefined)),
            Path = maps:get(path, UriMap),
            Query = maps:get(query, UriMap, ""),
            #uri{
                scheme = Scheme,
                authority = {parse_userinfo(UserInfo), Host, Port},
                path = Path,
                query = uri_string:dissect_query(Query),
                fragment = maps:get(fragment, UriMap, undefined)
            };
        %% No host component (scheme-less or relative input), or uri_string
        %% reported a parse error. Either way the input is not a usable
        %% absolute URI, so report it rather than crash.
        _ ->
            {error, {malformed_uri, Value}}
    end.

-spec parse_userinfo(string() | undefined) ->
    {username() | undefined, password() | undefined} | undefined.
parse_userinfo(undefined) -> undefined;
parse_userinfo([]) -> undefined;
parse_userinfo({User, undefined}) -> {User, undefined};
parse_userinfo({User, Password}) -> {User, Password};
parse_userinfo(Value) -> parse_userinfo_result(string:tokens(Value, ":")).

-spec parse_userinfo_result(list()) ->
    {username() | undefined, password() | undefined} | undefined.
parse_userinfo_result([User, Password]) -> {User, Password};
parse_userinfo_result([User]) -> {User, undefined};
parse_userinfo_result({User, undefined}) -> {User, undefined};
parse_userinfo_result([]) -> undefined;
parse_userinfo_result(User) -> {User, undefined}.

%% @spec build_query(proplist()) -> string()
%% @doc Build the query parameters string from a proplist
%% @end
%%

-spec build_query_string([{any(), any()}]) -> string().

build_query_string(Args) when is_list(Args) ->
    Normalized = [{to_list(K), to_list(V)} || {K, V} <- Args],
    uri_string:compose_query(Normalized).

-spec to_list(Val :: integer() | list() | binary() | atom() | map()) -> list().
to_list(Val) when is_list(Val) -> Val;
to_list(Val) when is_map(Val) -> maps:to_list(Val);
to_list(Val) when is_atom(Val) -> atom_to_list(Val);
to_list(Val) when is_binary(Val) -> binary_to_list(Val);
to_list(Val) when is_integer(Val) -> integer_to_list(Val).
