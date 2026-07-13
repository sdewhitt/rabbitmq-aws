%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% Thin wrappers over the OTP stdlib uri_string module -- the plugin's single
%% URI parser. parse/1 returns an OPAQUE uri() (backed by uri_string:uri_map/1);
%% callers never touch the underlying representation, they read components
%% through the accessors (host/1, port/1, path/1, query/1, target/1). This keeps
%% every URI concern -- RFC 3986 parsing, scheme port defaulting, the never-crash
%% guard, and request-target assembly -- in one place, built on OTP rather than
%% hand-rolled string splitting.
-module(aws_lib_uri).

-export([
    parse/1,
    host/1,
    port/1,
    transport/1,
    path/1,
    query/1,
    target/1,
    compose_query/1
]).

-export_type([uri/0]).

%% Opaque URI handle. Backed by uri_string:uri_map/1, but that is an
%% implementation detail: outside this module a uri() is only ever produced by
%% parse/1 and read through the accessors below.
-opaque uri() :: uri_string:uri_map().

-spec parse(string()) -> {ok, uri()} | {error, {malformed_uri, string()}}.
%% @doc Parse a URI string into an opaque uri(). Built on the RFC 3986 compliant
%% uri_string:parse/1. A scheme-less, relative, or otherwise malformed input (no
%% host component, or a uri_string parse error) returns
%% {error, {malformed_uri, _}} rather than crashing, so callers handle a bad URI
%% explicitly instead of a later accessor failing with a function_clause.
%% @end
parse(Value) ->
    case uri_string:parse(Value) of
        #{host := _} = UriMap ->
            {ok, UriMap};
        %% No host component (scheme-less or relative input), or uri_string
        %% reported a parse error. Either way the input is not a usable
        %% absolute URI, so report it rather than hand back a partial map.
        _ ->
            {error, {malformed_uri, Value}}
    end.

-spec host(uri()) -> string().
%% @doc The host component as a list string.
%% @end
host(#{host := Host}) ->
    unicode:characters_to_list(Host).

-spec port(uri()) -> inet:port_number().
%% @doc The port, defaulted by scheme (http -> 80, https -> 443) when the URI
%% does not state one explicitly. uri_string only reports a port when present.
%% @end
port(#{port := Port}) when is_integer(Port) ->
    Port;
port(#{scheme := Scheme}) ->
    default_port(unicode:characters_to_list(Scheme)).

default_port("https") -> 443;
default_port("http") -> 80;
%% Fall back to HTTPS for any other scheme, matching the plugin's HTTPS default.
default_port(_) -> 443.

-spec transport(uri()) -> tls | tcp.
%% @doc The Gun transport implied by the scheme: `https' (and any unknown
%% scheme, matching the plugin's HTTPS default) uses TLS, `http' uses plain TCP.
%% Scheme-driven rather than port-driven, so an https endpoint on a non-443 port
%% still uses TLS and an http endpoint on any port stays plaintext.
%% @end
transport(#{scheme := Scheme}) ->
    transport_for_scheme(string:lowercase(unicode:characters_to_list(Scheme)));
transport(_) ->
    tls.

transport_for_scheme("http") -> tcp;
transport_for_scheme(_) -> tls.

-spec path(uri()) -> string().
%% @doc The path component as a list string, with an empty path normalized to
%% "/" so it is always a usable request target on its own. The query is NOT
%% included; use target/1 for the path-with-query request line.
%% @end
path(UriMap) ->
    case unicode:characters_to_list(maps:get(path, UriMap, "")) of
        "" -> "/";
        Path -> Path
    end.

-spec query(uri()) -> [{string(), string()}].
%% @doc The query component dissected into a key/value proplist (empty list when
%% there is no query). This is the shape the request signer canonicalizes.
%% @end
query(UriMap) ->
    uri_string:dissect_query(maps:get(query, UriMap, "")).

-spec target(uri()) -> string().
%% @doc The request target: path with the raw query reattached (path?query), or
%% just the path when there is no query. Used directly as the Gun request line.
%% The RAW query from uri_string is used (not the dissected/recomposed form) so
%% the target is byte-for-byte what was parsed, matching what the signer signs.
%% @end
target(UriMap) ->
    Path = path(UriMap),
    case unicode:characters_to_list(maps:get(query, UriMap, "")) of
        "" -> Path;
        Query -> Path ++ "?" ++ Query
    end.

-spec compose_query([{term(), term()}]) -> string().
%% @doc Compose a key/value proplist into a query string, coercing non-string
%% keys and values to strings first. Wraps uri_string:compose_query/1.
%% @end
compose_query(Args) when is_list(Args) ->
    Normalized = [{to_list(K), to_list(V)} || {K, V} <- Args],
    uri_string:compose_query(Normalized).

-spec to_list(integer() | list() | binary() | atom() | map()) -> list().
to_list(Val) when is_list(Val) -> Val;
to_list(Val) when is_map(Val) -> maps:to_list(Val);
to_list(Val) when is_atom(Val) -> atom_to_list(Val);
to_list(Val) when is_binary(Val) -> binary_to_list(Val);
to_list(Val) when is_integer(Val) -> integer_to_list(Val).
