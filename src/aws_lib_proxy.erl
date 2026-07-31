%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% HTTP proxy configuration and NO_PROXY matching for the aws_lib HTTP client.
%%
%% AWS API traffic is ALWAYS HTTPS. The correct proxy mechanism is HTTP CONNECT
%% tunneling: open a TCP connection to the proxy, send HTTP CONNECT to tunnel to
%% the origin, upgrade the tunnel to TLS with SNI against the ORIGIN, then issue
%% the actual HTTPS request through the tunnel. Plain-HTTP-through-proxy
%% (absolute-URI form) is not supported because AWS endpoints require TLS.
%%
%% Config resolution precedence:
%%   1. Explicit app env (aws.proxy.https_host / aws.proxy.https_port)
%%   2. HTTPS_PROXY environment variable (for HTTPS targets)
%%   3. NO_PROXY wins over both for matching hosts
%%
%% IMDS / ECS link-local addresses ALWAYS bypass the proxy unconditionally,
%% regardless of NO_PROXY configuration:
%%   - 169.254.169.254 (IMDS)
%%   - 169.254.170.2 (ECS container credentials)
%%   - Any 169.254.0.0/16 (link-local)
%%   - fd00:ec2::254 (IPv6 IMDS)
-module(aws_lib_proxy).

-include_lib("kernel/include/logger.hrl").

-export([
    resolve_proxy/2,
    parse_no_proxy/1,
    host_bypasses_proxy/2,
    redact_proxy_url/1
]).

-export_type([proxy_result/0, no_proxy_list/0]).

-type proxy_auth() :: {Username :: string(), Password :: string()} | undefined.
-type proxy_result() ::
    {proxy, Host :: string(), Port :: inet:port_number(), Auth :: proxy_auth()} | direct.
-type no_proxy_entry() ::
    wildcard
    | {domain_suffix, string()}
    | {exact_or_suffix, string()}
    | {cidr_v4, {tuple(), non_neg_integer()}}
    | {cidr_v6, {tuple(), non_neg_integer()}}
    | {host_port, string(), inet:port_number()}.
-type no_proxy_list() :: [no_proxy_entry()].

%%--------------------------------------------------------------------
%% Public API
%%--------------------------------------------------------------------

-spec resolve_proxy(Host :: string(), Port :: inet:port_number()) -> proxy_result().
%% @doc Determine whether to use a proxy for the given target Host:Port.
%% Returns `{proxy, ProxyHost, ProxyPort, ProxyAuth}` when a proxy should be
%% used, or `direct` when the target should be connected to directly.
%%
%% IMDS and link-local addresses are hard-coded to always bypass the proxy,
%% independent of NO_PROXY configuration.
%% @end
resolve_proxy(Host, Port) ->
    case is_link_local(Host) of
        true ->
            direct;
        false ->
            resolve_proxy_with_config(Host, Port)
    end.

-spec parse_no_proxy(string() | false) -> no_proxy_list().
%% @doc Parse a NO_PROXY string into a structured list for matching.
%% Entries are comma-separated, whitespace-trimmed.
%% @end
parse_no_proxy(false) ->
    [];
parse_no_proxy([]) ->
    [];
parse_no_proxy(NoProxyStr) when is_list(NoProxyStr) ->
    Entries = string:tokens(NoProxyStr, ","),
    lists:filtermap(fun parse_no_proxy_entry/1, Entries).

-spec host_bypasses_proxy(Host :: string(), NoProxy :: no_proxy_list()) -> boolean().
%% @doc Check if a host matches any entry in the parsed NO_PROXY list.
%% @end
host_bypasses_proxy(_Host, []) ->
    false;
host_bypasses_proxy(Host, NoProxy) ->
    host_bypasses_proxy(Host, undefined, NoProxy).

-spec redact_proxy_url(string()) -> string().
%% @doc Strip userinfo (credentials) from a proxy URL for safe logging.
%% Returns the URL with any user:password@ portion removed.
%% @end
redact_proxy_url(Url) when is_list(Url) ->
    case uri_string:parse(Url) of
        #{userinfo := _} = Parsed ->
            uri_string:recompose(maps:remove(userinfo, Parsed));
        #{} ->
            Url;
        _ ->
            Url
    end.

%%--------------------------------------------------------------------
%% Internal -- link-local bypass
%%--------------------------------------------------------------------

%% Hard-coded bypass for addresses that must never be proxied. Covers:
%%   - 169.254.0.0/16 (link-local, includes IMDS 169.254.169.254 and ECS 169.254.170.2)
%%   - 127.0.0.0/8 (loopback)
%%   - fd00:ec2::254 (IPv6 IMDS)
%%   - fe80::/10 (IPv6 link-local)
%%   - ::1 (IPv6 loopback)
%%   - IPv4-mapped/compatible/NAT64 IPv6 encodings of the above (via embedded_v4)
%%
%% This matches the infra ranges denied by aws_auth_validate_net:classify_ip/2.
is_link_local(Host) ->
    case inet:parse_address(Host) of
        {ok, {169, 254, _, _}} ->
            true;
        {ok, {127, _, _, _}} ->
            true;
        {ok, {16#fd00, 16#ec2, 0, 0, 0, 0, 0, 16#254}} ->
            true;
        {ok, {0, 0, 0, 0, 0, 0, 0, 1}} ->
            %% ::1 IPv6 loopback
            true;
        {ok, {W1, _, _, _, _, _, _, _}} when
            W1 >= 16#fe80, W1 =< 16#febf
        ->
            %% fe80::/10 IPv6 link-local
            true;
        {ok, {_, _, _, _, _, _, _, _} = V6} ->
            %% Check IPv4-mapped/compatible/NAT64 encodings
            case aws_auth_validate_net:embedded_v4(V6) of
                {ok, {169, 254, _, _}} -> true;
                {ok, {127, _, _, _}} -> true;
                _ -> false
            end;
        _ ->
            false
    end.

%%--------------------------------------------------------------------
%% Internal -- proxy config resolution
%%--------------------------------------------------------------------

resolve_proxy_with_config(Host, Port) ->
    case get_proxy_config() of
        {ok, ProxyHost, ProxyPort, ProxyAuth} ->
            NoProxy = get_no_proxy(),
            case host_bypasses_proxy(Host, Port, NoProxy) of
                true -> direct;
                false -> {proxy, ProxyHost, ProxyPort, ProxyAuth}
            end;
        none ->
            direct
    end.

%% Config precedence: app env beats env var.
get_proxy_config() ->
    case get_app_env_proxy() of
        {ok, _, _, _} = Result -> Result;
        none -> get_env_var_proxy()
    end.

get_app_env_proxy() ->
    case application:get_env(aws, proxy_https_host) of
        {ok, ProxyHost} when is_list(ProxyHost), ProxyHost =/= [] ->
            case application:get_env(aws, proxy_https_port) of
                {ok, ProxyPort} when is_integer(ProxyPort), ProxyPort > 0, ProxyPort =< 65535 ->
                    Username =
                        case application:get_env(aws, proxy_https_username) of
                            {ok, U} when is_list(U), U =/= [] -> U;
                            _ -> undefined
                        end,
                    Password =
                        case application:get_env(aws, proxy_https_password) of
                            {ok, P} when is_list(P), P =/= [] -> P;
                            _ -> undefined
                        end,
                    Auth =
                        case {Username, Password} of
                            {undefined, _} -> undefined;
                            {_, undefined} -> undefined;
                            {U2, P2} -> {U2, P2}
                        end,
                    {ok, ProxyHost, ProxyPort, Auth};
                _ ->
                    ?LOG_WARNING(
                        "aws.proxy.https_host is configured but "
                        "aws.proxy.https_port is missing or invalid -- "
                        "proxy configuration ignored"
                    ),
                    none
            end;
        _ ->
            none
    end.

get_env_var_proxy() ->
    %% Check HTTPS_PROXY then https_proxy (common convention: uppercase first)
    EnvValue =
        case os:getenv("HTTPS_PROXY") of
            false -> os:getenv("https_proxy");
            Val -> Val
        end,
    case EnvValue of
        false -> none;
        [] -> none;
        Url -> parse_proxy_url(Url)
    end.

get_no_proxy() ->
    %% App env takes precedence over env var for NO_PROXY as well
    case application:get_env(aws, proxy_no_proxy) of
        {ok, NoProxyStr} when is_list(NoProxyStr) ->
            parse_no_proxy(NoProxyStr);
        _ ->
            %% NO_PROXY env var (uppercase takes precedence)
            EnvValue =
                case os:getenv("NO_PROXY") of
                    false -> os:getenv("no_proxy");
                    Val -> Val
                end,
            parse_no_proxy(EnvValue)
    end.

%%--------------------------------------------------------------------
%% Internal -- proxy URL parsing
%%--------------------------------------------------------------------

parse_proxy_url(Url) ->
    case uri_string:parse(Url) of
        #{host := Host, port := Port} = Parsed when
            is_list(Host), Host =/= [], is_integer(Port), Port > 0, Port =< 65535
        ->
            Auth = extract_auth(Parsed),
            {ok, Host, Port, Auth};
        #{host := Host} = Parsed when is_list(Host), Host =/= [] ->
            %% No explicit port in the URL. Use port 80 for http:// scheme and
            %% 443 for https:// scheme, matching standard URI semantics. A proxy
            %% URL without a port and without a recognized scheme is rejected
            %% rather than guessing.
            DefaultPort = scheme_default_port(Parsed),
            case DefaultPort of
                undefined ->
                    none;
                P ->
                    Auth = extract_auth(Parsed),
                    {ok, Host, P, Auth}
            end;
        _ ->
            none
    end.

scheme_default_port(#{scheme := "http"}) -> 80;
scheme_default_port(#{scheme := "https"}) -> 443;
scheme_default_port(_) -> undefined.

extract_auth(#{userinfo := Userinfo}) when is_list(Userinfo), Userinfo =/= [] ->
    case string:split(Userinfo, ":") of
        [User, Pass] when User =/= [] -> {User, Pass};
        _ -> undefined
    end;
extract_auth(_) ->
    undefined.

%%--------------------------------------------------------------------
%% Internal -- NO_PROXY parsing
%%--------------------------------------------------------------------

parse_no_proxy_entry(RawEntry) ->
    Entry = string:trim(RawEntry),
    case Entry of
        [] ->
            false;
        "*" ->
            {true, wildcard};
        [$. | Domain] ->
            %% Leading dot: matches subdomains only (not the bare domain itself)
            {true, {domain_suffix, string:lowercase(Domain)}};
        _ ->
            parse_no_proxy_host_or_cidr(Entry)
    end.

parse_no_proxy_host_or_cidr(Entry) ->
    case string:split(Entry, "/") of
        [IpStr, PrefixStr] ->
            %% Might be a CIDR entry
            case parse_cidr(IpStr, PrefixStr) of
                {ok, Cidr} -> {true, Cidr};
                error -> parse_host_port_entry(Entry)
            end;
        _ ->
            parse_host_port_entry(Entry)
    end.

parse_cidr(IpStr, PrefixStr) ->
    case catch list_to_integer(string:trim(PrefixStr)) of
        Prefix when is_integer(Prefix) ->
            case inet:parse_address(string:trim(IpStr)) of
                {ok, {_, _, _, _} = Addr} when Prefix >= 0, Prefix =< 32 ->
                    {ok, {cidr_v4, {Addr, Prefix}}};
                {ok, {_, _, _, _, _, _, _, _} = Addr} when Prefix >= 0, Prefix =< 128 ->
                    {ok, {cidr_v6, {Addr, Prefix}}};
                _ ->
                    error
            end;
        _ ->
            error
    end.

parse_host_port_entry(Entry) ->
    %% If the entry is a valid IP address (v4 or v6), treat it as an exact match.
    %% This must come BEFORE the colon split to avoid misinterpreting IPv6
    %% addresses (e.g., "::1", "fe80::1") as host:port pairs.
    case inet:parse_address(Entry) of
        {ok, _IP} ->
            {true, {exact_or_suffix, string:lowercase(Entry)}};
        {error, _} ->
            parse_host_port_split(Entry)
    end.

parse_host_port_split(Entry) ->
    %% Check for host:port pattern. Split on the LAST colon.
    case string:find(Entry, ":", trailing) of
        nomatch ->
            %% No colon -- bare hostname, matches exactly and subdomains
            {true, {exact_or_suffix, string:lowercase(Entry)}};
        ":" ++ PortStr ->
            HostPart = string:slice(Entry, 0, length(Entry) - length(PortStr) - 1),
            case catch list_to_integer(PortStr) of
                Port when is_integer(Port), Port > 0, Port =< 65535 ->
                    {true, {host_port, string:lowercase(HostPart), Port}};
                _ ->
                    %% Not a valid port, treat as bare hostname
                    {true, {exact_or_suffix, string:lowercase(Entry)}}
            end
    end.

%%--------------------------------------------------------------------
%% Internal -- NO_PROXY matching
%%--------------------------------------------------------------------

%% Two-arity version for external callers (no port context)
host_bypasses_proxy(_Host, _Port, []) ->
    false;
host_bypasses_proxy(Host, Port, [Entry | Rest]) ->
    case matches_entry(Host, Port, Entry) of
        true -> true;
        false -> host_bypasses_proxy(Host, Port, Rest)
    end.

matches_entry(_Host, _Port, wildcard) ->
    true;
matches_entry(Host, _Port, {domain_suffix, Suffix}) ->
    %% Leading dot: matches *.suffix but NOT the bare suffix itself
    LHost = string:lowercase(Host),
    ends_with_dot_suffix(LHost, Suffix);
matches_entry(Host, _Port, {exact_or_suffix, Domain}) ->
    %% Bare domain: matches the exact domain AND subdomains, but NOT
    %% unrelated domains that happen to end with the same substring.
    %% "example.com" matches "example.com" and "foo.example.com"
    %% but NOT "notexample.com" or "example.com.evil.net"
    LHost = string:lowercase(Host),
    LHost =:= Domain orelse ends_with_dot_suffix(LHost, Domain);
matches_entry(Host, Port, {host_port, HostPattern, EntryPort}) ->
    %% Port-specific: only match if port matches
    case Port of
        EntryPort ->
            LHost = string:lowercase(Host),
            LHost =:= HostPattern orelse ends_with_dot_suffix(LHost, HostPattern);
        _ ->
            false
    end;
matches_entry(Host, _Port, {cidr_v4, Cidr}) ->
    match_cidr(Host, Cidr);
matches_entry(Host, _Port, {cidr_v6, Cidr}) ->
    match_cidr(Host, Cidr).

%% Check if LHost is a subdomain of Domain: LHost ends with "." ++ Domain
%% This prevents substring confusion: "notexample.com" does NOT match
%% "example.com" because we require the dot separator.
ends_with_dot_suffix(LHost, Domain) ->
    DotDomain = "." ++ Domain,
    lists:suffix(DotDomain, LHost).

match_cidr(Host, Cidr) ->
    case inet:parse_address(Host) of
        {ok, IP} -> aws_auth_validate_net:in_cidr(IP, Cidr);
        {error, _} -> false
    end.
