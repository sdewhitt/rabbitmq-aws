%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% Unit tests for aws_lib_proxy -- NO_PROXY matching, config precedence,
%% IMDS hard bypass, URL parsing, and credential redaction.
-module(aws_lib_proxy_tests).

-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% NO_PROXY matching: leading dot semantics
%%--------------------------------------------------------------------

leading_dot_matches_subdomain_test() ->
    NoProxy = aws_lib_proxy:parse_no_proxy(".foo.com"),
    ?assert(aws_lib_proxy:host_bypasses_proxy("bar.foo.com", NoProxy)),
    ?assert(aws_lib_proxy:host_bypasses_proxy("deep.bar.foo.com", NoProxy)).

leading_dot_does_not_match_bare_domain_test() ->
    NoProxy = aws_lib_proxy:parse_no_proxy(".foo.com"),
    ?assertNot(aws_lib_proxy:host_bypasses_proxy("foo.com", NoProxy)).

leading_dot_does_not_match_unrelated_test() ->
    NoProxy = aws_lib_proxy:parse_no_proxy(".foo.com"),
    ?assertNot(aws_lib_proxy:host_bypasses_proxy("notfoo.com", NoProxy)).

%%--------------------------------------------------------------------
%% NO_PROXY matching: bare domain semantics
%%--------------------------------------------------------------------

bare_domain_matches_exact_test() ->
    NoProxy = aws_lib_proxy:parse_no_proxy("foo.com"),
    ?assert(aws_lib_proxy:host_bypasses_proxy("foo.com", NoProxy)).

bare_domain_matches_subdomain_test() ->
    NoProxy = aws_lib_proxy:parse_no_proxy("foo.com"),
    ?assert(aws_lib_proxy:host_bypasses_proxy("bar.foo.com", NoProxy)),
    ?assert(aws_lib_proxy:host_bypasses_proxy("deep.bar.foo.com", NoProxy)).

bare_domain_does_not_match_prefix_test() ->
    %% "notfoo.com" must NOT match NO_PROXY=foo.com (substring confusion)
    NoProxy = aws_lib_proxy:parse_no_proxy("foo.com"),
    ?assertNot(aws_lib_proxy:host_bypasses_proxy("notfoo.com", NoProxy)).

bare_domain_does_not_match_suffix_attack_test() ->
    %% "foo.com.evil.net" must NOT match NO_PROXY=foo.com
    NoProxy = aws_lib_proxy:parse_no_proxy("foo.com"),
    ?assertNot(aws_lib_proxy:host_bypasses_proxy("foo.com.evil.net", NoProxy)).

example_com_not_match_notexample_test() ->
    NoProxy = aws_lib_proxy:parse_no_proxy("example.com"),
    ?assertNot(aws_lib_proxy:host_bypasses_proxy("notexample.com", NoProxy)).

%%--------------------------------------------------------------------
%% NO_PROXY matching: wildcard
%%--------------------------------------------------------------------

wildcard_matches_everything_test() ->
    NoProxy = aws_lib_proxy:parse_no_proxy("*"),
    ?assert(aws_lib_proxy:host_bypasses_proxy("anything.example.com", NoProxy)),
    ?assert(aws_lib_proxy:host_bypasses_proxy("10.0.0.1", NoProxy)).

%%--------------------------------------------------------------------
%% NO_PROXY matching: CIDR
%%--------------------------------------------------------------------

cidr_v4_matches_test() ->
    NoProxy = aws_lib_proxy:parse_no_proxy("10.0.0.0/8"),
    ?assert(aws_lib_proxy:host_bypasses_proxy("10.1.2.3", NoProxy)),
    ?assert(aws_lib_proxy:host_bypasses_proxy("10.255.255.255", NoProxy)).

cidr_v4_does_not_match_outside_test() ->
    NoProxy = aws_lib_proxy:parse_no_proxy("10.0.0.0/8"),
    ?assertNot(aws_lib_proxy:host_bypasses_proxy("11.0.0.1", NoProxy)),
    ?assertNot(aws_lib_proxy:host_bypasses_proxy("192.168.1.1", NoProxy)).

cidr_v6_matches_test() ->
    NoProxy = aws_lib_proxy:parse_no_proxy("fd00::/8"),
    ?assert(aws_lib_proxy:host_bypasses_proxy("fd00::1", NoProxy)).

cidr_hostname_does_not_match_test() ->
    %% A hostname (not an IP) never matches a CIDR entry
    NoProxy = aws_lib_proxy:parse_no_proxy("10.0.0.0/8"),
    ?assertNot(aws_lib_proxy:host_bypasses_proxy("ten-network.internal", NoProxy)).

%%--------------------------------------------------------------------
%% NO_PROXY matching: port-specific
%%--------------------------------------------------------------------

port_specific_via_resolve_test() ->
    %% Port-specific NO_PROXY entries are tested through resolve_proxy/2 rather
    %% than host_bypasses_proxy/2, because the 2-arg public API passes
    %% `undefined` for port so port-specific entries would never match.
    %% Set up app env proxy config and NO_PROXY with port-specific entry
    application:set_env(aws, proxy_https_host, "proxy.internal"),
    application:set_env(aws, proxy_https_port, 3128),
    application:set_env(aws, proxy_no_proxy, "myhost:443"),
    try
        %% myhost on port 443 bypasses
        ?assertEqual(direct, aws_lib_proxy:resolve_proxy("myhost", 443)),
        %% myhost on port 8080 does NOT bypass
        ?assertMatch({proxy, _, _, _}, aws_lib_proxy:resolve_proxy("myhost", 8080))
    after
        application:unset_env(aws, proxy_https_host),
        application:unset_env(aws, proxy_https_port),
        application:unset_env(aws, proxy_no_proxy)
    end.

%%--------------------------------------------------------------------
%% NO_PROXY matching: case insensitivity
%%--------------------------------------------------------------------

case_insensitive_matching_test() ->
    NoProxy = aws_lib_proxy:parse_no_proxy("Example.COM"),
    ?assert(aws_lib_proxy:host_bypasses_proxy("example.com", NoProxy)),
    ?assert(aws_lib_proxy:host_bypasses_proxy("EXAMPLE.COM", NoProxy)),
    ?assert(aws_lib_proxy:host_bypasses_proxy("sub.example.com", NoProxy)).

%%--------------------------------------------------------------------
%% NO_PROXY matching: multiple entries
%%--------------------------------------------------------------------

multiple_entries_test() ->
    NoProxy = aws_lib_proxy:parse_no_proxy("foo.com, .bar.org, 10.0.0.0/8"),
    ?assert(aws_lib_proxy:host_bypasses_proxy("foo.com", NoProxy)),
    ?assert(aws_lib_proxy:host_bypasses_proxy("sub.bar.org", NoProxy)),
    ?assert(aws_lib_proxy:host_bypasses_proxy("10.5.5.5", NoProxy)),
    ?assertNot(aws_lib_proxy:host_bypasses_proxy("other.com", NoProxy)).

whitespace_trimmed_test() ->
    NoProxy = aws_lib_proxy:parse_no_proxy("  foo.com  ,  bar.com  "),
    ?assert(aws_lib_proxy:host_bypasses_proxy("foo.com", NoProxy)),
    ?assert(aws_lib_proxy:host_bypasses_proxy("bar.com", NoProxy)).

empty_entries_ignored_test() ->
    NoProxy = aws_lib_proxy:parse_no_proxy("foo.com,,bar.com,"),
    ?assertEqual(2, length(NoProxy)).

%%--------------------------------------------------------------------
%% IMDS hard bypass
%%--------------------------------------------------------------------

imds_v4_always_direct_test() ->
    %% 169.254.169.254 (IMDS) always bypasses regardless of proxy config
    application:set_env(aws, proxy_https_host, "proxy.internal"),
    application:set_env(aws, proxy_https_port, 3128),
    try
        ?assertEqual(direct, aws_lib_proxy:resolve_proxy("169.254.169.254", 80))
    after
        application:unset_env(aws, proxy_https_host),
        application:unset_env(aws, proxy_https_port)
    end.

ecs_link_local_always_direct_test() ->
    %% 169.254.170.2 (ECS container credentials) always bypasses
    application:set_env(aws, proxy_https_host, "proxy.internal"),
    application:set_env(aws, proxy_https_port, 3128),
    try
        ?assertEqual(direct, aws_lib_proxy:resolve_proxy("169.254.170.2", 80))
    after
        application:unset_env(aws, proxy_https_host),
        application:unset_env(aws, proxy_https_port)
    end.

link_local_range_always_direct_test() ->
    %% Any 169.254.x.y always bypasses
    application:set_env(aws, proxy_https_host, "proxy.internal"),
    application:set_env(aws, proxy_https_port, 3128),
    try
        ?assertEqual(direct, aws_lib_proxy:resolve_proxy("169.254.1.1", 80)),
        ?assertEqual(direct, aws_lib_proxy:resolve_proxy("169.254.255.255", 80))
    after
        application:unset_env(aws, proxy_https_host),
        application:unset_env(aws, proxy_https_port)
    end.

ipv6_imds_always_direct_test() ->
    %% fd00:ec2::254 always bypasses
    application:set_env(aws, proxy_https_host, "proxy.internal"),
    application:set_env(aws, proxy_https_port, 3128),
    try
        ?assertEqual(direct, aws_lib_proxy:resolve_proxy("fd00:ec2::254", 80))
    after
        application:unset_env(aws, proxy_https_host),
        application:unset_env(aws, proxy_https_port)
    end.

%%--------------------------------------------------------------------
%% Config precedence
%%--------------------------------------------------------------------

app_env_beats_env_var_test() ->
    application:set_env(aws, proxy_https_host, "app-proxy.internal"),
    application:set_env(aws, proxy_https_port, 8080),
    os:putenv("HTTPS_PROXY", "http://env-proxy.internal:3128"),
    try
        Result = aws_lib_proxy:resolve_proxy("api.amazonaws.com", 443),
        ?assertMatch({proxy, "app-proxy.internal", 8080, _}, Result)
    after
        application:unset_env(aws, proxy_https_host),
        application:unset_env(aws, proxy_https_port),
        os:unsetenv("HTTPS_PROXY")
    end.

env_var_used_when_no_app_env_test() ->
    application:unset_env(aws, proxy_https_host),
    application:unset_env(aws, proxy_https_port),
    os:putenv("HTTPS_PROXY", "http://env-proxy.internal:3128"),
    try
        Result = aws_lib_proxy:resolve_proxy("api.amazonaws.com", 443),
        ?assertMatch({proxy, "env-proxy.internal", 3128, _}, Result)
    after
        os:unsetenv("HTTPS_PROXY")
    end.

lowercase_env_var_fallback_test() ->
    application:unset_env(aws, proxy_https_host),
    os:unsetenv("HTTPS_PROXY"),
    os:putenv("https_proxy", "http://lower-proxy.internal:9090"),
    try
        Result = aws_lib_proxy:resolve_proxy("api.amazonaws.com", 443),
        ?assertMatch({proxy, "lower-proxy.internal", 9090, _}, Result)
    after
        os:unsetenv("https_proxy")
    end.

no_proxy_configured_returns_direct_test() ->
    application:unset_env(aws, proxy_https_host),
    application:unset_env(aws, proxy_https_port),
    os:unsetenv("HTTPS_PROXY"),
    os:unsetenv("https_proxy"),
    ?assertEqual(direct, aws_lib_proxy:resolve_proxy("api.amazonaws.com", 443)).

%%--------------------------------------------------------------------
%% URL parsing -- extract host/port/auth from proxy URL
%%--------------------------------------------------------------------

url_with_port_test() ->
    os:putenv("HTTPS_PROXY", "http://myproxy:8888"),
    application:unset_env(aws, proxy_https_host),
    try
        ?assertMatch(
            {proxy, "myproxy", 8888, undefined},
            aws_lib_proxy:resolve_proxy("target.com", 443)
        )
    after
        os:unsetenv("HTTPS_PROXY")
    end.

url_with_auth_test() ->
    os:putenv("HTTPS_PROXY", "http://user:pass@myproxy:3128"),
    application:unset_env(aws, proxy_https_host),
    try
        ?assertMatch(
            {proxy, "myproxy", 3128, {"user", "pass"}},
            aws_lib_proxy:resolve_proxy("target.com", 443)
        )
    after
        os:unsetenv("HTTPS_PROXY")
    end.

url_without_port_uses_scheme_default_test() ->
    %% http:// scheme without port uses standard port 80
    os:putenv("HTTPS_PROXY", "http://myproxy"),
    application:unset_env(aws, proxy_https_host),
    try
        ?assertMatch(
            {proxy, "myproxy", 80, undefined},
            aws_lib_proxy:resolve_proxy("target.com", 443)
        )
    after
        os:unsetenv("HTTPS_PROXY")
    end.

url_without_port_https_scheme_test() ->
    %% https:// scheme without port uses standard port 443
    os:putenv("HTTPS_PROXY", "https://secureproxy"),
    application:unset_env(aws, proxy_https_host),
    try
        ?assertMatch(
            {proxy, "secureproxy", 443, undefined},
            aws_lib_proxy:resolve_proxy("target.com", 443)
        )
    after
        os:unsetenv("HTTPS_PROXY")
    end.

url_without_port_unknown_scheme_rejected_test() ->
    %% Unknown scheme without port is rejected rather than guessing
    os:putenv("HTTPS_PROXY", "socks5://myproxy"),
    application:unset_env(aws, proxy_https_host),
    try
        ?assertEqual(direct, aws_lib_proxy:resolve_proxy("target.com", 443))
    after
        os:unsetenv("HTTPS_PROXY")
    end.

app_env_auth_test() ->
    application:set_env(aws, proxy_https_host, "proxy.internal"),
    application:set_env(aws, proxy_https_port, 3128),
    application:set_env(aws, proxy_https_username, "admin"),
    application:set_env(aws, proxy_https_password, "secret"),
    try
        ?assertMatch(
            {proxy, "proxy.internal", 3128, {"admin", "secret"}},
            aws_lib_proxy:resolve_proxy("target.com", 443)
        )
    after
        application:unset_env(aws, proxy_https_host),
        application:unset_env(aws, proxy_https_port),
        application:unset_env(aws, proxy_https_username),
        application:unset_env(aws, proxy_https_password)
    end.

%%--------------------------------------------------------------------
%% Redaction
%%--------------------------------------------------------------------

redact_strips_credentials_test() ->
    ?assertEqual(
        "http://myproxy:3128",
        aws_lib_proxy:redact_proxy_url("http://user:pass@myproxy:3128")
    ).

redact_preserves_url_without_auth_test() ->
    ?assertEqual(
        "http://myproxy:3128",
        aws_lib_proxy:redact_proxy_url("http://myproxy:3128")
    ).

%%--------------------------------------------------------------------
%% NO_PROXY app env takes precedence over env var
%%--------------------------------------------------------------------

no_proxy_app_env_beats_env_var_test() ->
    application:set_env(aws, proxy_https_host, "proxy.internal"),
    application:set_env(aws, proxy_https_port, 3128),
    application:set_env(aws, proxy_no_proxy, "internal.example.com"),
    os:putenv("NO_PROXY", "something-else.com"),
    try
        %% internal.example.com bypasses (app env NO_PROXY)
        ?assertEqual(direct, aws_lib_proxy:resolve_proxy("internal.example.com", 443)),
        %% something-else.com does NOT bypass (env var ignored)
        ?assertMatch(
            {proxy, _, _, _},
            aws_lib_proxy:resolve_proxy("something-else.com", 443)
        )
    after
        application:unset_env(aws, proxy_https_host),
        application:unset_env(aws, proxy_https_port),
        application:unset_env(aws, proxy_no_proxy),
        os:unsetenv("NO_PROXY")
    end.

%%--------------------------------------------------------------------
%% parse_no_proxy edge cases
%%--------------------------------------------------------------------

parse_no_proxy_false_test() ->
    ?assertEqual([], aws_lib_proxy:parse_no_proxy(false)).

parse_no_proxy_empty_test() ->
    ?assertEqual([], aws_lib_proxy:parse_no_proxy("")).

%%--------------------------------------------------------------------
%% resolve_proxy returns direct when no proxy configured
%%--------------------------------------------------------------------

resolve_proxy_no_config_test() ->
    application:unset_env(aws, proxy_https_host),
    application:unset_env(aws, proxy_https_port),
    os:unsetenv("HTTPS_PROXY"),
    os:unsetenv("https_proxy"),
    ?assertEqual(direct, aws_lib_proxy:resolve_proxy("s3.amazonaws.com", 443)).
