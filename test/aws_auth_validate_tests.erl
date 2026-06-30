%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% Unit tests for the auth-validation subsystem's pure modules: semaphore,
%% registry, the LDAP backend's input parsing, and the LDAP query DSL parser
%% (incl. upstream parity). The live bind/connect/TLS path lives in
%% aws_auth_validate_ldap_SUITE; the HTTP pipeline lives in
%% aws_auth_validate_mgmt_SUITE.
-module(aws_auth_validate_tests).

-include_lib("eunit/include/eunit.hrl").
-include("aws_lib.hrl").

%%--------------------------------------------------------------------
%% Semaphore
%%--------------------------------------------------------------------

semaphore_test_() ->
    {foreach,
        fun() ->
            {ok, Pid} = aws_auth_validate_semaphore:start_link(#{max => 2}),
            Pid
        end,
        fun stop/1, [
            {"acquire/release sequence", fun() ->
                {ok, R1} = aws_auth_validate_semaphore:acquire(),
                {ok, R2} = aws_auth_validate_semaphore:acquire(),
                ?assertEqual({error, full}, aws_auth_validate_semaphore:acquire()),
                ok = aws_auth_validate_semaphore:release(R1),
                {ok, R3} = aws_auth_validate_semaphore:acquire(),
                ok = aws_auth_validate_semaphore:release(R2),
                ok = aws_auth_validate_semaphore:release(R3),
                ?assertEqual(0, aws_auth_validate_semaphore:current())
            end}
        ]}.

semaphore_crashed_holder_test_() ->
    {setup,
        fun() ->
            {ok, Pid} = aws_auth_validate_semaphore:start_link(#{max => 1}),
            Pid
        end,
        fun stop/1, fun(_) ->
            Self = self(),
            Worker = spawn(fun() ->
                {ok, _Ref} = aws_auth_validate_semaphore:acquire(),
                Self ! acquired,
                receive
                    die -> exit(boom)
                end
            end),
            receive
                acquired -> ok
            after 1_000 -> ?assert(false)
            end,
            ?assertEqual({error, full}, aws_auth_validate_semaphore:acquire()),
            Worker ! die,
            wait_until_zero(50),
            [?_assertMatch({ok, _}, aws_auth_validate_semaphore:acquire())]
        end}.

%%--------------------------------------------------------------------
%% Registry
%%--------------------------------------------------------------------

registry_unknown_method_test() ->
    ?assertEqual(
        {error, unknown_method},
        aws_auth_validate_registry:dispatch(<<"nope">>, #{})
    ).

registry_method_disabled_test_() ->
    {setup,
        fun() ->
            application:set_env(
                aws,
                auth_validation_enabled_methods,
                [{<<"ldap">>, false}]
            )
        end,
        fun(_) ->
            application:unset_env(aws, auth_validation_enabled_methods)
        end,
        [
            ?_assertEqual(
                {error, method_disabled},
                aws_auth_validate_registry:dispatch(<<"ldap">>, #{})
            )
        ]}.

registry_field_filter_override_test_() ->
    {setup,
        fun() ->
            application:set_env(
                aws,
                {auth_validation_allowed_fields_override, <<"ldap">>},
                [<<"servers">>, <<"port">>, <<"unknown">>]
            )
        end,
        fun(_) ->
            application:unset_env(
                aws,
                {auth_validation_allowed_fields_override, <<"ldap">>}
            )
        end,
        [
            fun() ->
                Effective = aws_auth_validate_registry:effective_allowed_fields(
                    aws_auth_validate_ldap, <<"ldap">>
                ),
                ?assert(lists:member(<<"servers">>, Effective)),
                ?assert(lists:member(<<"port">>, Effective)),
                ?assertNot(lists:member(<<"unknown">>, Effective))
            end
        ]}.

%%--------------------------------------------------------------------
%% Mgmt status mapping
%%--------------------------------------------------------------------

status_for_category_known_test() ->
    ?assertEqual(400, aws_auth_validate_mgmt:status_for_category(input_invalid)),
    ?assertEqual(400, aws_auth_validate_mgmt:status_for_category(connection_failed)),
    ?assertEqual(400, aws_auth_validate_mgmt:status_for_category(tls_failed)),
    ?assertEqual(400, aws_auth_validate_mgmt:status_for_category(query_invalid)),
    ?assertEqual(422, aws_auth_validate_mgmt:status_for_category(auth_failed)),
    ?assertEqual(422, aws_auth_validate_mgmt:status_for_category(config_conflict)),
    ?assertEqual(422, aws_auth_validate_mgmt:status_for_category(authz_unverified)).

%% A category outside the documented set maps to 500 rather than crashing.
status_for_category_unknown_test() ->
    ?assertEqual(500, aws_auth_validate_mgmt:status_for_category(some_future_category)).

%%--------------------------------------------------------------------
%% Mgmt body-size bound
%%--------------------------------------------------------------------

%% max_body_size/0 honours an in-range configured value and falls back to the
%% effective default for anything outside 1..1_048_576 (the 1 MB ceiling). The
%% effective default (65_536) is asserted indirectly via the out-of-range cases.
max_body_size_bound_test_() ->
    {foreach, fun() -> application:unset_env(aws, auth_validation_max_body_size) end,
        fun(_) -> application:unset_env(aws, auth_validation_max_body_size) end, [
            fun() ->
                application:set_env(aws, auth_validation_max_body_size, 4096),
                ?assertEqual(4096, aws_auth_validate_mgmt:max_body_size())
            end,
            %% The ceiling itself is accepted.
            fun() ->
                application:set_env(aws, auth_validation_max_body_size, 1_048_576),
                ?assertEqual(1_048_576, aws_auth_validate_mgmt:max_body_size())
            end,
            %% One byte over the ceiling falls back to the default.
            fun() ->
                application:set_env(aws, auth_validation_max_body_size, 1_048_577),
                ?assertEqual(65_536, aws_auth_validate_mgmt:max_body_size())
            end,
            %% The old 10 MB ceiling is now out of range and falls back.
            fun() ->
                application:set_env(aws, auth_validation_max_body_size, 10_000_000),
                ?assertEqual(65_536, aws_auth_validate_mgmt:max_body_size())
            end,
            %% Non-positive and non-integer values fall back too.
            fun() ->
                application:set_env(aws, auth_validation_max_body_size, 0),
                ?assertEqual(65_536, aws_auth_validate_mgmt:max_body_size())
            end,
            fun() ->
                application:set_env(aws, auth_validation_max_body_size, not_an_integer),
                ?assertEqual(65_536, aws_auth_validate_mgmt:max_body_size())
            end,
            %% Unset reads as the default.
            fun() ->
                ?assertEqual(65_536, aws_auth_validate_mgmt:max_body_size())
            end
        ]}.

%%--------------------------------------------------------------------
%% LDAP backend (input parsing only - the real bind path needs slapd)
%%--------------------------------------------------------------------

ldap_method_name_test() ->
    ?assertEqual(<<"ldap">>, aws_auth_validate_ldap:method_name()).

ldap_allowed_fields_test() ->
    Fields = aws_auth_validate_ldap:allowed_fields(),
    [
        ?assert(lists:member(F, Fields))
     || F <- [
            <<"servers">>,
            <<"port">>,
            <<"user_dn">>,
            <<"password_arn">>,
            <<"use_ssl">>,
            <<"use_starttls">>,
            <<"ssl_options">>,
            <<"dn_lookup_base">>,
            <<"dn_lookup_attribute">>,
            <<"username">>,
            <<"queries">>
        ]
    ].

%%--------------------------------------------------------------------
%% Server address validation (SSRF prevention)
%%--------------------------------------------------------------------

server_blocks_loopback_test() ->
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("127.0.0.1")).

server_blocks_link_local_test() ->
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("169.254.169.254")).

server_blocks_rfc1918_10_test() ->
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("10.0.0.1")).

server_blocks_rfc1918_172_test() ->
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("172.16.0.1")).

server_blocks_rfc1918_192_test() ->
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("192.168.1.1")).

server_blocks_zero_network_test() ->
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("0.0.0.0")).

%% 100.64.0.0/10 (RFC 6598) carrier-grade NAT shared address space.
server_blocks_cgnat_test() ->
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("100.64.0.1")),
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("100.100.50.1")),
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("100.127.255.255")).

%% Boundary: 100.63.x and 100.128.x are public space and must stay allowed, so
%% the /10 mask (second octet 64..127) is not widened to the whole 100/8.
server_allows_cgnat_boundaries_test() ->
    ?assertEqual(true, aws_auth_validate_ldap:is_allowed_server("100.63.255.255")),
    ?assertEqual(true, aws_auth_validate_ldap:is_allowed_server("100.128.0.0")).

server_blocks_ipv6_loopback_test() ->
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("::1")).

%% fc00::/7 (ULA). fd00:ec2::254 is the IPv6 IMDS address -- the SSRF filter
%% must block it just like the v4 169.254.169.254.
server_blocks_ipv6_imds_test() ->
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("fd00:ec2::254")).

server_blocks_ipv6_ula_test() ->
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("fc00::1")).

%% fe80::/10 spans fe80..febf, not just the fe80 word.
server_blocks_ipv6_link_local_test() ->
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("fe80::1")),
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("febf::1")).

%% An IPv4-mapped v6 address embedding IMDS must not bypass the v4 ranges.
server_blocks_ipv4_mapped_imds_test() ->
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("::ffff:169.254.169.254")).

%% NAT64 (64:ff9b::/96) embeds a v4 address; on a host with a NAT64/DNS64
%% resolver 64:ff9b::169.254.169.254 translates to IMDS, so it must be blocked.
server_blocks_nat64_imds_test() ->
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("64:ff9b::169.254.169.254")).

%% NAT64 wrapping a public v4 stays allowed: the embedded address, not the
%% prefix, decides.
server_allows_nat64_public_test() ->
    ?assertEqual(true, aws_auth_validate_ldap:is_allowed_server("64:ff9b::8.8.8.8")).

%% 240.0.0.0/4 (reserved/Class E) and the 255.255.255.255 limited broadcast.
server_blocks_reserved_and_broadcast_test() ->
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("240.0.0.1")),
    ?assertEqual(false, aws_auth_validate_ldap:is_allowed_server("255.255.255.255")).

server_rejects_unresolvable_test() ->
    ?assertEqual(
        false, aws_auth_validate_ldap:is_allowed_server("this.host.does.not.exist.invalid")
    ).

%%--------------------------------------------------------------------
%% Post-connect peer re-check (DNS-rebinding TOCTOU defence)
%%--------------------------------------------------------------------

%% peer_allowed/1 takes a peername/1 result ({ok, {IP, Port}}) and is the
%% second SSRF gate: it runs on the live socket's peer, so even if the
%% pre-connect is_allowed_server/1 was passed a public IP, a peer that rebound
%% to a blocked range is caught here.
peer_allowed_public_v4_ok_test() ->
    ?assertEqual(ok, aws_auth_validate_ldap:peer_allowed({ok, {{8, 8, 8, 8}, 636}})).

peer_allowed_rebound_to_imds_blocked_test() ->
    ?assertEqual(
        blocked, aws_auth_validate_ldap:peer_allowed({ok, {{169, 254, 169, 254}, 80}})
    ).

peer_allowed_private_v4_blocked_test() ->
    ?assertEqual(blocked, aws_auth_validate_ldap:peer_allowed({ok, {{10, 0, 0, 5}, 389}})).

%% A peer that rebound into CGNAT (RFC 6598) must be caught on the live socket.
peer_allowed_rebound_to_cgnat_blocked_test() ->
    ?assertEqual(blocked, aws_auth_validate_ldap:peer_allowed({ok, {{100, 64, 0, 1}, 389}})).

peer_allowed_public_v6_ok_test() ->
    ?assertEqual(
        ok, aws_auth_validate_ldap:peer_allowed({ok, {{16#2606, 16#4700, 0, 0, 0, 0, 0, 1}, 636}})
    ).

%% fd00:ec2::254 (IPv6 IMDS) reached as the live peer must be blocked.
peer_allowed_rebound_to_v6_imds_blocked_test() ->
    ?assertEqual(
        blocked,
        aws_auth_validate_ldap:peer_allowed({ok, {{16#fd00, 16#0ec2, 0, 0, 0, 0, 0, 16#254}, 636}})
    ).

%% A peer that rebound to NAT64-wrapped IMDS (64:ff9b::169.254.169.254) must be
%% caught on the live socket.
peer_allowed_rebound_to_nat64_imds_blocked_test() ->
    ?assertEqual(
        blocked,
        aws_auth_validate_ldap:peer_allowed(
            {ok, {{16#0064, 16#ff9b, 0, 0, 0, 0, 16#a9fe, 16#a9fe}, 389}}
        )
    ).

%% Fail closed: an undeterminable peer (peername error) is treated as blocked.
peer_allowed_error_blocked_test() ->
    ?assertEqual(blocked, aws_auth_validate_ldap:peer_allowed({error, einval})).

ldap_validate_rejects_private_server_test() ->
    Body = base_body(#{<<"servers">> => [<<"169.254.169.254">>]}),
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_ldap:validate(Body)).

%% These all fail in the pure (network-free) validation pipeline, before any
%% password ARN resolution or outbound connection is attempted.
ldap_input_validation_test_() ->
    [
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(
                #{<<"port">> => 389, <<"user_dn">> => <<"u">>}
            )
        ),
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(base_body(#{<<"servers">> => []}))
        ),
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(base_body(#{<<"port">> => 0}))
        ),
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(base_body(#{<<"port">> => 65536}))
        ),
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(base_body(#{<<"user_dn">> => <<>>}))
        ),
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(base_body(#{<<"ssl_options">> => <<"x">>}))
        ),
        %% An unknown ssl_options key is rejected, not silently dropped.
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(
                base_body(#{<<"ssl_options">> => #{<<"verfy">> => <<"verify_peer">>}})
            )
        ),
        %% A known key with a mis-typed value is rejected in the pure phase
        %% (rather than dropped and re-defaulted).
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(
                base_body(#{<<"ssl_options">> => #{<<"verify">> => <<"verfy_none">>}})
            )
        ),
        %% depth must be a non-negative integer.
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(
                base_body(#{<<"ssl_options">> => #{<<"depth">> => -1}})
            )
        ),
        %% versions must be a list of known TLS versions.
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(
                base_body(#{<<"ssl_options">> => #{<<"versions">> => [<<"sslv3">>]}})
            )
        )
    ].

%% build_ssl_opts/1 must translate validated ssl_options values to their ssl
%% atoms WITHOUT binary_to_existing_atom, which would raise badarg for the
%% verify_*/tls* atoms when ssl is not yet loaded (build_ssl_opts runs while
%% assembling eldap:open options, before ssl is guaranteed up). Pin that the
%% explicit mappings produce the right atoms.
ldap_build_ssl_opts_translates_verify_and_versions_test() ->
    Opts = aws_auth_validate_ldap:build_ssl_opts(#{
        <<"verify">> => <<"verify_peer">>,
        <<"versions">> => [<<"tlsv1.3">>, <<"tlsv1.2">>],
        <<"depth">> => 3
    }),
    ?assertEqual(verify_peer, proplists:get_value(verify, Opts)),
    ?assertEqual(['tlsv1.3', 'tlsv1.2'], proplists:get_value(versions, Opts)),
    ?assertEqual(3, proplists:get_value(depth, Opts)).

%% An explicit verify_none from the caller must be preserved (opt-out), never
%% silently upgraded by the verify default.
ldap_build_ssl_opts_keeps_explicit_verify_none_test() ->
    Opts = aws_auth_validate_ldap:build_ssl_opts(#{<<"verify">> => <<"verify_none">>}),
    ?assertEqual(verify_none, proplists:get_value(verify, Opts)).

ldap_config_conflict_test() ->
    Body = base_body(#{<<"use_ssl">> => true, <<"use_starttls">> => true}),
    ?assertMatch({error, config_conflict, _}, aws_auth_validate_ldap:validate(Body)).

%%--------------------------------------------------------------------
%% DN lookup + authorization query input validation (pure pipeline)
%%--------------------------------------------------------------------

ldap_dn_lookup_input_test_() ->
    [
        %% Wrong types for the optional DN-lookup fields are rejected.
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(base_body(#{<<"dn_lookup_base">> => 123}))
        ),
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(base_body(#{<<"dn_lookup_base">> => <<>>}))
        ),
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(base_body(#{<<"dn_lookup_attribute">> => 1}))
        )
    ].

ldap_queries_input_test_() ->
    [
        %% queries must be an object.
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(base_body(#{<<"queries">> => <<"nope">>}))
        ),
        %% A non-string query value is a shape error.
        ?_assertMatch(
            {error, input_invalid, _},
            aws_auth_validate_ldap:validate(
                base_body(#{<<"queries">> => #{<<"tags">> => 123}})
            )
        ),
        %% A syntactically invalid query string is query_invalid (400).
        ?_assertMatch(
            {error, query_invalid, _},
            aws_auth_validate_ldap:validate(
                base_body(#{<<"queries">> => #{<<"vhost_access">> => <<"{garbage,">>}})
            )
        ),
        %% A grammatically-valid query that references a disallowed top-level
        %% term is also query_invalid.
        ?_assertMatch(
            {error, query_invalid, _},
            aws_auth_validate_ldap:validate(
                base_body(#{<<"queries">> => #{<<"tags">> => <<"{bogus_term, 1, 2}">>}})
            )
        )
    ].

%%--------------------------------------------------------------------
%% Configured assume-role fallback (aws.arns.assume_role_arn)
%%--------------------------------------------------------------------
%% When the operator configured aws.arns.assume_role_arn, the validate endpoint
%% assumes that role and resolves the request's ARNs under it, instead of the
%% broker's bare ambient role. Mirrors the boot-path coverage in
%% aws_arn_config_tests: meck aws_iam:assume_role/2 and aws_arn_util:resolve_arn/2
%% and assert which credentials reach the resolve. The mecked resolve fails so no
%% real connection is attempted; the password_arn resolve is the observation point.
ldap_configured_assume_role_test_() ->
    {foreach,
        fun() ->
            ok = meck:new(aws_iam, [no_link]),
            ok = meck:new(aws_arn_util, [passthrough, no_link]),
            ok
        end,
        fun(_) ->
            application:unset_env(aws, arn_config),
            catch meck:unload(aws_arn_util),
            catch meck:unload(aws_iam),
            ok
        end,
        [
            {
                "no configured role: assume_role is never called and the ambient "
                "(credential-free) state reaches ARN resolution",
                fun assume_role_not_configured_uses_ambient_state/0
            },
            {"configured role: the assumed credentials reach ARN resolution",
                fun assume_role_configured_threads_assumed_credentials/0},
            {
                "configured role that fails to assume: input_invalid before any "
                "ARN resolve",
                fun assume_role_configured_failure_returns_input_invalid/0
            }
        ]}.

%% A state carrying these credentials is distinguishable, via
%% aws_lib:get_credentials/1, from the credential-free aws_lib:new().
assume_role_test_assumed_state() ->
    {ok, S} = aws_lib:set_credentials("assumed-key", "secret", "token", aws_lib:new()),
    S.

assume_role_test_access_key(State) ->
    case aws_lib:get_credentials(State) of
        {ok, #aws_credentials{access_key = Key}} -> Key;
        {error, undefined} -> undefined
    end.

assume_role_not_configured_uses_ambient_state() ->
    application:unset_env(aws, arn_config),
    Self = self(),
    ok = meck:expect(aws_arn_util, resolve_arn, fun(_Arn, State) ->
        Self ! {resolve_key, assume_role_test_access_key(State)},
        {error, stop_here}
    end),
    %% resolve fails -> input_invalid, but we only care which state was threaded.
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_ldap:validate(base_body(#{}))),
    ?assertEqual(0, meck:num_calls(aws_iam, assume_role, '_')),
    receive
        {resolve_key, Key} -> ?assertEqual(undefined, Key)
    after 1_000 -> ?assert(false)
    end.

assume_role_configured_threads_assumed_credentials() ->
    application:set_env(aws, arn_config, [
        {assume_role_arn, "arn:aws:iam::123456789012:role/r"}
    ]),
    Self = self(),
    ok = meck:expect(aws_iam, assume_role, fun(_RoleArn, _State) ->
        {ok, assume_role_test_assumed_state()}
    end),
    ok = meck:expect(aws_arn_util, resolve_arn, fun(_Arn, State) ->
        Self ! {resolve_key, assume_role_test_access_key(State)},
        {error, stop_here}
    end),
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_ldap:validate(base_body(#{}))),
    ?assertEqual(1, meck:num_calls(aws_iam, assume_role, '_')),
    receive
        {resolve_key, Key} -> ?assertEqual("assumed-key", Key)
    after 1_000 -> ?assert(false)
    end.

assume_role_configured_failure_returns_input_invalid() ->
    application:set_env(aws, arn_config, [
        {assume_role_arn, "arn:aws:iam::123456789012:role/r"}
    ]),
    ok = meck:expect(aws_iam, assume_role, fun(_RoleArn, _State) ->
        {error, boom}
    end),
    ok = meck:expect(aws_arn_util, resolve_arn, fun(_Arn, _State) ->
        erlang:error(resolve_should_not_be_reached)
    end),
    ?assertEqual(
        {error, input_invalid, <<"failed to assume the configured role">>},
        aws_auth_validate_ldap:validate(base_body(#{}))
    ),
    ?assertEqual(0, meck:num_calls(aws_arn_util, resolve_arn, '_')).

%%--------------------------------------------------------------------
%% R6: password must never reach a crash report / log, even on a raise
%%--------------------------------------------------------------------

%% A unique, recognisable sentinel standing in for the resolved bind password.
%% If it appears anywhere in a crash report or log line, R6 is violated.
-define(SECRET, "S3cr3t-Sentinel-Passw0rd-DO-NOT-LEAK").

%% do_ldap_validate/1 is not exported, so reach it via validate/1's public
%% entry point would require a real ARN resolve. Instead we drive the same code
%% path the handler does -- a successful open() followed by a *raising*
%% simple_bind() -- with eldap mocked, and assert: (a) the result collapses to
%% the fixed connection_failed category (never propagates), and (b) the secret
%% byte-string does not appear in the formatted exception/stacktrace that a
%% crash report would render. We exercise validate/1 with the ARN resolver and
%% the eldap module both mocked so no network or AWS call occurs.
ldap_bind_raise_does_not_leak_password_test_() ->
    {setup,
        fun() ->
            ok = meck:new(eldap, [unstick, non_strict]),
            ok = meck:new(aws_arn_util, [passthrough]),
            %% Resolve any ARN to our sentinel password. resolve_arn/2 threads
            %% the passed aws_lib:aws_state() back in the success 3-tuple.
            meck:expect(aws_arn_util, resolve_arn, fun(_Arn, State) -> {ok, ?SECRET, State} end),
            %% open() succeeds, then simple_bind/3 RAISES with the password
            %% present in the failing call's arguments -- the worst case for a
            %% crash-report leak.
            meck:expect(eldap, open, fun(_Servers, _Opts) -> {ok, fake_handle} end),
            meck:expect(eldap, close, fun(_H) -> ok end),
            meck:expect(eldap, simple_bind, fun(_H, _Dn, Pw) ->
                erlang:error({ldap_blew_up, Pw})
            end),
            ok
        end,
        fun(_) ->
            meck:unload(eldap),
            meck:unload(aws_arn_util)
        end,
        fun(_) ->
            Body = bind_body(),
            %% (a) A raise in the bind path collapses to a fixed category and
            %% never propagates.
            Result = aws_auth_validate_ldap:validate(Body),
            %% (b) The secret never appears in the rendered result term.
            Rendered = lists:flatten(io_lib:format("~p", [Result])),
            [
                ?_assertMatch({error, connection_failed, _}, Result),
                ?_assertEqual(nomatch, string_find(Rendered, ?SECRET))
            ]
        end}.

%% A body that passes the pure pipeline so resolve_password/2 (mocked) and the
%% bind path are actually reached. use_ssl/use_starttls default to false.
bind_body() ->
    #{
        <<"servers">> => [<<"8.8.8.8">>],
        <<"port">> => 389,
        <<"user_dn">> => <<"cn=u,dc=example,dc=com">>,
        <<"password_arn">> =>
            <<"arn:aws:secretsmanager:us-east-1:111111111111:secret:x">>
    }.

string_find(Haystack, Needle) ->
    string:find(Haystack, Needle).

%%--------------------------------------------------------------------
%% CA-cert ARN resolution: failures must be reported, never silently
%% downgrade TLS to verify_none
%%--------------------------------------------------------------------

%% A failed cacertfile_arn resolution must surface as input_invalid (mirroring
%% the password-ARN path), NOT silently proceed with no trust anchor (which
%% would let `verify' default to verify_none and validate a TLS config the
%% operator believes is certificate-verified). We mock resolve_arn so the
%% password ARN resolves but the CA-cert ARN does not, and stop before any real
%% connection by asserting on the input_invalid result the resolve produces.
cacert_arn_resolution_test_() ->
    {foreach,
        fun() ->
            ok = meck:new(eldap, [unstick, non_strict]),
            ok = meck:new(aws_arn_util, [passthrough]),
            %% Keep the suite hermetic: the TLS-off case reaches the connect
            %% path, so stub eldap:open to fail fast instead of dialling out.
            meck:expect(eldap, open, fun(_Servers, _Opts) -> {error, refused} end),
            meck:expect(eldap, close, fun(_H) -> ok end),
            ok
        end,
        fun(_) ->
            meck:unload(eldap),
            meck:unload(aws_arn_util)
        end,
        [
            {"unresolvable CA-cert ARN -> input_invalid (no silent verify_none)", fun() ->
                %% Password ARN resolves; CA-cert ARN does not.
                meck:expect(aws_arn_util, resolve_arn, fun(Arn, State) ->
                    case lists:prefix("arn:aws:cacert", Arn) of
                        true -> {error, not_found};
                        false -> {ok, <<"pw">>, State}
                    end
                end),
                ?assertMatch(
                    {error, input_invalid, _},
                    aws_auth_validate_ldap:validate(tls_body(<<"arn:aws:cacert:nope">>))
                )
            end},
            {"CA-cert ARN resolving to non-PEM data -> input_invalid", fun() ->
                meck:expect(aws_arn_util, resolve_arn, fun(Arn, State) ->
                    case lists:prefix("arn:aws:cacert", Arn) of
                        true -> {ok, <<"this is not a PEM certificate">>, State};
                        false -> {ok, <<"pw">>, State}
                    end
                end),
                ?assertMatch(
                    {error, input_invalid, _},
                    aws_auth_validate_ldap:validate(tls_body(<<"arn:aws:cacert:garbage">>))
                )
            end},
            {"CA-cert ARN ignored when TLS is off (no resolve, no error)", fun() ->
                %% With use_ssl/use_starttls both false the CA cert is never
                %% consumed, so a bogus cacertfile_arn must not trigger a
                %% resolve or fail the request -- only the password ARN is
                %% fetched. A resolve of the CA-cert ARN raises so the test
                %% fails loudly if resolve_cacert/1 runs it; the password ARN
                %% resolves normally. The bind is then left to fail at connect
                %% (8.8.8.8:389), which is NOT input_invalid.
                meck:expect(aws_arn_util, resolve_arn, fun(Arn, State) ->
                    case lists:prefix("arn:aws:cacert", Arn) of
                        true -> erlang:error(cacert_resolved_with_tls_off);
                        false -> {ok, <<"pw">>, State}
                    end
                end),
                Result = aws_auth_validate_ldap:validate(
                    (bind_body())#{
                        <<"ssl_options">> => #{<<"cacertfile_arn">> => <<"arn:aws:cacert:x">>}
                    }
                ),
                ?assertNotMatch({error, input_invalid, _}, Result)
            end}
        ]}.

%% A body with TLS enabled and a caller-supplied CA-cert ARN, otherwise valid.
tls_body(CacertArn) ->
    (bind_body())#{
        <<"use_ssl">> => true,
        <<"ssl_options">> => #{<<"cacertfile_arn">> => CacertArn}
    }.

%%--------------------------------------------------------------------
%% LDAP query DSL parser (aws_auth_validate_ldap_query)
%%--------------------------------------------------------------------

parse_accepts_test_() ->
    ok = ensure_query_vocabulary_interned(),
    [
        ?_assertMatch({ok, _}, aws_auth_validate_ldap_query:parse(Q))
     || Q <- accepted_queries()
    ].

parse_rejects_test_() ->
    [
        ?_assertMatch({error, _}, aws_auth_validate_ldap_query:parse(Q))
     || Q <- rejected_queries()
    ].

parse_accepts_string_input_test() ->
    ?assertMatch({ok, _}, aws_auth_validate_ldap_query:parse("{constant, true}")).

%% Atom-exhaustion guard: the query string is attacker-controlled, so parsing
%% must never intern a new atom. A query naming an atom the broker has never
%% interned is rejected, and crucially the rejection creates zero atoms (the
%% old erl_scan:string/1 path interned one atom per distinct identifier).

parse_rejects_unknown_atom_does_not_intern_test() ->
    %% A syntactically valid term whose tag atom does not exist in the VM.
    Q = <<"[{zzz_phantom_tag_never_interned, {constant, true}}]">>,
    Before = erlang:system_info(atom_count),
    Result = aws_auth_validate_ldap_query:parse(Q),
    After = erlang:system_info(atom_count),
    ?assertMatch({error, _}, Result),
    ?assertEqual(0, After - Before).

parse_rejects_atom_flood_without_interning_test() ->
    %% Many distinct never-seen atoms in one query: the pre-safe-lexer code
    %% would have interned one atom each. Assert the whole batch is rejected
    %% and not a single atom is created.
    Atoms = [
        unicode:characters_to_binary(["zzz_flood_atom_", integer_to_list(N)])
     || N <- lists:seq(1, 500)
    ],
    Q = <<"[", (iolist_to_binary(lists:join(<<", ">>, Atoms)))/binary, "]">>,
    Before = erlang:system_info(atom_count),
    Result = aws_auth_validate_ldap_query:parse(Q),
    After = erlang:system_info(atom_count),
    ?assertMatch({error, _}, Result),
    ?assertEqual(0, After - Before).

%% Literal DN extraction (the placeholder-free DNs used for static reachability)

literal_dns_in_group_test() ->
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        <<"{in_group, \"cn=admins,ou=groups,dc=example,dc=com\"}">>
    ),
    ?assertEqual(
        ["cn=admins,ou=groups,dc=example,dc=com"],
        aws_auth_validate_ldap_query:literal_dns(Q)
    ).

literal_dns_skips_placeholder_test() ->
    %% A DN with a ${...} placeholder is runtime-filled, not literal, so it
    %% contributes no static reachability check.
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        <<"{in_group, \"cn=${username},ou=groups,dc=example,dc=com\"}">>
    ),
    ?assertEqual([], aws_auth_validate_ldap_query:literal_dns(Q)).

literal_dns_constant_test() ->
    {ok, Q} = aws_auth_validate_ldap_query:parse(<<"{constant, true}">>),
    ?assertEqual([], aws_auth_validate_ldap_query:literal_dns(Q)).

literal_dns_nested_and_or_test() ->
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        <<"{'or', [{in_group, \"cn=a,dc=x\"}, {'and', [{in_group, \"cn=b,dc=x\"}]}]}">>
    ),
    ?assertEqual(
        ["cn=a,dc=x", "cn=b,dc=x"],
        aws_auth_validate_ldap_query:literal_dns(Q)
    ).

literal_dns_tag_queries_test() ->
    ok = ensure_query_vocabulary_interned(),
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        <<"[{administrator, {in_group, \"cn=admins,dc=x\"}}, {management, {constant, true}}]">>
    ),
    ?assertEqual(["cn=admins,dc=x"], aws_auth_validate_ldap_query:literal_dns(Q)).

literal_dns_exists_test() ->
    %% parse/1 rejects {exists,_} (parse_query/1 does not allow it), but
    %% literal_dns/1 still walks the term defensively, so test it on a
    %% directly-constructed term rather than via parse/1.
    ?assertEqual(
        ["ou=users,dc=x"],
        aws_auth_validate_ldap_query:literal_dns({exists, "ou=users,dc=x"})
    ).

literal_dns_for_test() ->
    ok = ensure_query_vocabulary_interned(),
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        <<"{for, [{permission, configure, {in_group, \"cn=cfg,dc=x\"}}]}">>
    ),
    ?assertEqual(["cn=cfg,dc=x"], aws_auth_validate_ldap_query:literal_dns(Q)).

%% Regression tests for collect/2 DN extraction: value operands of
%% equals/match and bare-string queries must NOT be treated as DNs, while a
%% literal DN nested in an {attribute, DN, _} operand still is.

literal_dns_equals_placeholder_attribute_test() ->
    %% The DN slot of the attribute is a placeholder, so no literal DN; the
    %% value operand "engineering" is a value, never a DN.
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        <<"{equals, {attribute, \"${u}\", \"dept\"}, \"engineering\"}">>
    ),
    ?assertEqual([], aws_auth_validate_ldap_query:literal_dns(Q)).

literal_dns_equals_literal_attribute_test() ->
    %% A literal DN inside the attribute operand IS extracted; the value
    %% operand "v" is still ignored.
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        <<"{equals, {attribute, \"cn=x,dc=y\", \"dept\"}, \"v\"}">>
    ),
    ?assertEqual(["cn=x,dc=y"], aws_auth_validate_ldap_query:literal_dns(Q)).

literal_dns_match_value_operands_test() ->
    %% Both operands of match are values (a string and a regex), never DNs.
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        <<"{match, \"${username}\", \"^a.*\"}">>
    ),
    ?assertEqual([], aws_auth_validate_ldap_query:literal_dns(Q)).

literal_dns_bare_string_query_test() ->
    %% A top-level bare-string query parses to a character list; it is a
    %% value, not a DN, so it contributes nothing.
    {ok, Q} = aws_auth_validate_ldap_query:parse(<<"\"just a string\"">>),
    ?assertEqual([], aws_auth_validate_ldap_query:literal_dns(Q)).

%%--------------------------------------------------------------------
%% Placeholder filling (aws_auth_validate_ldap_query:fill/2)
%%--------------------------------------------------------------------

%% A literal in_group DN is unchanged by fill/2 and becomes evaluable.
fill_in_group_literal_test() ->
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        <<"{in_group, \"cn=admins,ou=groups,dc=x,dc=com\"}">>
    ),
    {in_group, DN} = aws_auth_validate_ldap_query:fill(Q, [{username, "alice"}]),
    ?assertEqual("cn=admins,ou=groups,dc=x,dc=com", DN),
    ?assert(aws_auth_validate_ldap_query:is_evaluable(DN)).

%% A ${username} placeholder in a DN sink is substituted and the result becomes
%% evaluable.
fill_username_in_dn_test() ->
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        <<"{in_group, \"cn=${username},ou=groups,dc=x,dc=com\"}">>
    ),
    {in_group, DN} = aws_auth_validate_ldap_query:fill(Q, [{username, "alice"}]),
    ?assertEqual("cn=alice,ou=groups,dc=x,dc=com", DN),
    ?assert(aws_auth_validate_ldap_query:is_evaluable(DN)).

%% DN sinks RFC 4514-escape the substituted value; the user_dn key is exempt
%% (it already holds a complete DN). A username with a comma must be escaped
%% inside a DN component but a user_dn value must not.
fill_dn_escaping_test() ->
    {ok, Q1} = aws_auth_validate_ldap_query:parse(
        <<"{in_group, \"cn=${username},dc=x\"}">>
    ),
    {in_group, DN1} = aws_auth_validate_ldap_query:fill(Q1, [{username, "a,b"}]),
    ?assertEqual("cn=a\\,b,dc=x", DN1),
    {ok, Q2} = aws_auth_validate_ldap_query:parse(
        <<"{in_group, \"${user_dn}\"}">>
    ),
    {in_group, DN2} = aws_auth_validate_ldap_query:fill(
        Q2, [{user_dn, "cn=a,ou=people,dc=x"}]
    ),
    ?assertEqual("cn=a,ou=people,dc=x", DN2).

%% A per-operation placeholder we cannot supply (${vhost}) survives unfilled,
%% so the DN stays non-evaluable and the backend degrades it.
fill_residual_placeholder_not_evaluable_test() ->
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        <<"{in_group, \"cn=admins,ou=${vhost},dc=x\"}">>
    ),
    {in_group, DN} = aws_auth_validate_ldap_query:fill(Q, [{username, "alice"}]),
    ?assertNot(aws_auth_validate_ldap_query:is_evaluable(DN)).

%% equals/match value operands are filled RAW (no DN escaping) -- they are ACL
%% value sinks, not DNs.
fill_value_operand_raw_test() ->
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        <<"{equals, \"${username}\", \"a,b\"}">>
    ),
    {equals, V1, V2} = aws_auth_validate_ldap_query:fill(Q, [{username, "x,y"}]),
    ?assertEqual("x,y", value_str(V1)),
    ?assertEqual("a,b", value_str(V2)).

%% ad_args/1 splits a DOMAIN\\user username and yields nothing for other shapes.
ad_args_test() ->
    ?assertEqual(
        [{ad_domain, "CORP"}, {ad_user, "alice"}],
        aws_auth_validate_ldap_query:ad_args("CORP\\alice")
    ),
    ?assertEqual([], aws_auth_validate_ldap_query:ad_args("alice")),
    ?assertEqual([], aws_auth_validate_ldap_query:ad_args(<<"alice">>)).

%% No-username path is unchanged: a placeholder-bearing DN is not literal, so
%% literal_dns/1 still skips it (backward-compat guard).
fill_does_not_affect_literal_dns_test() ->
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        <<"{in_group, \"cn=${username},dc=x\"}">>
    ),
    ?assertEqual([], aws_auth_validate_ldap_query:literal_dns(Q)).

value_str({string, S}) -> S;
value_str(S) when is_list(S) -> S.

%% Parity of fill/2 with the broker's fill machinery (design req R12). Our DN
%% sinks must match rabbit_ldap_rfc4514:fill_dn/2 and our value sinks must match
%% rabbit_auth_backend_ldap_util:fill/2. Skips unless both upstream modules are
%% loadable (same matrix concern as the parser parity test).
fill_parity_test_() ->
    case fill_upstream_usable() of
        true ->
            [
                {
                    "dn:" ++ Fmt,
                    ?_assertEqual(
                        rabbit_ldap_rfc4514:fill_dn(Fmt, Args),
                        fill_dn_via_query(Fmt, Args)
                    )
                }
             || {Fmt, Args} <- fill_dn_corpus()
            ] ++
                [
                    {
                        "raw:" ++ Fmt,
                        ?_assertEqual(
                            rabbit_auth_backend_ldap_util:fill(Fmt, Args),
                            fill_raw_via_query(Fmt, Args)
                        )
                    }
                 || {Fmt, Args} <- fill_raw_corpus()
                ];
        false ->
            []
    end.

%% Drive our DN-sink fill through a parsed in_group query and recover the DN.
fill_dn_via_query(Fmt, Args) ->
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        list_to_binary("{in_group, \"" ++ Fmt ++ "\"}")
    ),
    {in_group, DN} = aws_auth_validate_ldap_query:fill(Q, Args),
    DN.

%% Drive our value-sink (raw) fill through the second operand of an equals query.
fill_raw_via_query(Fmt, Args) ->
    {ok, Q} = aws_auth_validate_ldap_query:parse(
        list_to_binary("{equals, \"x\", \"" ++ Fmt ++ "\"}")
    ),
    {equals, _, V} = aws_auth_validate_ldap_query:fill(Q, Args),
    value_str(V).

fill_dn_corpus() ->
    [
        {"cn=${username},dc=x", [{username, "alice"}]},
        {"cn=${username},dc=x", [{username, "a,b+c"}]},
        {"${user_dn}", [{user_dn, "cn=a,ou=people,dc=x"}]},
        {"cn=${ad_user},dc=${ad_domain}", [{ad_user, "u"}, {ad_domain, "d"}]}
    ].

fill_raw_corpus() ->
    [
        {"${username}", [{username, "alice"}]},
        {"${username}", [{username, "a,b"}]},
        {"pre-${username}-post", [{username, "x"}]}
    ].

fill_upstream_usable() ->
    code:ensure_loaded(rabbit_ldap_rfc4514) =/= {error, nofile} andalso
        code:ensure_loaded(rabbit_auth_backend_ldap_util) =/= {error, nofile} andalso
        erlang:function_exported(rabbit_ldap_rfc4514, fill_dn, 2) andalso
        erlang:function_exported(rabbit_auth_backend_ldap_util, fill, 2).

%% Parity with rabbit_auth_backend_ldap_util:parse_query/1 (design req R12).
%% The broker's parser throws via cuttlefish:invalid/2 on rejection; ours
%% returns {error, _}. Assert both classify each corpus entry the same way.
%%
%% Runs only when upstream parse_query/1 is actually usable in this node.
%% It is not enough that the module loads: parse_query/1 calls
%% rabbit_data_coercion (and cuttlefish:invalid on rejection), and across
%% the RMQ-version CI matrix those deps are not always loaded in the bare
%% eunit node. If they are missing, every parse_query/1 call throws undef
%% and upstream_accepts/1 would report "rejected" for EVERYTHING, making the
%% test fail spuriously. So we probe upstream with a known-good and a
%% known-bad query first and skip the whole parity check unless upstream
%% classifies both correctly.
parity_test_() ->
    case upstream_parser_usable() of
        true ->
            [
                {
                    binary_to_list(Q),
                    ?_assertEqual(upstream_accepts(Q), ours_accepts(Q))
                }
             || Q <- accepted_queries() ++ rejected_queries()
            ];
        false ->
            []
    end.

%% True only if rabbit_auth_backend_ldap_util:parse_query/1 is loaded AND its
%% transitive deps are available, verified by a positive+negative probe.
upstream_parser_usable() ->
    code:ensure_loaded(rabbit_auth_backend_ldap_util) =/= {error, nofile} andalso
        erlang:function_exported(rabbit_auth_backend_ldap_util, parse_query, 1) andalso
        upstream_accepts(<<"{constant, true}">>) andalso
        not upstream_accepts(<<"{bogus_term, 1, 2}">>).

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

%% The query DSL parser tokenizes via the safe, non-interning lexer, so it
%% only accepts atoms that ALREADY exist in the VM. A running broker has
%% interned the whole legitimate vocabulary -- grammar keywords (from the
%% parser module itself), the configure/write/read permissions and the
%% for-query variable names (from core rabbit and rabbit_auth_backend_ldap),
%% the in_group_nested scopes, and every configured user tag. The bare eunit
%% node has executed almost none of that code, so those atoms are absent and a
%% legitimate query would be wrongly rejected here (but NOT in production).
%% Reference the vocabulary the corpus exercises as literals so the test node
%% mirrors a running broker. This list is test scaffolding, not a parser
%% allowlist: the parser accepts ANY already-interned atom (open tag set),
%% exactly as the broker does.
ensure_query_vocabulary_interned() ->
    %% list_to_atom/1 unconditionally interns, which is exactly what a running
    %% broker has already done for this vocabulary through normal operation.
    %% (A literal atom list would only intern at THIS module's load time, which
    %% eunit does not guarantee precedes the parser's list_to_existing_atom/1
    %% check; list_to_atom/1 is unambiguous.)
    _ = [
        list_to_atom(A)
     || A <- [
            %% permissions
            "configure",
            "write",
            "read",
            %% for-query variable names
            "username",
            "user_dn",
            "vhost",
            "resource",
            "name",
            "permission",
            %% in_group_nested scopes
            "subtree",
            "singlelevel",
            "single_level",
            "onelevel",
            "one_level",
            %% the specific tags the accepted-query corpus references
            "administrator",
            "management"
        ]
    ],
    ok.

stop(Pid) ->
    unlink(Pid),
    exit(Pid, kill),
    timer:sleep(10),
    ok.

wait_until_zero(0) ->
    ?assertEqual(0, aws_auth_validate_semaphore:current());
wait_until_zero(N) ->
    case aws_auth_validate_semaphore:current() of
        0 ->
            ok;
        _ ->
            timer:sleep(10),
            wait_until_zero(N - 1)
    end.

%% A minimally-valid body for the pure validation pipeline. Note: the tests
%% that use this assert failures triggered *before* password_arn resolution,
%% so the ARN here is never resolved (no AWS call is made). Uses a public IP
%% to pass server-address validation (SSRF filter blocks private ranges).
base_body(Overrides) when is_map(Overrides) ->
    Base = #{
        <<"servers">> => [<<"8.8.8.8">>],
        <<"port">> => 389,
        <<"user_dn">> => <<"cn=u">>,
        <<"password_arn">> => <<"arn:aws:secretsmanager:us-east-1:111111111111:secret:x">>
    },
    maps:merge(Base, Overrides).

%% Query corpus shared by the parser accept/reject tests and the parity test.

%% Queries the broker accepts. Kept in sync with the parity test.
accepted_queries() ->
    [
        <<"{constant, true}">>,
        <<"{constant, false}">>,
        <<"{in_group, \"cn=admins,ou=groups,dc=example,dc=com\"}">>,
        <<"{in_group_nested, \"cn=g,dc=example,dc=com\", \"member\"}">>,
        <<"{'not', {constant, true}}">>,
        <<"{'and', [{constant, true}, {constant, false}]}">>,
        <<"{'or', [{constant, true}, {constant, false}]}">>,
        <<"{equals, \"${username}\", \"admin\"}">>,
        <<"{match, \"${username}\", \"^a.*\"}">>,
        <<"{for, [{permission, configure, {constant, true}}]}">>,
        %% tag_queries form: a list of {Tag, SubQuery} pairs.
        <<"[{administrator, {in_group, \"cn=admins,dc=example,dc=com\"}}]">>,
        %% trailing dot already present
        <<"{constant, true}.">>,
        %% A bare quoted string parses to an Erlang list, so it hits the
        %% is_list/1 (tag_queries) clause in BOTH parsers. Included here to
        %% pin that parity quirk rather than to endorse it as a useful query.
        <<"\"just a string\"">>
    ].

rejected_queries() ->
    [
        <<"{garbage,">>,
        <<"not even erlang">>,
        <<"{bogus_term, 1, 2}">>,
        <<"42">>,
        <<>>,
        %% Forms the runtime evaluator handles but parse_query/1 (the config
        %% gate we mirror) rejects, so the endpoint rejects them too.
        <<"{in_group, \"cn=g,dc=example,dc=com\", \"member\"}">>,
        <<"{exists, \"ou=users,dc=example,dc=com\"}">>,
        <<"{attribute, \"cn=g,dc=example,dc=com\", \"member\"}">>
    ].

ours_accepts(Q) ->
    case aws_auth_validate_ldap_query:parse(Q) of
        {ok, _} -> true;
        {error, _} -> false
    end.

upstream_accepts(Q) ->
    try rabbit_auth_backend_ldap_util:parse_query(Q) of
        %% cuttlefish:invalid/2 throws on rejection; any throw/exit means the
        %% upstream parser rejected the query.
        _ -> true
    catch
        _:_ -> false
    end.
