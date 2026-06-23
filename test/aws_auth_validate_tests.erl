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
