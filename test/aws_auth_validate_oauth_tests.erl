%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% Unit tests for the OAuth 2.0 auth-validation backend's pure phase
%% (no real network). Covers URL parsing, SSRF classification, ssl_options
%% validation, and mocked JWKS/OIDC well-formedness checks.
-module(aws_auth_validate_oauth_tests).

-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% Method identity
%%--------------------------------------------------------------------

method_name_test() ->
    ?assertEqual(<<"oauth">>, aws_auth_validate_oauth:method_name()).

allowed_fields_test() ->
    Fields = aws_auth_validate_oauth:allowed_fields(),
    [
        ?assert(lists:member(F, Fields))
     || F <- [
            <<"jwks_uri">>,
            <<"issuer">>,
            <<"resource_server_id">>,
            <<"ssl_options">>
        ]
    ].

%%--------------------------------------------------------------------
%% Pure phase: URL presence / scheme enforcement
%%--------------------------------------------------------------------

%% At least one of jwks_uri or issuer is required.
missing_both_jwks_uri_and_issuer_test() ->
    Body = #{<<"resource_server_id">> => <<"my-api">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% A plain http:// jwks_uri is rejected (https-only for signing keys).
http_jwks_uri_rejected_test() ->
    Body = #{<<"jwks_uri">> => <<"http://idp.example.com/.well-known/jwks.json">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% A plain http:// issuer is rejected.
http_issuer_rejected_test() ->
    Body = #{<<"issuer">> => <<"http://idp.example.com">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% An empty string jwks_uri is rejected.
empty_jwks_uri_rejected_test() ->
    Body = #{<<"jwks_uri">> => <<>>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% An empty string issuer is rejected.
empty_issuer_rejected_test() ->
    Body = #{<<"issuer">> => <<>>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% A non-string jwks_uri value is rejected.
non_string_jwks_uri_rejected_test() ->
    Body = #{<<"jwks_uri">> => 12345},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%%--------------------------------------------------------------------
%% Pure phase: URL shape rejections
%%--------------------------------------------------------------------

%% A URL with userinfo (user:pass@host) is rejected.
url_with_userinfo_rejected_test() ->
    Body = #{<<"jwks_uri">> => <<"https://admin:secret@idp.example.com/jwks">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% A URL with a pre-existing query string is rejected.
url_with_query_rejected_test() ->
    Body = #{<<"jwks_uri">> => <<"https://idp.example.com/jwks?foo=bar">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% A URL with an out-of-range port (0) is rejected.
url_port_zero_rejected_test() ->
    Body = #{<<"jwks_uri">> => <<"https://idp.example.com:0/jwks">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% A URL with an out-of-range port (>65535) is rejected.
url_port_too_high_rejected_test() ->
    Body = #{<<"jwks_uri">> => <<"https://idp.example.com:70000/jwks">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% A URL with an unparseable structure is rejected.
url_garbage_rejected_test() ->
    Body = #{<<"jwks_uri">> => <<"not a url at all">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%%--------------------------------------------------------------------
%% Pure phase: SSRF literal-IP classification
%%--------------------------------------------------------------------

%% 169.254.169.254 (IMDS) is denied.
ssrf_imds_v4_test() ->
    Body = #{<<"jwks_uri">> => <<"https://169.254.169.254/latest/meta-data/">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% 127.0.0.1 (loopback) is denied.
ssrf_loopback_v4_test() ->
    Body = #{<<"jwks_uri">> => <<"https://127.0.0.1/jwks">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% ::1 (IPv6 loopback) is denied.
ssrf_loopback_v6_test() ->
    Body = #{<<"jwks_uri">> => <<"https://[::1]/jwks">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% IPv4-mapped IMDS (::ffff:169.254.169.254) is denied.
ssrf_v4_mapped_imds_test() ->
    Body = #{<<"jwks_uri">> => <<"https://[::ffff:169.254.169.254]/jwks">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% fd00:ec2::254 (IPv6 IMDS) is denied.
ssrf_v6_imds_test() ->
    Body = #{<<"jwks_uri">> => <<"https://[fd00:ec2::254]/jwks">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% fe80::1 (link-local) is denied.
ssrf_link_local_v6_test() ->
    Body = #{<<"jwks_uri">> => <<"https://[fe80::1]/jwks">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% 0.0.0.0 (unspecified) is denied.
ssrf_unspecified_v4_test() ->
    Body = #{<<"jwks_uri">> => <<"https://0.0.0.0/jwks">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% The SSRF guard also applies to the issuer URL.
ssrf_issuer_imds_test() ->
    Body = #{<<"issuer">> => <<"https://169.254.169.254">>},
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%%--------------------------------------------------------------------
%% Pure phase: resource_server_id validation
%%--------------------------------------------------------------------

%% resource_server_id, if present, must be a non-empty string.
resource_server_id_empty_rejected_test() ->
    Body = #{
        <<"jwks_uri">> => <<"https://idp.example.com/jwks">>,
        <<"resource_server_id">> => <<>>
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% A non-string resource_server_id is rejected.
resource_server_id_non_string_rejected_test() ->
    Body = #{
        <<"jwks_uri">> => <<"https://idp.example.com/jwks">>,
        <<"resource_server_id">> => 42
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%%--------------------------------------------------------------------
%% Pure phase: ssl_options validation
%%--------------------------------------------------------------------

%% ssl_options must be an object (map), not a scalar.
ssl_options_not_map_rejected_test() ->
    Body = #{
        <<"jwks_uri">> => <<"https://idp.example.com/jwks">>,
        <<"ssl_options">> => <<"bad">>
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% An unknown ssl_options key is rejected.
ssl_options_unknown_key_rejected_test() ->
    Body = #{
        <<"jwks_uri">> => <<"https://idp.example.com/jwks">>,
        <<"ssl_options">> => #{<<"unknown_key">> => <<"value">>}
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% verify must be verify_peer or verify_none.
ssl_options_bad_verify_rejected_test() ->
    Body = #{
        <<"jwks_uri">> => <<"https://idp.example.com/jwks">>,
        <<"ssl_options">> => #{<<"verify">> => <<"verfy_peer">>}
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% depth must be a non-negative integer.
ssl_options_bad_depth_rejected_test() ->
    Body = #{
        <<"jwks_uri">> => <<"https://idp.example.com/jwks">>,
        <<"ssl_options">> => #{<<"depth">> => -1}
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% versions must be a list of known TLS versions.
ssl_options_bad_versions_rejected_test() ->
    Body = #{
        <<"jwks_uri">> => <<"https://idp.example.com/jwks">>,
        <<"ssl_options">> => #{<<"versions">> => [<<"sslv3">>]}
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% sni must be a non-empty string.
ssl_options_bad_sni_rejected_test() ->
    Body = #{
        <<"jwks_uri">> => <<"https://idp.example.com/jwks">>,
        <<"ssl_options">> => #{<<"sni">> => <<>>}
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% certfile_arn and keyfile_arn must be supplied together -- one without the
%% other is rejected.
ssl_options_cert_without_key_rejected_test() ->
    Body = #{
        <<"jwks_uri">> => <<"https://idp.example.com/jwks">>,
        <<"ssl_options">> => #{<<"certfile_arn">> => <<"arn:aws:s3:::bucket/cert.pem">>}
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

ssl_options_key_without_cert_rejected_test() ->
    Body = #{
        <<"jwks_uri">> => <<"https://idp.example.com/jwks">>,
        <<"ssl_options">> => #{
            <<"keyfile_arn">> => <<"arn:aws:secretsmanager:us-east-1:111:secret:k">>
        }
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%% cacertfile_arn must be a non-empty string.
ssl_options_bad_cacert_arn_rejected_test() ->
    Body = #{
        <<"jwks_uri">> => <<"https://idp.example.com/jwks">>,
        <<"ssl_options">> => #{<<"cacertfile_arn">> => <<>>}
    },
    ?assertMatch({error, input_invalid, _}, aws_auth_validate_oauth:validate(Body)).

%%--------------------------------------------------------------------
%% Network phase (mocked): JWKS well-formedness
%%--------------------------------------------------------------------

%% A 200 response with {"keys":[{...}]} is well-formed -> ok.
jwks_valid_200_test_() ->
    {setup, fun setup_httpc_mock/0, fun teardown_httpc_mock/1, fun(_) ->
        JwksBody = rabbit_json:encode(#{
            <<"keys">> => [
                #{<<"kty">> => <<"RSA">>, <<"kid">> => <<"key1">>}
            ]
        }),
        mock_httpc_response(200, JwksBody),
        mock_arn_resolve_noop(),
        Result = aws_auth_validate_oauth:validate(jwks_body()),
        [?_assertEqual(ok, Result)]
    end}.

%% A 200 with {"keys":[]} (empty array) -> auth_failed.
jwks_empty_keys_test_() ->
    {setup, fun setup_httpc_mock/0, fun teardown_httpc_mock/1, fun(_) ->
        JwksBody = rabbit_json:encode(#{<<"keys">> => []}),
        mock_httpc_response(200, JwksBody),
        mock_arn_resolve_noop(),
        Result = aws_auth_validate_oauth:validate(jwks_body()),
        [?_assertMatch({error, auth_failed, _}, Result)]
    end}.

%% A 200 with a non-JWKS body (no "keys" field) -> auth_failed.
jwks_non_jwks_body_test_() ->
    {setup, fun setup_httpc_mock/0, fun teardown_httpc_mock/1, fun(_) ->
        NotJwks = rabbit_json:encode(#{<<"something">> => <<"else">>}),
        mock_httpc_response(200, NotJwks),
        mock_arn_resolve_noop(),
        Result = aws_auth_validate_oauth:validate(jwks_body()),
        [?_assertMatch({error, auth_failed, _}, Result)]
    end}.

%% A non-200 HTTP response -> auth_failed (endpoint reachable but not
%% serving a JWKS).
jwks_non_200_test_() ->
    {setup, fun setup_httpc_mock/0, fun teardown_httpc_mock/1, fun(_) ->
        mock_httpc_response(403, <<"Forbidden">>),
        mock_arn_resolve_noop(),
        Result = aws_auth_validate_oauth:validate(jwks_body()),
        [?_assertMatch({error, auth_failed, _}, Result)]
    end}.

%% An httpc transport error -> connection_failed.
jwks_connection_error_test_() ->
    {setup, fun setup_httpc_mock/0, fun teardown_httpc_mock/1, fun(_) ->
        meck:expect(httpc, request, fun(_Method, _Req, _HttpOpts, _Opts, _Profile) ->
            {error,
                {failed_connect, [{to_address, {"idp.example.com", 443}}, {inet, [], econnrefused}]}}
        end),
        mock_arn_resolve_noop(),
        Result = aws_auth_validate_oauth:validate(jwks_body()),
        [?_assertMatch({error, connection_failed, _}, Result)]
    end}.

%%--------------------------------------------------------------------
%% Network phase (mocked): OIDC discovery
%%--------------------------------------------------------------------

%% When only issuer is given, the backend fetches .well-known/openid-configuration
%% and extracts jwks_uri. A discovery doc lacking jwks_uri -> auth_failed.
oidc_discovery_missing_jwks_uri_test_() ->
    {setup, fun setup_httpc_mock/0, fun teardown_httpc_mock/1, fun(_) ->
        %% First request = discovery, returns a doc without jwks_uri.
        DiscoveryBody = rabbit_json:encode(#{
            <<"issuer">> => <<"https://idp.example.com">>,
            <<"authorization_endpoint">> => <<"https://idp.example.com/authorize">>
        }),
        meck:expect(httpc, request, fun(_Method, _Req, _HttpOpts, _Opts, _Profile) ->
            {ok, {{"HTTP/1.1", 200, "OK"}, [], DiscoveryBody}}
        end),
        mock_arn_resolve_noop(),
        Result = aws_auth_validate_oauth:validate(issuer_body()),
        [?_assertMatch({error, auth_failed, _}, Result)]
    end}.

%% A valid discovery doc with jwks_uri pointing to a valid JWKS -> ok.
oidc_discovery_success_test_() ->
    {setup, fun setup_httpc_mock/0, fun teardown_httpc_mock/1, fun(_) ->
        JwksBody = rabbit_json:encode(#{
            <<"keys">> => [#{<<"kty">> => <<"RSA">>, <<"kid">> => <<"k1">>}]
        }),
        DiscoveryBody = rabbit_json:encode(#{
            <<"issuer">> => <<"https://idp.example.com">>,
            <<"jwks_uri">> => <<"https://idp.example.com/.well-known/jwks.json">>
        }),
        %% Sequence: first call = discovery, second call = JWKS fetch.
        meck:expect(httpc, request, fun(_Method, Req, _HttpOpts, _Opts, _Profile) ->
            Url = request_url(Req),
            case string:find(Url, "openid-configuration") of
                nomatch ->
                    {ok, {{"HTTP/1.1", 200, "OK"}, [], JwksBody}};
                _ ->
                    {ok, {{"HTTP/1.1", 200, "OK"}, [], DiscoveryBody}}
            end
        end),
        mock_arn_resolve_noop(),
        Result = aws_auth_validate_oauth:validate(issuer_body()),
        [?_assertEqual(ok, Result)]
    end}.

%%--------------------------------------------------------------------
%% R6: no secret leakage in error results
%%--------------------------------------------------------------------

%% A network-phase error must never include resolved secret material.
no_secret_in_error_test_() ->
    {setup, fun setup_httpc_mock/0, fun teardown_httpc_mock/1, fun(_) ->
        %% Simulate a TLS failure that includes secret bytes in the error term.
        meck:expect(httpc, request, fun(_Method, _Req, _HttpOpts, _Opts, _Profile) ->
            {error, {failed_connect, [{tls_alert, {certificate_expired, "SECRET-PEM-DATA"}}]}}
        end),
        mock_arn_resolve_noop(),
        Result = aws_auth_validate_oauth:validate(jwks_body()),
        Rendered = lists:flatten(io_lib:format("~p", [Result])),
        [
            ?_assertMatch({error, tls_failed, _}, Result),
            ?_assertEqual(nomatch, string:find(Rendered, "SECRET-PEM-DATA"))
        ]
    end}.

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

%% A minimal body with a direct jwks_uri (bypasses OIDC discovery).
jwks_body() ->
    #{<<"jwks_uri">> => <<"https://idp.example.com/.well-known/jwks.json">>}.

%% A minimal body with only issuer (triggers OIDC discovery).
issuer_body() ->
    #{<<"issuer">> => <<"https://idp.example.com">>}.

%% Setup meck for httpc and inets (the backend starts/stops an ephemeral
%% httpc profile). Also mock inet for DNS resolution in the network phase
%% so the resolve_and_pin step does not hit real DNS.
setup_httpc_mock() ->
    %% Ensure no stale mocks from a prior group whose teardown was skipped.
    catch meck:unload(httpc),
    catch meck:unload(inets),
    catch meck:unload(inet),
    catch meck:unload(aws_arn_util),
    ok = meck:new(httpc, [unstick, non_strict]),
    ok = meck:new(inets, [unstick, non_strict]),
    ok = meck:new(inet, [unstick, passthrough]),
    %% Default: inets profile start/stop always succeed.
    meck:expect(inets, start, fun(httpc, _Opts) -> {ok, self()} end),
    meck:expect(inets, stop, fun(httpc, _Profile) -> ok end),
    %% Default: httpc set_options succeeds.
    meck:expect(httpc, set_options, fun(_Opts, _Profile) -> ok end),
    %% DNS resolution returns a safe public IP for any hostname. This avoids
    %% hitting real DNS and ensures resolve_and_pin's SSRF re-check passes.
    meck:expect(inet, getaddrs, fun
        (_Host, inet) ->
            {ok, [{93, 184, 216, 34}]};
        (_Host, inet6) ->
            {error, nxdomain}
    end),
    ok.

teardown_httpc_mock(_) ->
    catch meck:unload(httpc),
    catch meck:unload(inets),
    catch meck:unload(inet),
    catch meck:unload(aws_arn_util),
    ok.

%% Mock httpc:request to return a fixed HTTP response.
mock_httpc_response(StatusCode, Body) when is_binary(Body) ->
    meck:expect(httpc, request, fun(_Method, _Req, _HttpOpts, _Opts, _Profile) ->
        {ok, {{"HTTP/1.1", StatusCode, "OK"}, [], Body}}
    end).

%% Mock ARN resolution to succeed as a no-op (the pure-phase tests do not
%% supply ssl_options with ARNs, so this only fires if the backend
%% optionally resolves something).
mock_arn_resolve_noop() ->
    catch meck:unload(aws_arn_util),
    ok = meck:new(aws_arn_util, [passthrough]),
    meck:expect(aws_arn_util, resolve_arn, fun(_Arn, State) -> {ok, <<"noop">>, State} end),
    ok.

%% Extract the URL string from an httpc Request tuple (GET or POST form).
request_url({Url, _Headers}) -> Url;
request_url({Url, _Headers, _ContentType, _Body}) -> Url.
