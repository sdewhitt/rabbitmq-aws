%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% HTTP auth-backend reachability validation.
%%
%% Validates a `rabbit_auth_backend_http' configuration (the auth_http.*
%% settings a customer would put in rabbitmq.conf) without a broker restart.
%% Mirrors the LDAP backend's shape: pure input validation runs first, secret
%% ARNs are resolved only after, and every outcome collapses to a fixed
%% category so the response leaks no target URL, response body, or raw httpc
%% error.
%%
%% Scope: REACHABILITY-ONLY (deliberate first cut). An HTTP auth server, by
%% contract, answers `allow'/`deny' for a specific {user, vhost, resource}
%% tuple -- a `deny' is a correctly-working server, not a misconfiguration. So
%% we do NOT assert that any particular principal is authorized. Instead we
%% confirm each configured `*_path' is reachable over (m)TLS and answers like
%% an auth server (a well-formed HTTP response). That catches the actual pain
%% (wrong URL, TLS/CA misconfig, unreachable host) without needing a real test
%% credential or an authz-semantics judgement.
%%
%% A future credentialed-probe mode (assert user_path returns `allow' for a
%% supplied username + password_arn) is intentionally out of scope here; see
%% http-validation-analysis.md, open question 1.
%%
%% Category mapping (reuses the existing aws_auth_validate_backend categories;
%% no new category is introduced, per R4 "keep the set small"):
%%   * connection_failed (400) -- host unreachable / DNS / connection refused.
%%   * tls_failed        (400) -- TLS handshake / cert verification failure.
%%   * auth_failed       (422) -- reached the server but its response is not
%%                                auth-server-shaped (no usable HTTP status).
%%     NOTE: auth_failed is borrowed for "endpoint did not behave like an auth
%%     server". If reachability-only proves too coarse, introduce a dedicated
%%     `endpoint_unverified' category (analogous to authz_unverified) -- that
%%     requires extending aws_auth_validate_backend:error_category/0 and the
%%     handler's status_for_category/1.
-module(aws_auth_validate_http).

-behaviour(aws_auth_validate_backend).

-export([method_name/0, validate/1, allowed_fields/0]).

%% resolve_arn/1 is part of the reachability-probe skeleton (it will resolve
%% cacertfile_arn once do_http_validate/1 is implemented). It is defined now so
%% the probe's contract is visible, but is not yet called -- suppress the
%% unused-function warning until the probe wires it in. Remove this when the
%% probe lands.
-compile({nowarn_unused_function, [{resolve_arn, 1}]}).

%% Default per-request timeout (ms) when auth_validation_connection_timeout_ms
%% is unset. Matches the LDAP backend's default.
-define(DEFAULT_TIMEOUT_MS, 5_000).

%% The four request paths a rabbit_auth_backend_http config can define. Each is
%% an absolute URL. user_path is required (the broker always issues a user
%% check); the other three are optional and validated/probed only when present.
-define(PATH_KEYS, [
    <<"user_path">>,
    <<"vhost_path">>,
    <<"resource_path">>,
    <<"topic_path">>
]).
-define(REQUIRED_PATH_KEY, <<"user_path">>).

%% Accepted values for http_method (mirrors rabbit_auth_backend_http's
%% auth_http.http_method).
-define(HTTP_METHOD_VALUES, [<<"get">>, <<"post">>]).

%% ssl_options surface, identical to the LDAP backend's (auth_http.ssl_options.*
%% has the same shape as auth_ldap.ssl_options.*).
-define(SSL_OPTION_KEYS, [
    <<"cacertfile_arn">>,
    <<"verify">>,
    <<"depth">>,
    <<"versions">>,
    <<"server_name_indication">>
]).
-define(SSL_VERIFY_VALUES, [<<"verify_peer">>, <<"verify_none">>]).
-define(SSL_VERSION_VALUES, [
    <<"tlsv1.3">>,
    <<"tlsv1.2">>,
    <<"tlsv1.1">>,
    <<"tlsv1">>
]).

%% Fixed, hardcoded reason strings (R4): no URL, host, or raw error echoed.
-define(REASON_BAD_PATHS, <<"at least user_path must be a non-empty URL string">>).
-define(REASON_BAD_PATH_VALUE, <<"each path must be a non-empty URL string">>).
-define(REASON_BAD_URL, <<"a configured path is not a valid http(s) URL">>).
-define(REASON_URL_NOT_ALLOWED, <<"a configured path targets a disallowed address">>).
-define(REASON_BAD_HTTP_METHOD, <<"http_method must be get or post">>).
-define(REASON_BAD_SSL_OPTIONS, <<"ssl_options must be an object">>).
-define(REASON_UNKNOWN_SSL_OPTION, <<
    "ssl_options contains an unknown key; allowed keys are cacertfile_arn, "
    "verify, depth, versions, server_name_indication"
>>).
-define(REASON_BAD_SSL_VERIFY, <<"ssl_options.verify must be verify_peer or verify_none">>).
-define(REASON_BAD_SSL_DEPTH, <<"ssl_options.depth must be a non-negative integer">>).
-define(REASON_BAD_SSL_VERSIONS, <<"ssl_options.versions must be a list of known TLS versions">>).
-define(REASON_BAD_SSL_SNI, <<"ssl_options.server_name_indication must be a string">>).
-define(REASON_BAD_SSL_CACERT_ARN, <<"ssl_options.cacertfile_arn must be a non-empty string">>).
-define(REASON_CONNECTION, <<"could not connect to HTTP auth server">>).
-define(REASON_TLS_HANDSHAKE, <<"TLS handshake failed">>).
-define(REASON_ENDPOINT, <<"HTTP auth server did not return a usable response">>).

%%--------------------------------------------------------------------
%% Behaviour callbacks
%%--------------------------------------------------------------------

method_name() ->
    <<"http">>.

allowed_fields() ->
    [
        <<"user_path">>,
        <<"vhost_path">>,
        <<"resource_path">>,
        <<"topic_path">>,
        <<"http_method">>,
        <<"ssl_options">>
    ].

-spec validate(map()) -> aws_auth_validate_backend:result().
validate(Body) when is_map(Body) ->
    %% Same ARN-first ordering as the LDAP backend: all pure, network-free
    %% validation (URL shape, method, ssl_options values, and the SSRF guard)
    %% runs before any cacertfile_arn is resolved or any request is made.
    case parse_input(Body) of
        {error, _, _} = Err ->
            Err;
        {ok, Params} ->
            do_http_validate(Params)
    end.

%%--------------------------------------------------------------------
%% Input parsing (pure, no network)
%%--------------------------------------------------------------------

parse_input(Body) ->
    Steps = [
        fun parse_paths/2,
        fun parse_http_method/2,
        fun parse_ssl_options/2,
        %% SSRF guard runs in the pure phase so a disallowed target is rejected
        %% before any ARN resolution or outbound request. See guard_urls/2.
        fun guard_urls/2
    ],
    parse_input(Steps, Body, #{timeout => connection_timeout_ms()}).

parse_input([], _Body, Acc) ->
    {ok, Acc};
parse_input([Step | Rest], Body, Acc0) ->
    case Step(Body, Acc0) of
        {ok, Acc1} -> parse_input(Rest, Body, Acc1);
        {error, _, _} = Err -> Err
    end.

%% Collect the configured paths. user_path is mandatory; the others are
%% optional. Each present value must be a non-empty string and parse as an
%% http(s) URL. Stored as a list of {Key, UrlString} preserving which path is
%% which (so a probe failure could be attributed internally, though the
%% response stays category-only).
parse_paths(Body, Acc) ->
    case maps:get(?REQUIRED_PATH_KEY, Body, undefined) of
        V when not (is_binary(V) andalso byte_size(V) > 0) ->
            {error, input_invalid, ?REASON_BAD_PATHS};
        _ ->
            collect_paths(?PATH_KEYS, Body, Acc, [])
    end.

collect_paths([], _Body, Acc, Paths) ->
    {ok, Acc#{paths => lists:reverse(Paths)}};
collect_paths([Key | Rest], Body, Acc, Paths) ->
    case maps:get(Key, Body, undefined) of
        undefined ->
            collect_paths(Rest, Body, Acc, Paths);
        V when is_binary(V), byte_size(V) > 0 ->
            case parse_url(V) of
                {ok, Url} -> collect_paths(Rest, Body, Acc, [{Key, Url} | Paths]);
                {error, _} -> {error, input_invalid, ?REASON_BAD_URL}
            end;
        _ ->
            {error, input_invalid, ?REASON_BAD_PATH_VALUE}
    end.

%% Parse + minimally validate an http(s) URL. Returns a normalized
%% representation the probe and the SSRF guard can both use. Kept deliberately
%% small here; richer parsing belongs with the guard work.
parse_url(Bin) when is_binary(Bin) ->
    Str = binary_to_list(Bin),
    case uri_string:parse(Str) of
        #{scheme := Scheme, host := Host} = Parsed when
            Host =/= [], (Scheme =:= "http" orelse Scheme =:= "https")
        ->
            {ok, Parsed#{url_string => Str}};
        _ ->
            {error, bad_url}
    end.

parse_http_method(Body, Acc) ->
    case maps:get(<<"http_method">>, Body, undefined) of
        undefined ->
            %% rabbit_auth_backend_http requires http_method to be set; default
            %% to post (its documented default) when the caller omits it.
            {ok, Acc#{http_method => post}};
        V when is_binary(V) ->
            case lists:member(V, ?HTTP_METHOD_VALUES) of
                true -> {ok, Acc#{http_method => binary_to_existing_atom(V, utf8)}};
                false -> {error, input_invalid, ?REASON_BAD_HTTP_METHOD}
            end;
        _ ->
            {error, input_invalid, ?REASON_BAD_HTTP_METHOD}
    end.

%% ssl_options parsing is identical to the LDAP backend's: validate both keys
%% and values in the pure phase so a mis-typed value cannot be silently dropped
%% and re-defaulted.
parse_ssl_options(Body, Acc) ->
    case maps:get(<<"ssl_options">>, Body, undefined) of
        undefined ->
            {ok, Acc#{ssl_options => #{}}};
        Map when is_map(Map) ->
            case [K || K <- maps:keys(Map), not lists:member(K, ?SSL_OPTION_KEYS)] of
                [] -> validate_ssl_values(maps:to_list(Map), Acc, Map);
                [_ | _] -> {error, input_invalid, ?REASON_UNKNOWN_SSL_OPTION}
            end;
        _ ->
            {error, input_invalid, ?REASON_BAD_SSL_OPTIONS}
    end.

validate_ssl_values([], Acc, Map) ->
    {ok, Acc#{ssl_options => Map}};
validate_ssl_values([{Key, Value} | Rest], Acc, Map) ->
    case valid_ssl_value(Key, Value) of
        ok -> validate_ssl_values(Rest, Acc, Map);
        {error, _, _} = Err -> Err
    end.

valid_ssl_value(<<"verify">>, V) ->
    case lists:member(V, ?SSL_VERIFY_VALUES) of
        true -> ok;
        false -> {error, input_invalid, ?REASON_BAD_SSL_VERIFY}
    end;
valid_ssl_value(<<"depth">>, V) when is_integer(V), V >= 0 ->
    ok;
valid_ssl_value(<<"depth">>, _) ->
    {error, input_invalid, ?REASON_BAD_SSL_DEPTH};
valid_ssl_value(<<"versions">>, V) when is_list(V), V =/= [] ->
    case lists:all(fun(Ver) -> lists:member(Ver, ?SSL_VERSION_VALUES) end, V) of
        true -> ok;
        false -> {error, input_invalid, ?REASON_BAD_SSL_VERSIONS}
    end;
valid_ssl_value(<<"versions">>, _) ->
    {error, input_invalid, ?REASON_BAD_SSL_VERSIONS};
valid_ssl_value(<<"server_name_indication">>, V) ->
    case is_nonempty_binary(V) of
        true -> ok;
        false -> {error, input_invalid, ?REASON_BAD_SSL_SNI}
    end;
valid_ssl_value(<<"cacertfile_arn">>, V) ->
    case is_nonempty_binary(V) of
        true -> ok;
        false -> {error, input_invalid, ?REASON_BAD_SSL_CACERT_ARN}
    end.

%%--------------------------------------------------------------------
%% SSRF guard (SKELETON -- needs a deep dive before production)
%%--------------------------------------------------------------------
%%
%% The validator issues outbound requests to customer-supplied URLs using the
%% broker's network position -- a textbook SSRF / confused-deputy surface. This
%% guard is the single chokepoint where every target URL is checked before any
%% request is made. It runs in the pure phase (no DNS, no network) so the
%% policy decision is deterministic and testable.
%%
%% DEEP-DIVE TODO (tracked in http-validation-analysis.md, open question 4):
%%   1. Scheme allowlist -- decide whether to require https only, or allow http
%%      for in-VPC plaintext auth servers. (Skeleton: ?ALLOWED_SCHEMES.)
%%   2. Address denylist -- block link-local / metadata / loopback / private
%%      ranges as policy dictates, MOST IMPORTANTLY the IMDS endpoint
%%      169.254.169.254 (and fd00:ec2::254 for IPv6). Note: a hostname can
%%      resolve to a blocked IP at request time (DNS rebinding), so a complete
%%      guard must also pin/re-check the resolved address at connect time --
%%      that part is NOT pure and belongs with the probe, not here.
%%   3. Redirect handling -- httpc must NOT auto-follow redirects to a
%%      blocked address (set autoredirect=false in the probe).
%%   4. AppSec review before this leaves draft.
%%
%% Until the deep dive lands, this is intentionally permissive: it enforces only
%% the scheme allowlist (already guaranteed by parse_url/1) and leaves the
%% address policy as a marked extension point. Flipping ?ENFORCE_ADDRESS_POLICY
%% to true (after implementing classify_address/1) makes it deny by policy.

-define(ALLOWED_SCHEMES, ["https", "http"]).
%% Toggle for the address denylist. Stays false until classify_address/1 is
%% implemented and AppSec-reviewed; see DEEP-DIVE TODO above.
-define(ENFORCE_ADDRESS_POLICY, false).

guard_urls(_Body, #{paths := Paths} = Acc) ->
    case check_urls(Paths) of
        ok -> {ok, Acc};
        {error, _, _} = Err -> Err
    end.

check_urls([]) ->
    ok;
check_urls([{_Key, Url} | Rest]) ->
    case url_allowed(Url) of
        ok -> check_urls(Rest);
        {error, _, _} = Err -> Err
    end.

%% Single per-URL policy check. Scheme is already constrained by parse_url/1;
%% the address policy is the skeleton's extension point.
url_allowed(#{scheme := Scheme} = Url) ->
    case lists:member(Scheme, ?ALLOWED_SCHEMES) of
        false ->
            {error, input_invalid, ?REASON_URL_NOT_ALLOWED};
        true ->
            case ?ENFORCE_ADDRESS_POLICY of
                false ->
                    ok;
                true ->
                    %% classify_address/1 is the deep-dive hook: it must map the
                    %% host (literal IP, or -- carefully -- a resolved address)
                    %% to allow|deny per the metadata/link-local/private policy.
                    case classify_address(Url) of
                        allow -> ok;
                        deny -> {error, input_invalid, ?REASON_URL_NOT_ALLOWED}
                    end
            end
    end.

%% DEEP-DIVE HOOK -- not yet implemented. Intentionally returns `allow' for
%% every host so the skeleton is inert until the policy is designed. Do NOT
%% enable ?ENFORCE_ADDRESS_POLICY until this classifies link-local
%% (169.254.0.0/16, fe80::/10), the IMDS address (169.254.169.254), loopback,
%% and the configured private-range policy.
classify_address(_Url) ->
    allow.

%%--------------------------------------------------------------------
%% Reachability probe (network)
%%--------------------------------------------------------------------
%%
%% SKELETON -- not yet implemented. The shape this will take:
%%   * Resolve cacertfile_arn (if any) via resolve_arn/1, under the ARN lock.
%%   * Build httpc ssl options from ssl_options (build_ssl_opts/1, the same
%%     verify/cacerts/sni shaping as the LDAP backend but wrapped as
%%     {ssl, Opts} for httpc rather than eldap sslopts), applying
%%     rabbit_ssl_options:fix_client/1 to match the real backend (R11/R12).
%%   * For each configured path, issue ONE request with the configured method
%%     (autoredirect=false, bounded timeout) and map the outcome:
%%       - transport error / econnrefused / nxdomain -> connection_failed
%%       - TLS/cert error                            -> tls_failed
%%       - any well-formed HTTP status               -> reachable (ok)
%%       - malformed / no HTTP response              -> auth_failed (endpoint)
%%   * Wrap the whole probe in a try/catch that collapses any raise to
%%     connection_failed, so a resolved secret (future credentialed mode) can
%%     never reach a crash report (R6).
%%
%% Returning ok unconditionally for now would be a false pass, so the skeleton
%% returns a fixed connection_failed until the probe is implemented. This keeps
%% the method safe to register behind its (default-disabled) enable flag
%% without ever reporting a misleading success.
do_http_validate(#{paths := _Paths} = _Params) ->
    %% TODO(http-validation): implement the reachability probe described above.
    {error, connection_failed, ?REASON_CONNECTION}.

%%--------------------------------------------------------------------
%% Shared helpers (mirror the LDAP backend)
%%--------------------------------------------------------------------

is_nonempty_binary(B) -> is_binary(B) andalso byte_size(B) > 0.

%% ARN resolution mutates the shared rabbitmq_aws region/credential singleton,
%% so serialize it across concurrent validations. Reused verbatim from the LDAP
%% backend's contract; will be called by the probe to resolve cacertfile_arn.
-spec resolve_arn(binary()) -> {ok, binary()} | {error, term()}.
resolve_arn(Arn) when is_binary(Arn) ->
    aws_auth_validate_arn_lock:with_lock(fun() ->
        aws_arn_util:resolve_arn(binary_to_list(Arn))
    end).

connection_timeout_ms() ->
    case application:get_env(aws, auth_validation_connection_timeout_ms) of
        {ok, Ms} when is_integer(Ms), Ms > 0 -> Ms;
        _ -> ?DEFAULT_TIMEOUT_MS
    end.
