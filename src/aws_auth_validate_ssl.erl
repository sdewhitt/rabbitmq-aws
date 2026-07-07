%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% Shared TLS-material, ARN-resolution, and assume-role helpers for the auth
%% validation backends (ldap / http / oauth).
%%
%% Before this module each backend carried its own byte-identical copy of the
%% ARN resolver, the assume-role guardrail, the cacert/client-cert PEM decoders,
%% the ssl_options value validators, and the verify/version/depth translators.
%% Three separate copies meant a security fix (e.g. the cacerts-DER fix, the
%% assume_role guardrail) had to be applied three times or silently drift. This
%% module is the single home for that logic; each backend now delegates.
%%
%% Backend-specific surface differences (LDAP has no client cert and uses the
%% `server_name_indication' key; HTTP/OAuth carry the mTLS pair and the `sni'
%% key) are absorbed by an options map passed to the parsing entry points, so
%% the behaviour is identical where the backends agree and explicit where they
%% differ.
%%
%% Security invariants preserved verbatim from the original copies:
%%   * R6 -- a resolved secret (password / PEM) is never logged or returned;
%%     resolve_arn/2 adapts aws_arn_util's 3-tuple to {ok, Binary} and discards
%%     the threaded state.
%%   * assume_role guardrail -- resolving any ARN requires a configured
%%     aws.arns.assume_role_arn; the broker instance role is never used.
%%   * cacerts DER -- decode_pem_cacerts/1 returns raw 'Certificate' DER, not
%%     pem_entry_decode/1 records (ssl silently ignores the latter under
%%     {cacerts,_} -> unknown_ca -> spurious tls_failed).
-module(aws_auth_validate_ssl).

-export([
    %% assume-role / request state
    configured_assume_role_arn/0,
    resolve_request_state/2,
    resolve_arn/2,
    %% ssl_options parsing (pure phase)
    parse_ssl_options/3,
    valid_ssl_value/3,
    %% TLS-material resolution + translation (network phase)
    resolve_cacerts/2,
    resolve_client_cert/2,
    decode_pem_cacerts/1,
    decode_client_cert/1,
    decode_client_key/1,
    translate_ssl_opts/2,
    apply_verify_default/2,
    ensure_trust_anchor/1,
    trust_source/1,
    os_cacerts/0,
    %% value translators (shared by all three backends)
    to_verify/1,
    to_version/1,
    to_versions/1,
    to_integer/1,
    to_list/1,
    %% httpc error classification
    classify_http_error/3,
    is_tls_error/1,
    %% misc shared helpers
    connection_timeout_ms/1,
    is_nonempty_binary/1
]).

%% Accepted values for `verify' and `versions', shared by all backends.
-define(SSL_VERIFY_VALUES, [<<"verify_peer">>, <<"verify_none">>]).
-define(SSL_VERSION_VALUES, [
    <<"tlsv1.3">>,
    <<"tlsv1.2">>,
    <<"tlsv1.1">>,
    <<"tlsv1">>
]).

%% opts() is the per-backend surface description supplied by the caller. Fields:
%%   arn_keys   :: [binary()] -- ssl_options keys that reference an ARN (a
%%                 request touching any of these must assume a role).
%%   sni_key    :: binary()   -- the customer-facing SNI key (<<"sni">> for
%%                 http/oauth, <<"server_name_indication">> for ldap).
%%   client_cert :: boolean() -- whether the mTLS cert/key pair is accepted.
%%   reasons    :: map()      -- backend-specific fixed reason binaries, keyed by
%%                 the atoms below (so each backend keeps its own wording/R4
%%                 contract). See reason/2.
-type opts() :: #{
    arn_keys := [binary()],
    ssl_option_keys := [binary()],
    sni_key := binary(),
    client_cert := boolean(),
    reasons := map()
}.

-export_type([opts/0]).

%%--------------------------------------------------------------------
%% assume-role / request state
%%--------------------------------------------------------------------

%% The operator-configured boot-time assume role (aws.arns.assume_role_arn),
%% read from the same `aws, arn_config' env the boot sequence uses
%% (aws_arn_config:maybe_assume_role/1). Returns the role ARN string, or `none'
%% when unset.
-spec configured_assume_role_arn() -> string() | none.
configured_assume_role_arn() ->
    case application:get_env(aws, arn_config) of
        {ok, ArnConfig} when is_list(ArnConfig) ->
            case proplists:get_value(assume_role_arn, ArnConfig) of
                undefined -> none;
                Arn when is_list(Arn) -> Arn;
                Arn when is_binary(Arn) -> binary_to_list(Arn);
                _ -> none
            end;
        _ ->
            none
    end.

%% Build the per-request aws_lib state used for every ARN fetch in this request,
%% and thread it into Params under `aws_state'. MustAssume indicates whether the
%% request references any ARN (true = a fetch will occur, so a role is required).
%%
%% When a role is required and configured, we assume it into a request-local
%% aws_lib state -- the SAME role the plugin assumes at boot -- and resolve ARNs
%% under it. This is operator config, not caller input, so no confused-deputy.
%% When required but NOT configured, refuse with config_conflict rather than fall
%% back to the broker's ambient EC2 instance role (a least-privilege pitfall).
%% When not required (no ARN referenced), thread a default state that is never
%% used to resolve an ARN, preserving the credential-free reachability check.
-spec resolve_request_state(map(), opts()) ->
    {ok, map()} | {error, aws_auth_validate_backend:error_category(), binary()}.
resolve_request_state(Params, Opts) ->
    case request_references_arn(Params, Opts) of
        false ->
            {ok, Params#{aws_state => aws_lib:new()}};
        true ->
            case configured_assume_role_arn() of
                none ->
                    {error, config_conflict, reason(no_assume_role, Opts)};
                RoleArn ->
                    case aws_iam:assume_role(RoleArn, aws_lib:new()) of
                        {ok, State} -> {ok, Params#{aws_state => State}};
                        {error, _} -> {error, input_invalid, reason(assume_role, Opts)}
                    end
            end
    end.

%% True when the request references any ARN-backed TLS material under
%% ssl_options, i.e. resolving the request will make at least one AWS call.
request_references_arn(#{ssl_options := Map}, #{arn_keys := Keys}) ->
    lists:any(fun(K) -> maps:is_key(K, Map) end, Keys);
request_references_arn(_Params, _Opts) ->
    false.

%% Resolve an ARN using the request's threaded aws_state(). The 3-tuple
%% {ok, Data, State1} from aws_arn_util:resolve_arn/2 is adapted back to the
%% {ok, Binary} contract callers expect; the threaded state is request-scoped
%% and discarded here. R6: the resolved secret is neither logged nor returned.
%%
%% Fail closed on the `none' sentinel: a request that referenced no ARN carries
%% aws_state => none (a no-ARN branch), and must never resolve an ARN -- doing so
%% under aws_lib's default credential chain could reach the broker's EC2 instance
%% role. Refusing here turns any such path into a fixed-category error rather than
%% an instance-role fetch. A credentialed state is only ever produced by
%% resolve_request_state/2's assume_role path.
-spec resolve_arn(binary(), aws_lib:aws_state() | none) -> {ok, binary()} | {error, term()}.
resolve_arn(_Arn, none) ->
    {error, no_credentials_state};
resolve_arn(Arn, State) when is_binary(Arn) ->
    case aws_arn_util:resolve_arn(binary_to_list(Arn), State) of
        {ok, Data, _State1} -> {ok, Data};
        {error, _} = Error -> Error
    end.

%%--------------------------------------------------------------------
%% ssl_options parsing (pure phase)
%%--------------------------------------------------------------------

%% Validate the ssl_options object: unknown-key rejection, the mTLS both-or-
%% neither pairing (when client_cert is enabled), and every value's shape/domain.
%% Stores the original map unchanged under `ssl_options' (translation happens
%% later). SslOptionKeys is the allowed-key list for this backend.
-spec parse_ssl_options(term(), map(), opts()) ->
    {ok, map()} | {error, aws_auth_validate_backend:error_category(), binary()}.
parse_ssl_options(undefined, Acc, _Opts) ->
    {ok, Acc#{ssl_options => #{}}};
parse_ssl_options(Map, Acc, #{ssl_option_keys := Keys} = Opts) when is_map(Map) ->
    case [K || K <- maps:keys(Map), not lists:member(K, Keys)] of
        [_ | _] ->
            {error, input_invalid, reason(unknown_ssl_option, Opts)};
        [] ->
            case client_cert_pairing_ok(Map, Opts) of
                false -> {error, input_invalid, reason(client_cert_incomplete, Opts)};
                true -> validate_ssl_values(maps:to_list(Map), Acc, Map, Opts)
            end
    end;
parse_ssl_options(_Other, _Acc, Opts) ->
    {error, input_invalid, reason(bad_ssl_options, Opts)}.

%% Client cert + key are an inseparable pair: one without the other cannot build
%% an mTLS identity. Only enforced for backends that accept client certs.
client_cert_pairing_ok(Map, #{client_cert := true}) ->
    maps:is_key(<<"certfile_arn">>, Map) =:= maps:is_key(<<"keyfile_arn">>, Map);
client_cert_pairing_ok(_Map, _Opts) ->
    true.

validate_ssl_values([], Acc, Map, _Opts) ->
    {ok, Acc#{ssl_options => Map}};
validate_ssl_values([{Key, Value} | Rest], Acc, Map, Opts) ->
    case valid_ssl_value(Key, Value, Opts) of
        ok -> validate_ssl_values(Rest, Acc, Map, Opts);
        {error, _, _} = Err -> Err
    end.

%% Validate one ssl_options value for shape/domain. The `sni' key is spelled
%% differently per backend (Opts.sni_key), so it is matched dynamically.
-spec valid_ssl_value(binary(), term(), opts()) ->
    ok | {error, aws_auth_validate_backend:error_category(), binary()}.
valid_ssl_value(<<"verify">>, V, Opts) ->
    case lists:member(V, ?SSL_VERIFY_VALUES) of
        true -> ok;
        false -> {error, input_invalid, reason(bad_ssl_verify, Opts)}
    end;
valid_ssl_value(<<"depth">>, V, _Opts) when is_integer(V), V >= 0 ->
    ok;
valid_ssl_value(<<"depth">>, _V, Opts) ->
    {error, input_invalid, reason(bad_ssl_depth, Opts)};
valid_ssl_value(<<"versions">>, V, Opts) when is_list(V), V =/= [] ->
    case lists:all(fun(Ver) -> lists:member(Ver, ?SSL_VERSION_VALUES) end, V) of
        true -> ok;
        false -> {error, input_invalid, reason(bad_ssl_versions, Opts)}
    end;
valid_ssl_value(<<"versions">>, _V, Opts) ->
    {error, input_invalid, reason(bad_ssl_versions, Opts)};
valid_ssl_value(<<"cacertfile_arn">>, V, Opts) ->
    nonempty_or(V, bad_ssl_cacert_arn, Opts);
valid_ssl_value(<<"certfile_arn">>, V, Opts) ->
    nonempty_or(V, bad_ssl_cert_arn, Opts);
valid_ssl_value(<<"keyfile_arn">>, V, Opts) ->
    nonempty_or(V, bad_ssl_key_arn, Opts);
valid_ssl_value(Key, V, #{sni_key := Key} = Opts) ->
    %% The SNI key (backend-specific spelling): a non-empty string.
    nonempty_or(V, bad_ssl_sni, Opts).

nonempty_or(V, ReasonKey, Opts) ->
    case is_nonempty_binary(V) of
        true -> ok;
        false -> {error, input_invalid, reason(ReasonKey, Opts)}
    end.

%%--------------------------------------------------------------------
%% TLS-material resolution (network phase)
%%--------------------------------------------------------------------

%% Resolve ssl_options.cacertfile_arn to the raw-DER cacerts ssl option (or [] if
%% absent / no cert entries). Any resolve failure -> input_invalid (fixed reason).
-spec resolve_cacerts(term(), aws_lib:aws_state()) ->
    {ok, list()} | {error, aws_auth_validate_backend:error_category(), binary()}.
resolve_cacerts(undefined, _State) ->
    {ok, []};
resolve_cacerts(Arn, State) when is_binary(Arn) ->
    case resolve_arn(Arn, State) of
        {ok, Pem} ->
            case decode_pem_cacerts(Pem) of
                skip -> {ok, []};
                Certs -> {ok, [{cacerts, Certs}]}
            end;
        {error, _} ->
            {error, input_invalid, generic_arn_resolve()}
    end.

%% Resolve the client certificate + private key for mutual TLS. parse_ssl_options
%% already guaranteed both are present or both absent, so here we either resolve
%% the pair or return no client-auth options.
-spec resolve_client_cert(map(), aws_lib:aws_state()) ->
    {ok, list()} | {error, aws_auth_validate_backend:error_category(), binary()}.
resolve_client_cert(#{<<"certfile_arn">> := CertArn, <<"keyfile_arn">> := KeyArn}, State) when
    is_binary(CertArn), is_binary(KeyArn)
->
    case resolve_arn(CertArn, State) of
        {ok, CertPem} ->
            case decode_client_cert(CertPem) of
                {error, _, _} = Err ->
                    Err;
                {ok, CertOpt} ->
                    case resolve_arn(KeyArn, State) of
                        {ok, KeyPem} ->
                            case decode_client_key(KeyPem) of
                                {error, _, _} = Err -> Err;
                                {ok, KeyOpt} -> {ok, [CertOpt, KeyOpt]}
                            end;
                        {error, _} ->
                            {error, input_invalid, generic_arn_resolve()}
                    end
            end;
        {error, _} ->
            {error, input_invalid, generic_arn_resolve()}
    end;
resolve_client_cert(_Map, _State) ->
    {ok, []}.

%% Decode a CA-bundle PEM into the raw 'Certificate' DER binaries ssl's
%% {cacerts,_} expects. Passing pem_entry_decode/1 records makes ssl silently
%% ignore the anchor -> unknown_ca -> spurious tls_failed. `skip' when the data
%% holds no certificate entries.
-spec decode_pem_cacerts(binary()) -> skip | [binary()].
decode_pem_cacerts(B) when is_binary(B) ->
    case [Der || {'Certificate', Der, not_encrypted} <- public_key:pem_decode(B)] of
        [] -> skip;
        Ders -> Ders
    end.

%% Decode a client-certificate PEM into an ssl {cert, [DER]} option. A PEM with
%% no certificate entry is a resolution-shaped failure (fixed ARN category).
-spec decode_client_cert(binary()) ->
    {ok, {cert, [binary()]}} | {error, aws_auth_validate_backend:error_category(), binary()}.
decode_client_cert(Pem) when is_binary(Pem) ->
    case [Der || {'Certificate', Der, not_encrypted} <- public_key:pem_decode(Pem)] of
        [] -> {error, input_invalid, generic_arn_resolve()};
        Ders -> {ok, {cert, Ders}}
    end.

%% Decode a private-key PEM into an ssl {key, {Asn1Type, DER}} option. An
%% encrypted or absent key is a fixed ARN-category failure.
-spec decode_client_key(binary()) ->
    {ok, {key, {atom(), binary()}}}
    | {error, aws_auth_validate_backend:error_category(), binary()}.
decode_client_key(Pem) when is_binary(Pem) ->
    KeyEntries = [
        {Type, Der}
     || {Type, Der, not_encrypted} <- public_key:pem_decode(Pem),
        lists:member(Type, [
            'PrivateKeyInfo', 'RSAPrivateKey', 'ECPrivateKey', 'DSAPrivateKey'
        ])
    ],
    case KeyEntries of
        [{Type, Der} | _] -> {ok, {key, {Type, Der}}};
        [] -> {error, input_invalid, generic_arn_resolve()}
    end.

%% Translate the non-cacert ssl_options keys into an ssl proplist. SniKey is the
%% backend's customer-facing SNI key spelling; it always maps to the ssl
%% `server_name_indication' atom.
-spec translate_ssl_opts(map(), binary()) -> list().
translate_ssl_opts(Map, SniKey) ->
    Pairs = [
        {verify, <<"verify">>, fun to_verify/1},
        {depth, <<"depth">>, fun to_integer/1},
        {versions, <<"versions">>, fun to_versions/1},
        {server_name_indication, SniKey, fun to_list/1}
    ],
    lists:foldl(
        fun({SslKey, JsonKey, Fun}, Acc) ->
            case maps:get(JsonKey, Map, undefined) of
                undefined -> Acc;
                Value -> [{SslKey, Fun(Value)} | Acc]
            end
        end,
        [],
        Pairs
    ).

%% Ensure verify_peer always has a trust anchor. VerifyExplicit governs the
%% no-anchor policy: an EXPLICIT verify_peer with no anchor FAILS (never silently
%% downgraded -- the false-positive this endpoint exists to prevent); a DEFAULTED
%% verify falls back to verify_none; an explicit verify_none is untouched; and
%% when verify is absent we default to verify_peer only if an anchor exists.
-spec apply_verify_default(list(), boolean()) ->
    {ok, list()} | {error, aws_auth_validate_backend:error_category(), binary()}.
apply_verify_default(Opts, VerifyExplicit) ->
    case lists:keyfind(verify, 1, Opts) of
        {verify, verify_peer} when VerifyExplicit ->
            case ensure_trust_anchor(Opts) of
                {ok, _} = Ok -> Ok;
                none -> {error, tls_failed, no_trust_anchor()}
            end;
        {verify, verify_peer} ->
            case ensure_trust_anchor(Opts) of
                {ok, Opts1} -> {ok, Opts1};
                none -> {ok, lists:keyreplace(verify, 1, Opts, {verify, verify_none})}
            end;
        {verify, _Other} ->
            {ok, Opts};
        false ->
            case ensure_trust_anchor(Opts) of
                {ok, Opts1} -> {ok, [{verify, verify_peer} | Opts1]};
                none -> {ok, Opts}
            end
    end.

%% Return {ok, OptsWithAnchor} when a trust anchor is present or can be sourced
%% from the OS store, else `none'. (trust_source/1 is the historical LDAP name
%% for the same behaviour; kept as an alias for that backend's call site.)
-spec ensure_trust_anchor(list()) -> {ok, list()} | none.
ensure_trust_anchor(Opts) ->
    case lists:keymember(cacerts, 1, Opts) of
        true ->
            {ok, Opts};
        false ->
            case os_cacerts() of
                [] -> none;
                Certs -> {ok, [{cacerts, Certs} | Opts]}
            end
    end.

-spec trust_source(list()) -> {ok, list()} | none.
trust_source(Opts) ->
    ensure_trust_anchor(Opts).

os_cacerts() ->
    try
        public_key:cacerts_get()
    catch
        _:_ -> []
    end.

%%--------------------------------------------------------------------
%% httpc error classification
%%--------------------------------------------------------------------

%% Map an httpc transport error to a fixed category: a TLS/cert failure is
%% tls_failed (with TlsReason), everything else connection_failed (ConnReason).
%% The raw reason is never echoed (R4).
-spec classify_http_error(term(), binary(), binary()) ->
    {error, tls_failed | connection_failed, binary()}.
classify_http_error(Reason, TlsReason, ConnReason) ->
    case is_tls_error(Reason) of
        true -> {error, tls_failed, TlsReason};
        false -> {error, connection_failed, ConnReason}
    end.

%% Recursively scan an httpc error term for the markers of a TLS-layer failure.
-spec is_tls_error(term()) -> boolean().
is_tls_error(Term) when is_tuple(Term) ->
    case element(1, Term) of
        tls_alert -> true;
        Other when is_atom(Other) -> is_tls_atom(Other) orelse is_tls_error(tuple_to_list(Term));
        _ -> is_tls_error(tuple_to_list(Term))
    end;
is_tls_error([H | T]) ->
    is_tls_error(H) orelse is_tls_error(T);
is_tls_error(Atom) when is_atom(Atom) ->
    is_tls_atom(Atom);
is_tls_error(_) ->
    false.

is_tls_atom(A) ->
    lists:member(A, [
        tls_alert,
        certificate_expired,
        bad_certificate,
        unknown_ca,
        handshake_failure,
        certificate_unknown,
        no_peercert
    ]).

%%--------------------------------------------------------------------
%% Value translators (total over the pure-phase-validated domain)
%%--------------------------------------------------------------------

to_list(B) when is_binary(B) -> binary_to_list(B);
to_list(L) when is_list(L) -> L.

to_integer(I) when is_integer(I) -> I.

to_verify(<<"verify_peer">>) -> verify_peer;
to_verify(<<"verify_none">>) -> verify_none.

to_versions(L) when is_list(L) ->
    [to_version(V) || V <- L].

to_version(<<"tlsv1.3">>) -> 'tlsv1.3';
to_version(<<"tlsv1.2">>) -> 'tlsv1.2';
to_version(<<"tlsv1.1">>) -> 'tlsv1.1';
to_version(<<"tlsv1">>) -> tlsv1.

%%--------------------------------------------------------------------
%% Misc shared helpers
%%--------------------------------------------------------------------

is_nonempty_binary(B) -> is_binary(B) andalso byte_size(B) > 0.

%% Per-request connection timeout (ms), read from aws env. Bounded to
%% (0, MaxMs]; anything out of range falls back to Default. A shared cap
%% prevents an operator-set timeout from pinning a semaphore slot indefinitely.
-spec connection_timeout_ms(#{default := pos_integer(), max := pos_integer()}) -> pos_integer().
connection_timeout_ms(#{default := Default, max := Max}) ->
    case application:get_env(aws, auth_validation_connection_timeout_ms) of
        {ok, Ms} when is_integer(Ms), Ms > 0, Ms =< Max -> Ms;
        _ -> Default
    end.

%%--------------------------------------------------------------------
%% Reason lookup
%%--------------------------------------------------------------------

%% Fetch a backend-specific fixed reason binary. Each backend supplies its own
%% wording (preserving its R4 response contract and existing tests) via the
%% reasons map in opts().
reason(Key, #{reasons := Reasons}) ->
    maps:get(Key, Reasons).

%% The generic ARN-resolve reason. resolve_cacerts/2, resolve_client_cert/2, and
%% the PEM decoders all report the same fixed string across backends (all three
%% originals used <<"failed to resolve ARN">> in these paths).
generic_arn_resolve() ->
    <<"failed to resolve ARN">>.

no_trust_anchor() ->
    <<"verify_peer requested but no CA trust anchor is available; supply cacertfile_arn">>.
