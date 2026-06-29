%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%%% A leex lexer for the rabbitmq_auth_backend_ldap authorization query DSL.
%%%
%%% This is a near-verbatim copy of hex_core's safe_erl_term.xrl (Apache-2.0,
%%% author Robert Virding), renamed to avoid a module clash with the
%%% safe_erl_term module hex_core ships in the same release. Its defining
%%% property, and the reason we use it here instead of erl_scan:string/1, is
%%% tokenize_atom/2: it interns nothing -- it resolves atoms with
%%% list_to_existing_atom/1 and returns {error, ...} for an atom that does not
%%% already exist. erl_scan:string/1 calls list_to_atom/1 unconditionally, so
%%% scanning an attacker-controlled query through it permanently adds an atom
%%% per distinct identifier, an unbounded resource the VM never reclaims (the
%%% atom table is capped, default ~1M). Routing the query DSL through this
%%% lexer closes that exhaustion vector: a query referencing an atom the broker
%%% has never interned (a typo'd keyword or an unknown tag) is rejected rather
%%% than minting the atom. A running broker has already interned the full
%%% legitimate vocabulary (grammar keywords, the configure/write/read
%%% permissions, the for-query variable names, the in_group_nested scopes, and
%%% every configured user tag), so legitimate queries are unaffected.

Definitions.

D = [0-9]
U = [A-Z]
L = [a-z]
A = ({U}|{L}|{D}|_|@)
WS = ([\000-\s])

Rules.

{L}{A}*             : tokenize_atom(TokenChars, TokenLine).
'(\\\^.|\\.|[^'])*' : tokenize_atom(escape(unquote(TokenChars, TokenLen)), TokenLine).
"(\\\^.|\\.|[^"])*" : {token, {string, TokenLine, escape(unquote(TokenChars, TokenLen))}}.
{D}+                : {token, {integer, TokenLine, list_to_integer(TokenChars)}}.
[\#\[\]}{,+-]       : {token, {list_to_atom(TokenChars), TokenLine}}.
(<<|>>|=>)          : {token, {list_to_atom(TokenChars), TokenLine}}.
\.                  : {token, {dot, TokenLine}}.
/                   : {token, {'/', TokenLine}}.
{WS}+               : skip_token.

Erlang code.

-export([terms/1]).

terms(Tokens) ->
  terms(Tokens, []).

terms([{dot, _} = H], Buffer) ->
  [buffer_to_term([H|Buffer])];
terms([{dot, _} = H|T], Buffer) ->
  [buffer_to_term([H|Buffer])|terms(T, [])];
terms([H|T], Buffer) ->
  terms(T, [H|Buffer]).

buffer_to_term(Buffer) ->
  {ok, Term} = erl_parse:parse_term(lists:reverse(Buffer)),
  Term.

unquote(TokenChars, TokenLen) ->
  lists:sublist(TokenChars, 2, TokenLen - 2).

tokenize_atom(TokenChars, TokenLine) ->
  try list_to_existing_atom(TokenChars) of
    Atom -> {token, {atom, TokenLine, Atom}}
  catch
    error:badarg -> {error, "illegal atom " ++ TokenChars}
  end.

escape([$\\|Cs]) ->
  do_escape(Cs);
escape([C|Cs]) ->
  [C|escape(Cs)];
escape([]) -> [].

do_escape([O1,O2,O3|S]) when
    O1 >= $0, O1 =< $7, O2 >= $0, O2 =< $7, O3 >= $0, O3 =< $7 ->
  [(O1*8 + O2)*8 + O3 - 73*$0|escape(S)];
do_escape([$^,C|Cs]) ->
  [C band 31|escape(Cs)];
do_escape([C|Cs]) when C >= $\000, C =< $\s ->
  escape(Cs);
do_escape([C|Cs]) ->
  [escape_char(C)|escape(Cs)].

escape_char($n) -> $\n;       %\n = LF
escape_char($r) -> $\r;       %\r = CR
escape_char($t) -> $\t;       %\t = TAB
escape_char($v) -> $\v;       %\v = VT
escape_char($b) -> $\b;       %\b = BS
escape_char($f) -> $\f;       %\f = FF
escape_char($e) -> $\e;       %\e = ESC
escape_char($s) -> $\s;       %\s = SPC
escape_char($d) -> $\d;       %\d = DEL
escape_char(C) -> C.
