-module(aws_lib_httpc_tests).

-include_lib("eunit/include/eunit.hrl").

%% Direct unit tests for the Gun lifecycle boundary. gun is mocked so these pin
%% aws_lib_httpc's own contract (open wrapping, the await/await_body dance and
%% its error handling, one-shot open/close) independently of the callers that
%% exercise it transitively.

%%--------------------------------------------------------------------
%% open/3
%%--------------------------------------------------------------------

open_test_() ->
    {foreach,
        fun() ->
            meck:new(gun, []),
            [gun]
        end,
        fun meck:unload/1, [
            {"success returns the connection", fun() ->
                meck:expect(gun, open, fun(_, _, _) -> {ok, conn} end),
                meck:expect(gun, await_up, fun(_, _) -> {ok, http} end),
                ?assertEqual({ok, conn}, aws_lib_httpc:open("h", 80, #{}))
            end},
            {"open failure is wrapped as gun_open_failed", fun() ->
                meck:expect(gun, open, fun(_, _, _) -> {error, enetunreach} end),
                ?assertEqual(
                    {error, {gun_open_failed, enetunreach}},
                    aws_lib_httpc:open("h", 80, #{})
                )
            end},
            {"await_up failure is wrapped as gun_connection_failed and closes", fun() ->
                meck:expect(gun, open, fun(_, _, _) -> {ok, conn} end),
                meck:expect(gun, await_up, fun(_, _) -> {error, timeout} end),
                meck:expect(gun, close, fun(_) -> ok end),
                ?assertEqual(
                    {error, {gun_connection_failed, timeout}},
                    aws_lib_httpc:open("h", 80, #{})
                ),
                %% the socket opened by gun:open is torn down on await_up failure
                ?assertEqual(1, meck:num_calls(gun, close, [conn]))
            end}
        ]}.

%%--------------------------------------------------------------------
%% request/6 (on an already-open connection)
%%--------------------------------------------------------------------

request_on_conn_test_() ->
    {foreach,
        fun() ->
            meck:new(gun, []),
            [gun]
        end,
        fun meck:unload/1, [
            {"fin response yields an empty body", fun() ->
                meck:expect(gun, get, fun(_, _, _) -> stream end),
                meck:expect(gun, await, fun(_, _, _) -> {response, fin, 200, [{h, v}]} end),
                ?assertEqual(
                    {ok, {{http_version, 200, "OK"}, [{h, v}], <<>>}},
                    aws_lib_httpc:request(conn, get, "/", [], <<>>, 1000)
                )
            end},
            {"nofin response reads the body", fun() ->
                meck:expect(gun, get, fun(_, _, _) -> stream end),
                meck:expect(gun, await, fun(_, _, _) -> {response, nofin, 200, [{h, v}]} end),
                meck:expect(gun, await_body, fun(_, _, _) -> {ok, <<"payload">>} end),
                ?assertEqual(
                    {ok, {{http_version, 200, "OK"}, [{h, v}], <<"payload">>}},
                    aws_lib_httpc:request(conn, get, "/", [], <<>>, 1000)
                )
            end},
            {"await error is surfaced", fun() ->
                meck:expect(gun, get, fun(_, _, _) -> stream end),
                meck:expect(gun, await, fun(_, _, _) -> {error, timeout} end),
                ?assertEqual(
                    {error, timeout},
                    aws_lib_httpc:request(conn, get, "/", [], <<>>, 1000)
                )
            end},
            {"await_body error is surfaced, not a badmatch", fun() ->
                meck:expect(gun, get, fun(_, _, _) -> stream end),
                meck:expect(gun, await, fun(_, _, _) -> {response, nofin, 200, []} end),
                meck:expect(gun, await_body, fun(_, _, _) -> {error, timeout} end),
                ?assertEqual(
                    {error, timeout},
                    aws_lib_httpc:request(conn, get, "/", [], <<>>, 1000)
                )
            end},
            {"a raise is caught and returned as an error", fun() ->
                meck:expect(gun, get, fun(_, _, _) -> error(boom) end),
                ?assertEqual(
                    {error, boom},
                    aws_lib_httpc:request(conn, get, "/", [], <<>>, 1000)
                )
            end},
            {"string and binary headers are normalized to binaries", fun() ->
                Self = self(),
                meck:expect(gun, get, fun(_, _, Headers) ->
                    Self ! {headers, Headers},
                    stream
                end),
                meck:expect(gun, await, fun(_, _, _) -> {response, fin, 200, []} end),
                aws_lib_httpc:request(
                    conn, get, "/", [{"x-str", "v"}, {<<"x-bin">>, <<"w">>}], <<>>, 1000
                ),
                receive
                    {headers, H} ->
                        ?assertEqual([{<<"x-str">>, <<"v">>}, {<<"x-bin">>, <<"w">>}], H)
                after 1000 -> ?assert(false)
                end
            end},
            {"the method selects the matching gun function", fun() ->
                meck:expect(gun, put, fun(_, _, _, _, _) -> stream end),
                %% 200 is in aws_lib_response:status_text/1's table, so its reason phrase
                %% is a known string; this also exercises the put/5 dispatch.
                meck:expect(gun, await, fun(_, _, _) -> {response, fin, 200, []} end),
                ?assertEqual(
                    {ok, {{http_version, 200, "OK"}, [], <<>>}},
                    aws_lib_httpc:request(conn, put, "/", [], <<"body">>, 1000)
                ),
                ?assertEqual(1, meck:num_calls(gun, put, ['_', '_', '_', '_', '_']))
            end}
        ]}.

%%--------------------------------------------------------------------
%% request/7 (one-shot: open + request + close)
%%--------------------------------------------------------------------

one_shot_test_() ->
    {foreach,
        fun() ->
            meck:new(gun, []),
            [gun]
        end,
        fun meck:unload/1, [
            {"opens, requests, and closes on success", fun() ->
                meck:expect(gun, open, fun(_, _, _) -> {ok, conn} end),
                meck:expect(gun, await_up, fun(_, _) -> {ok, http} end),
                meck:expect(gun, get, fun(_, _, _) -> stream end),
                meck:expect(gun, await, fun(_, _, _) -> {response, fin, 200, []} end),
                meck:expect(gun, close, fun(_) -> ok end),
                ?assertEqual(
                    {ok, {{http_version, 200, "OK"}, [], <<>>}},
                    aws_lib_httpc:request("h", 80, get, "/", [], <<>>, #{})
                ),
                ?assertEqual(1, meck:num_calls(gun, close, [conn]))
            end},
            {"closes the connection even when the request errors", fun() ->
                meck:expect(gun, open, fun(_, _, _) -> {ok, conn} end),
                meck:expect(gun, await_up, fun(_, _) -> {ok, http} end),
                meck:expect(gun, get, fun(_, _, _) -> stream end),
                meck:expect(gun, await, fun(_, _, _) -> {error, timeout} end),
                meck:expect(gun, close, fun(_) -> ok end),
                ?assertEqual(
                    {error, timeout},
                    aws_lib_httpc:request("h", 80, get, "/", [], <<>>, #{})
                ),
                ?assertEqual(1, meck:num_calls(gun, close, [conn]))
            end},
            {"an open failure short-circuits without a request or close", fun() ->
                meck:expect(gun, open, fun(_, _, _) -> {error, enetunreach} end),
                ?assertEqual(
                    {error, {gun_open_failed, enetunreach}},
                    aws_lib_httpc:request("h", 80, get, "/", [], <<>>, #{})
                ),
                ?assertEqual(0, meck:num_calls(gun, close, '_'))
            end}
        ]}.
