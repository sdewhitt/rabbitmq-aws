-module(aws_lib_all_tests).

-export([run/0]).

-include_lib("eunit/include/eunit.hrl").

run() ->
    Result = {
        eunit:test(aws_lib_app_tests, [verbose]),
        eunit:test(aws_lib_config_tests, [verbose]),
        eunit:test(aws_lib_json_tests, [verbose]),
        eunit:test(aws_lib_sign_tests, [verbose]),
        eunit:test(aws_lib_sup_tests, [verbose]),
        eunit:test(aws_lib_tests, [verbose]),
        eunit:test(aws_lib_uri_tests, [verbose]),
        eunit:test(aws_lib_xml_tests, [verbose])
    },
    ?assertEqual({ok, ok, ok, ok, ok, ok, ok, ok}, Result).
