-module(aws_lib_uri_tests).

-include_lib("eunit/include/eunit.hrl").

%% parse/1 returns {ok, uri()}; these tests read the uri() only through the
%% public accessors (host/1, port/1, path/1, query/1, target/1), never by
%% inspecting the underlying representation.
parse_accessors_test_() ->
    [
        {"userinfo, explicit port, path and query", fun() ->
            {ok, U} = aws_lib_uri:parse("amqp://guest:password@rabbitmq:5672/%2F?heartbeat=5"),
            ?assertEqual("rabbitmq", aws_lib_uri:host(U)),
            ?assertEqual(5672, aws_lib_uri:port(U)),
            ?assertEqual("/%2F", aws_lib_uri:path(U)),
            ?assertEqual([{"heartbeat", "5"}], aws_lib_uri:query(U))
        end},
        {"http defaults the port to 80", fun() ->
            {ok, U} = aws_lib_uri:parse("http://www.google.com/search?foo=bar#baz"),
            ?assertEqual("www.google.com", aws_lib_uri:host(U)),
            ?assertEqual(80, aws_lib_uri:port(U)),
            ?assertEqual("/search", aws_lib_uri:path(U)),
            ?assertEqual([{"foo", "bar"}], aws_lib_uri:query(U))
        end},
        {"https defaults the port to 443", fun() ->
            {ok, U} = aws_lib_uri:parse("https://www.google.com/search"),
            ?assertEqual("www.google.com", aws_lib_uri:host(U)),
            ?assertEqual(443, aws_lib_uri:port(U)),
            ?assertEqual("/search", aws_lib_uri:path(U))
        end},
        {"a query-less URI has an empty query proplist", fun() ->
            {ok, U} = aws_lib_uri:parse("https://www.google.com/search"),
            ?assertEqual([], aws_lib_uri:query(U))
        end},
        {"an empty path is normalized to /", fun() ->
            {ok, U} = aws_lib_uri:parse("https://example.com"),
            ?assertEqual("/", aws_lib_uri:path(U))
        end}
    ].

%% target/1 is the request line: path with the raw query reattached.
target_test_() ->
    [
        {"path only when there is no query", fun() ->
            {ok, U} = aws_lib_uri:parse("https://s3.amazonaws.com/bucket/key"),
            ?assertEqual("/bucket/key", aws_lib_uri:target(U))
        end},
        {"path with the query reattached", fun() ->
            {ok, U} = aws_lib_uri:parse(
                "https://ec2.us-east-1.amazonaws.com/?Action=DescribeTags&Version=2015-10-01"
            ),
            ?assertEqual("/?Action=DescribeTags&Version=2015-10-01", aws_lib_uri:target(U))
        end},
        {"the raw query is preserved byte-for-byte (percent-encoding intact)", fun() ->
            {ok, U} = aws_lib_uri:parse("https://h.example.com/x?k=a%2Fb&t=1"),
            ?assertEqual("/x?k=a%2Fb&t=1", aws_lib_uri:target(U))
        end}
    ].

%% Malformed input must return an error tuple, never crash (issue #100).
parse_malformed_test_() ->
    [
        {"scheme-less input is rejected", fun() ->
            ?assertEqual(
                {error, {malformed_uri, "www.google.com/search"}},
                aws_lib_uri:parse("www.google.com/search")
            )
        end},
        {"relative path is rejected", fun() ->
            ?assertEqual(
                {error, {malformed_uri, "/just/a/path"}},
                aws_lib_uri:parse("/just/a/path")
            )
        end},
        {"empty string is rejected", fun() ->
            ?assertEqual({error, {malformed_uri, ""}}, aws_lib_uri:parse(""))
        end}
    ].

compose_query_test_() ->
    [
        {"basic list", fun() ->
            ?assertEqual(
                "foo=bar&baz=qux",
                aws_lib_uri:compose_query([{"foo", "bar"}, {"baz", "qux"}])
            )
        end},
        {"non-string values are coerced", fun() ->
            ?assertEqual(
                "foo=true&n=5",
                aws_lib_uri:compose_query([{"foo", true}, {"n", 5}])
            )
        end},
        {"empty list", fun() ->
            ?assertEqual("", aws_lib_uri:compose_query([]))
        end}
    ].
