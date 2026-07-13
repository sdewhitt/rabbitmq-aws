-module(aws_lib_response_tests).

-include_lib("eunit/include/eunit.hrl").

%% classify_response/2 decides retriability from the raw httpc result and its
%% formatted counterpart (issue #80): 5xx and 429 and throttling error codes
%% and transport errors are retriable; other 4xx and unfollowed 3xx are not.
classify_response_test_() ->
    Resp = fun(Status, ContentType, Body) ->
        {ok, {{http_version, Status, "msg"}, [{<<"content-type">>, ContentType}], Body}}
    end,
    Classify = fun(Response) ->
        aws_lib_response:classify_response(
            Response, aws_lib_response:format_response(Response)
        )
    end,
    [
        {"5xx is retriable", fun() ->
            ?assertEqual(retriable, Classify(Resp(503, <<"text/xml">>, <<>>)))
        end},
        {"429 is retriable", fun() ->
            ?assertEqual(retriable, Classify(Resp(429, <<"text/xml">>, <<>>)))
        end},
        {"a plain 4xx is not retriable", fun() ->
            ?assertEqual(
                not_retriable,
                Classify(
                    Resp(400, <<"application/json">>, <<"{\"__type\": \"InvalidParameterValue\"}">>)
                )
            )
        end},
        {"a 4xx throttling error code is retriable", fun() ->
            ?assertEqual(
                retriable,
                Classify(
                    Resp(400, <<"application/json">>, <<"{\"__type\": \"ThrottlingException\"}">>)
                )
            ),
            ?assertEqual(
                retriable,
                Classify(
                    Resp(400, <<"application/json">>, <<"{\"__type\": \"RequestLimitExceeded\"}">>)
                )
            )
        end},
        {"the botocore throttling code families are covered", fun() ->
            %% One representative per marker family from botocore's
            %% _THROTTLED_ERROR_CODES, plus the transient codes from its
            %% _TRANSIENT_ERROR_CODES (RequestTimeout, RequestTimeoutException,
            %% PriorRequestNotComplete) that botocore also retries.
            Codes = [
                "TooManyRequestsException",
                "ProvisionedThroughputExceededException",
                "TransactionInProgressException",
                "BandwidthLimitExceeded",
                "RequestThrottled",
                "SlowDown",
                "RequestTimeout",
                "RequestTimeoutException",
                "PriorRequestNotComplete"
            ],
            lists:foreach(
                fun(Code) ->
                    Body = iolist_to_binary(["{\"__type\": \"", Code, "\"}"]),
                    ?assertEqual(
                        retriable,
                        Classify(Resp(400, <<"application/json">>, Body))
                    )
                end,
                Codes
            )
        end},
        {"a namespaced throttling code matches case-insensitively", fun() ->
            %% Some services prefix the __type with a namespace and vary the
            %% casing; the marker match is a case-insensitive substring of the
            %% error code.
            ?assertEqual(
                retriable,
                Classify(
                    Resp(
                        400,
                        <<"application/json">>,
                        <<"{\"__type\": \"com.amazonaws.dynamodb#throttlingException\"}">>
                    )
                )
            )
        end},
        {"an XML error document Code is matched", fun() ->
            Body = <<
                "<ErrorResponse><Error><Code>Throttling</Code>"
                "<Message>Rate exceeded</Message></Error></ErrorResponse>"
            >>,
            ?assertEqual(retriable, Classify(Resp(400, <<"text/xml">>, Body)))
        end},
        {"an X-Amzn-Errortype header is consulted", fun() ->
            %% The JSON protocols allow the error type to arrive only in the
            %% X-Amzn-Errortype header (Smithy awsJson1.1 spec).
            Response =
                {ok, {
                    {http_version, 400, "msg"},
                    [
                        {<<"content-type">>, <<"application/json">>},
                        {<<"X-Amzn-Errortype">>, <<"ThrottlingException">>}
                    ],
                    <<"{\"message\": \"Rate exceeded\"}">>
                }},
            ?assertEqual(retriable, Classify(Response))
        end},
        {"a throttling marker outside the error code does not retry", fun() ->
            %% A marker inside a message or resource name must not trigger a
            %% retry; only the error-code fields are consulted.
            Body = <<
                "{\"__type\": \"ValidationException\","
                " \"message\": \"resource arn:aws:sns:us-east-1:1:ThrottlingAlarm\"}"
            >>,
            ?assertEqual(not_retriable, Classify(Resp(400, <<"application/json">>, Body)))
        end},
        {"an undecodable body is not substring-searched for markers", fun() ->
            %% An undecodable body (text/plain, text/html) carries no structured
            %% error code, so a marker in its text must not trigger a retry: a
            %% proxy or ALB 4xx error page containing `throttl' is a permanent
            %% error, not throttling.
            ?assertEqual(
                not_retriable,
                Classify(Resp(400, <<"text/plain">>, <<"Throttling: rate exceeded">>))
            ),
            ?assertEqual(
                not_retriable,
                Classify(Resp(400, <<"text/plain">>, <<"no such resource">>))
            )
        end},
        {"an undecodable body is retriable via its X-Amzn-Errortype header", fun() ->
            %% The status rules aside, an undecodable body still retries when the
            %% throttling code arrives in the X-Amzn-Errortype header.
            Response =
                {ok, {
                    {http_version, 400, "msg"},
                    [
                        {<<"content-type">>, <<"text/plain">>},
                        {<<"X-Amzn-Errortype">>, <<"ThrottlingException">>}
                    ],
                    <<"Throttling: rate exceeded">>
                }},
            ?assertEqual(retriable, Classify(Response))
        end},
        {"a non-string value under an error-code key does not crash", fun() ->
            %% An object under `code' is collected as a candidate value; it is
            %% not chardata, so the marker match rejects it instead of raising.
            Body = <<"{\"code\": {\"inner\": \"Throttling\"}, \"other\": 1}">>,
            ?assertEqual(not_retriable, Classify(Resp(400, <<"application/json">>, Body)))
        end},
        {"a 403 access-denied is not retriable", fun() ->
            ?assertEqual(
                not_retriable,
                Classify(Resp(403, <<"application/json">>, <<"{\"__type\": \"AccessDenied\"}">>))
            )
        end},
        {"an unfollowed 3xx is not retriable", fun() ->
            ?assertEqual(not_retriable, Classify(Resp(302, <<"text/xml">>, <<>>)))
        end},
        {"a transport error is retriable", fun() ->
            ?assertEqual(retriable, Classify({error, timeout}))
        end},
        {"a 2xx success stays total", fun() ->
            ?assertEqual(retriable, Classify(Resp(200, <<"application/json">>, <<"{}">>)))
        end}
    ].

format_response_test_() ->
    [
        {"ok", fun() ->
            Response =
                {ok, {
                    {"HTTP/1.1", 200, "Ok"},
                    [{<<"Content-Type">>, <<"text/xml">>}],
                    "<test>Value</test>"
                }},
            Expectation = {ok, {[{<<"Content-Type">>, <<"text/xml">>}], [{"test", "Value"}]}},
            ?assertEqual(Expectation, aws_lib_response:format_response(Response))
        end},
        {"error", fun() ->
            Response =
                {ok, {
                    {"HTTP/1.1", 500, "Internal Server Error"},
                    [{"Content-Type", "text/xml"}],
                    "<error>Boom</error>"
                }},
            Expectation =
                {error, "Internal Server Error",
                    {[{"Content-Type", "text/xml"}], [{"error", "Boom"}]}},
            ?assertEqual(Expectation, aws_lib_response:format_response(Response))
        end},
        {"201 Created is a success", fun() ->
            Response =
                {ok, {
                    {"HTTP/1.1", 201, "Created"},
                    [{<<"Content-Type">>, <<"text/xml">>}],
                    "<test>Value</test>"
                }},
            Expectation = {ok, {[{<<"Content-Type">>, <<"text/xml">>}], [{"test", "Value"}]}},
            ?assertEqual(Expectation, aws_lib_response:format_response(Response))
        end},
        {"204 No Content is a success", fun() ->
            Response =
                {ok, {
                    {"HTTP/1.1", 204, "No Content"},
                    [],
                    <<>>
                }},
            Expectation = {ok, {[], <<>>}},
            ?assertEqual(Expectation, aws_lib_response:format_response(Response))
        end},
        {"3xx redirect is an error (gun does not follow redirects)", fun() ->
            Response =
                {ok, {
                    {"HTTP/1.1", 302, "Found"},
                    [{<<"content-type">>, <<"text/plain">>}],
                    <<"moved">>
                }},
            Expectation = {error, "Found", {[{<<"content-type">>, <<"text/plain">>}], <<"moved">>}},
            ?assertEqual(Expectation, aws_lib_response:format_response(Response))
        end}
    ].

get_content_type_test_() ->
    [
        {"from headers caps", fun() ->
            Headers = [{"Content-Type", "text/xml"}],
            Expectation = {"text", "xml"},
            ?assertEqual(Expectation, aws_lib_response:get_content_type(Headers))
        end},
        {"from headers lower", fun() ->
            Headers = [{"content-type", "text/xml"}],
            Expectation = {"text", "xml"},
            ?assertEqual(Expectation, aws_lib_response:get_content_type(Headers))
        end}
    ].

maybe_decode_body_test_() ->
    [
        {"application/x-amz-json-1.0", fun() ->
            ContentType = {"application", "x-amz-json-1.0"},
            Body = "{\"test\": true}",
            Expectation = [{"test", true}],
            ?assertEqual(Expectation, aws_lib_response:maybe_decode_body(ContentType, Body))
        end},
        {"application/x-amz-json-1.1", fun() ->
            %% The JSON 1.1 protocol (e.g. Secrets Manager) must decode too (#99).
            ContentType = {"application", "x-amz-json-1.1"},
            Body = "{\"test\": true}",
            Expectation = [{"test", true}],
            ?assertEqual(Expectation, aws_lib_response:maybe_decode_body(ContentType, Body))
        end},
        {"application/json", fun() ->
            ContentType = {"application", "json"},
            Body = "{\"test\": true}",
            Expectation = [{"test", true}],
            ?assertEqual(Expectation, aws_lib_response:maybe_decode_body(ContentType, Body))
        end},
        {"application/*+json structured suffix", fun() ->
            ContentType = {"application", "vnd.api+json"},
            Body = "{\"test\": true}",
            Expectation = [{"test", true}],
            ?assertEqual(Expectation, aws_lib_response:maybe_decode_body(ContentType, Body))
        end},
        {"text/xml", fun() ->
            ContentType = {"text", "xml"},
            Body = "<test><node>value</node></test>",
            Expectation = [{"test", [{"node", "value"}]}],
            ?assertEqual(Expectation, aws_lib_response:maybe_decode_body(ContentType, Body))
        end},
        {"text/html [unsupported]", fun() ->
            ContentType = {"text", "html"},
            Body = "<html><head></head><body></body></html>",
            ?assertEqual(Body, aws_lib_response:maybe_decode_body(ContentType, Body))
        end},
        {"application/octet-stream is not decoded", fun() ->
            %% A non-JSON application/* subtype must fall through undecoded, not
            %% be treated as JSON.
            ContentType = {"application", "octet-stream"},
            Body = <<"raw bytes">>,
            ?assertEqual(Body, aws_lib_response:maybe_decode_body(ContentType, Body))
        end}
    ].

parse_content_type_test_() ->
    [
        {"application/x-amz-json-1.0", fun() ->
            Expectation = {"application", "x-amz-json-1.0"},
            ?assertEqual(
                Expectation, aws_lib_response:parse_content_type("application/x-amz-json-1.0")
            )
        end},
        {"application/xml", fun() ->
            Expectation = {"application", "xml"},
            ?assertEqual(Expectation, aws_lib_response:parse_content_type("application/xml"))
        end},
        {"text/xml;charset=UTF-8", fun() ->
            Expectation = {"text", "xml"},
            ?assertEqual(Expectation, aws_lib_response:parse_content_type("text/xml"))
        end}
    ].
