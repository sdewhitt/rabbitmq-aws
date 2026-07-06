-module(aws_lib_tests).

-include_lib("eunit/include/eunit.hrl").

-include("aws_lib.hrl").

%% Test helper functions
setup() ->
    application:ensure_all_started(aws_lib),
    ok.

teardown(_) ->
    application:stop(aws_lib),
    ok.

% Helper to create test state with credentials
set_test_credentials(AccessKey, SecretKey) ->
    set_test_credentials(AccessKey, SecretKey, undefined, undefined).

set_test_credentials(AccessKey, SecretKey, SecurityToken, Expiration) ->
    Creds = #aws_credentials{
        access_key = AccessKey,
        secret_key = SecretKey,
        security_token = SecurityToken,
        expiration = Expiration
    },
    State = aws_lib:new(),
    State#aws_state{credentials = Creds}.

set_test_region(Region) ->
    aws_lib:new(Region).

init_test_() ->
    {foreach,
        fun() ->
            os:putenv("AWS_DEFAULT_REGION", "us-west-3"),
            meck:new(aws_lib_config, [passthrough]),
            setup()
        end,
        fun(_) ->
            teardown(ok),
            os:unsetenv("AWS_DEFAULT_REGION"),
            meck:unload(aws_lib_config)
        end,
        [
            {"ok", fun() ->
                State0 = set_test_region("us-west-3"),
                os:unsetenv("AWS_SESSION_TOKEN"),
                os:putenv("AWS_ACCESS_KEY_ID", "Sésame"),
                os:putenv("AWS_SECRET_ACCESS_KEY", "ouvre-toi"),
                {ok, State1} = aws_lib:refresh_credentials(State0),
                ?assertEqual(true, aws_lib:has_credentials(State1)),
                {ok, Creds} = aws_lib:get_credentials(State1),
                ?assertEqual("Sésame", Creds#aws_credentials.access_key),
                ?assertEqual("ouvre-toi", Creds#aws_credentials.secret_key),
                ?assertEqual(undefined, Creds#aws_credentials.security_token),
                {ok, Region} = aws_lib:get_region(State1),
                ?assertEqual("us-west-3", Region),
                os:unsetenv("AWS_ACCESS_KEY_ID"),
                os:unsetenv("AWS_SECRET_ACCESS_KEY")
            end},
            {"error", fun() ->
                State = set_test_region("us-west-3"),
                meck:expect(aws_lib_config, credentials, fun(_) -> {error, test_result} end),
                ?assertEqual({error, test_result}, aws_lib:refresh_credentials(State)),
                meck:validate(aws_lib_config)
            end}
        ]}.

endpoint_test_() ->
    [
        {"specified", fun() ->
            Region = "us-east-3",
            Service = "dynamodb",
            Path = "/",
            Host = "localhost:32767",
            Expectation = "https://localhost:32767/",
            ?assertEqual(
                Expectation, aws_lib:endpoint(Region, Host, Service, Path)
            )
        end},
        {"unspecified", fun() ->
            Region = "us-east-3",
            Service = "dynamodb",
            Path = "/",
            Host = undefined,
            Expectation = "https://dynamodb.us-east-3.amazonaws.com/",
            ?assertEqual(
                Expectation, aws_lib:endpoint(Region, Host, Service, Path)
            )
        end}
    ].

endpoint_host_test_() ->
    [
        {"dynamodb service", fun() ->
            Expectation = "dynamodb.us-west-2.amazonaws.com",
            ?assertEqual(Expectation, aws_lib:endpoint_host("us-west-2", "dynamodb"))
        end}
    ].

cn_endpoint_host_test_() ->
    [
        {"s3", fun() ->
            Expectation = "s3.cn-north-1.amazonaws.com.cn",
            ?assertEqual(Expectation, aws_lib:endpoint_host("cn-north-1", "s3"))
        end},
        {"s3", fun() ->
            Expectation = "s3.cn-northwest-1.amazonaws.com.cn",
            ?assertEqual(Expectation, aws_lib:endpoint_host("cn-northwest-1", "s3"))
        end}
    ].

expired_credentials_test_() ->
    {
        foreach,
        fun() ->
            meck:new(calendar, [passthrough, unstick]),
            [calendar]
        end,
        fun meck:unload/1,
        [
            {"true", fun() ->
                Value = {{2016, 4, 1}, {12, 0, 0}},
                Expectation = true,
                meck:expect(calendar, local_time_to_universal_time_dst, fun(_) ->
                    [{{2016, 4, 1}, {12, 0, 0}}]
                end),
                ?assertEqual(Expectation, aws_lib:expired_credentials(Value)),
                meck:validate(calendar)
            end},
            {"false", fun() ->
                Value = {{2016, 5, 1}, {16, 30, 0}},
                Expectation = false,
                meck:expect(calendar, local_time_to_universal_time_dst, fun(_) ->
                    [{{2016, 4, 1}, {12, 0, 0}}]
                end),
                ?assertEqual(Expectation, aws_lib:expired_credentials(Value)),
                meck:validate(calendar)
            end},
            {"undefined", fun() ->
                ?assertEqual(false, aws_lib:expired_credentials(undefined))
            end}
        ]
    }.

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
            ?assertEqual(Expectation, aws_lib:format_response(Response))
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
            ?assertEqual(Expectation, aws_lib:format_response(Response))
        end},
        {"201 Created is a success", fun() ->
            Response =
                {ok, {
                    {"HTTP/1.1", 201, "Created"},
                    [{<<"Content-Type">>, <<"text/xml">>}],
                    "<test>Value</test>"
                }},
            Expectation = {ok, {[{<<"Content-Type">>, <<"text/xml">>}], [{"test", "Value"}]}},
            ?assertEqual(Expectation, aws_lib:format_response(Response))
        end},
        {"204 No Content is a success", fun() ->
            Response =
                {ok, {
                    {"HTTP/1.1", 204, "No Content"},
                    [],
                    <<>>
                }},
            Expectation = {ok, {[], <<>>}},
            ?assertEqual(Expectation, aws_lib:format_response(Response))
        end},
        {"3xx redirect is an error (gun does not follow redirects)", fun() ->
            Response =
                {ok, {
                    {"HTTP/1.1", 302, "Found"},
                    [{<<"content-type">>, <<"text/plain">>}],
                    <<"moved">>
                }},
            Expectation = {error, "Found", {[{<<"content-type">>, <<"text/plain">>}], <<"moved">>}},
            ?assertEqual(Expectation, aws_lib:format_response(Response))
        end}
    ].

get_content_type_test_() ->
    [
        {"from headers caps", fun() ->
            Headers = [{"Content-Type", "text/xml"}],
            Expectation = {"text", "xml"},
            ?assertEqual(Expectation, aws_lib:get_content_type(Headers))
        end},
        {"from headers lower", fun() ->
            Headers = [{"content-type", "text/xml"}],
            Expectation = {"text", "xml"},
            ?assertEqual(Expectation, aws_lib:get_content_type(Headers))
        end}
    ].

has_credentials_test_() ->
    {
        foreach,
        fun setup/0,
        fun teardown/1,
        [
            {"true", fun() ->
                State = set_test_credentials("TESTVALUE1", "SECRET"),
                ?assertEqual(true, aws_lib:has_credentials(State))
            end},
            {"false", fun() ->
                State = aws_lib:new(),
                ?assertEqual(false, aws_lib:has_credentials(State))
            end}
        ]
    }.

local_time_test_() ->
    {
        foreach,
        fun() ->
            meck:new(calendar, [passthrough, unstick]),
            [calendar]
        end,
        fun meck:unload/1,
        [
            {"value", fun() ->
                Value = {{2016, 5, 1}, {12, 0, 0}},
                meck:expect(calendar, local_time_to_universal_time_dst, fun(_) -> [Value] end),
                ?assertEqual(Value, aws_lib:local_time()),
                meck:validate(calendar)
            end}
        ]
    }.

maybe_decode_body_test_() ->
    [
        {"application/x-amz-json-1.0", fun() ->
            ContentType = {"application", "x-amz-json-1.0"},
            Body = "{\"test\": true}",
            Expectation = [{"test", true}],
            ?assertEqual(Expectation, aws_lib:maybe_decode_body(ContentType, Body))
        end},
        {"application/json", fun() ->
            ContentType = {"application", "json"},
            Body = "{\"test\": true}",
            Expectation = [{"test", true}],
            ?assertEqual(Expectation, aws_lib:maybe_decode_body(ContentType, Body))
        end},
        {"text/xml", fun() ->
            ContentType = {"text", "xml"},
            Body = "<test><node>value</node></test>",
            Expectation = [{"test", [{"node", "value"}]}],
            ?assertEqual(Expectation, aws_lib:maybe_decode_body(ContentType, Body))
        end},
        {"text/html [unsupported]", fun() ->
            ContentType = {"text", "html"},
            Body = "<html><head></head><body></body></html>",
            ?assertEqual(Body, aws_lib:maybe_decode_body(ContentType, Body))
        end}
    ].

parse_content_type_test_() ->
    [
        {"application/x-amz-json-1.0", fun() ->
            Expectation = {"application", "x-amz-json-1.0"},
            ?assertEqual(Expectation, aws_lib:parse_content_type("application/x-amz-json-1.0"))
        end},
        {"application/xml", fun() ->
            Expectation = {"application", "xml"},
            ?assertEqual(Expectation, aws_lib:parse_content_type("application/xml"))
        end},
        {"text/xml;charset=UTF-8", fun() ->
            Expectation = {"text", "xml"},
            ?assertEqual(Expectation, aws_lib:parse_content_type("text/xml"))
        end}
    ].

perform_request_test_() ->
    {
        foreach,
        fun() ->
            setup(),
            meck:new(gun, []),
            [gun]
        end,
        fun(Mods) ->
            teardown(ok),
            meck:unload(Mods)
        end,
        [
            {
                "Successful run",
                fun() ->
                    State0 = set_test_credentials(
                        "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
                    ),
                    {ok, State} = aws_lib:set_region("us-east-1", State0),
                    Service = "ec2",
                    Method = get,
                    Headers = [],
                    Path = "/?Action=DescribeTags&Version=2015-10-01",
                    Body = "",
                    Options = [],

                    meck:expect(gun, open, fun(_, _, _) -> {ok, pid} end),
                    meck:expect(gun, close, fun(_) -> ok end),
                    meck:expect(gun, await_up, fun(_, _) -> {ok, protocol} end),
                    meck:expect(
                        gun,
                        get,
                        fun(_Pid, "/?Action=DescribeTags&Version=2015-10-01", _Headers) -> nofin end
                    ),
                    meck:expect(
                        gun,
                        await,
                        fun(_Pid, _, _) ->
                            {response, nofin, 200, [{<<"content-type">>, <<"application/json">>}]}
                        end
                    ),
                    meck:expect(
                        gun,
                        await_body,
                        fun(_Pid, _, _) -> {ok, <<"{\"pass\": true}">>} end
                    ),

                    {ok, {Headers1, Body1}, State1} = aws_lib:request(
                        Service, Method, Path, Body, Headers, Options, State
                    ),
                    ?assertEqual([{<<"content-type">>, <<"application/json">>}], Headers1),
                    ?assertEqual([{"pass", true}], Body1),
                    ?assert(is_record(State1, aws_state)),
                    meck:validate(gun)
                end
            },
            {
                "await_body timeout is returned as a clean {error, timeout}",
                fun() ->
                    State0 = set_test_credentials(
                        "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
                    ),
                    {ok, State} = aws_lib:set_region("us-east-1", State0),

                    meck:expect(gun, open, fun(_, _, _) -> {ok, pid} end),
                    meck:expect(gun, close, fun(_) -> ok end),
                    meck:expect(gun, await_up, fun(_, _) -> {ok, protocol} end),
                    meck:expect(gun, get, fun(_Pid, _Path, _Headers) -> nofin end),
                    meck:expect(gun, await, fun(_Pid, _, _) ->
                        {response, nofin, 200, [{<<"content-type">>, <<"application/json">>}]}
                    end),
                    %% The headers arrive but the body read times out. This must
                    %% surface as {error, timeout}, not {error, {badmatch, _}}.
                    meck:expect(gun, await_body, fun(_Pid, _, _) -> {error, timeout} end),

                    Result = aws_lib:request("ec2", get, "/", "", [], [], State),
                    ?assertEqual({error, timeout, undefined}, Result),
                    meck:validate(gun)
                end
            }
        ]
    }.

sign_headers_test_() ->
    {
        foreach,
        fun() ->
            meck:new(calendar, [passthrough, unstick]),
            [calendar]
        end,
        fun meck:unload/1,
        [
            {"with security token", fun() ->
                Value = {{2016, 5, 1}, {12, 0, 0}},
                meck:expect(calendar, local_time_to_universal_time_dst, fun(_) -> [Value] end),
                AccessKey = "AKIDEXAMPLE",
                SecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                SecurityToken =
                    "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/L",
                Region = "us-east-1",
                Service = "ec2",
                Method = get,
                Headers = [],
                Body = "",
                URI = "http://ec2.us-east-1.amazonaws.com/?Action=DescribeTags&Version=2015-10-01",
                Expectation = [
                    {"authorization",
                        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20160501/us-east-1/ec2/aws4_request, SignedHeaders=content-length;date;host;x-amz-content-sha256;x-amz-security-token, Signature=62d10b4897f7d05e4454b75895b5e372f6c2eb6997943cd913680822e94c6999"},
                    {"content-length", "0"},
                    {"date", "20160501T120000Z"},
                    {"host", "ec2.us-east-1.amazonaws.com"},
                    {"x-amz-content-sha256",
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
                    {"x-amz-security-token",
                        "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/L"}
                ],
                ?assertEqual(
                    Expectation,
                    aws_lib:sign_headers(
                        AccessKey,
                        SecretKey,
                        SecurityToken,
                        Region,
                        Service,
                        Method,
                        URI,
                        Headers,
                        Body,
                        undefined
                    )
                ),
                meck:validate(calendar)
            end}
        ]
    }.

api_get_request_test_() ->
    {
        foreach,
        fun() ->
            setup(),
            meck:new(gun, []),
            meck:new(aws_lib_config, []),
            [gun, aws_lib_config]
        end,
        fun(Mods) ->
            teardown(ok),
            meck:unload(Mods)
        end,
        [
            {"AWS service API request succeeded", fun() ->
                State0 = set_test_credentials("ExpiredKey", "ExpiredAccessKey", undefined, {
                    {3016, 4, 1}, {12, 0, 0}
                }),
                {ok, State} = aws_lib:set_region("us-east-1", State0),

                meck:expect(gun, open, fun(_, _, _) -> {ok, pid} end),
                meck:expect(gun, close, fun(_) -> ok end),
                meck:expect(gun, await_up, fun(_, _) -> {ok, protocol} end),
                meck:expect(
                    gun,
                    get,
                    fun(_Pid, _Path, _Headers) -> nofin end
                ),
                meck:expect(
                    gun,
                    await,
                    fun(_Pid, _, _) ->
                        {response, nofin, 200, [{<<"content-type">>, <<"application/json">>}]}
                    end
                ),
                meck:expect(
                    gun,
                    await_body,
                    fun(_Pid, _, _) -> {ok, <<"{\"data\": \"value\"}">>} end
                ),

                {ok, Body, State1} = aws_lib:api_get_request("AWS", "API", State),
                ?assertEqual([{"data", "value"}], Body),
                ?assert(is_record(State1, aws_state)),
                meck:validate(gun)
            end},
            {"AWS service API request failed - API error with persistent failure", fun() ->
                State0 = set_test_credentials("ExpiredKey", "ExpiredAccessKey", undefined, {
                    {3016, 4, 1}, {12, 0, 0}
                }),
                {ok, State} = aws_lib:set_region("us-east-1", State0),

                meck:expect(gun, open, fun(_, _, _) -> {ok, spawn(fun() -> ok end)} end),
                meck:expect(gun, close, fun(_) -> ok end),
                meck:expect(gun, await_up, fun(_, _) -> {ok, protocol} end),
                meck:expect(
                    gun,
                    get,
                    fun(_Pid, _Path, _Headers) -> nofin end
                ),
                meck:expect(
                    gun,
                    await,
                    fun(_Pid, _, _) -> {error, "network error"} end
                ),

                Result = aws_lib:api_get_request("AWS", "API", State),
                ?assertEqual({error, "AWS service is unavailable"}, Result),
                meck:validate(gun)
            end},
            {"AWS service API request succeeded after a transient error", fun() ->
                State0 = set_test_credentials("ExpiredKey", "ExpiredAccessKey", undefined, {
                    {3016, 4, 1}, {12, 0, 0}
                }),
                {ok, State} = aws_lib:set_region("us-east-1", State0),

                meck:expect(gun, open, fun(_, _, _) -> {ok, spawn(fun() -> ok end)} end),
                meck:expect(gun, close, fun(_) -> ok end),
                meck:expect(gun, await_up, fun(_, _) -> {ok, protocol} end),
                meck:expect(
                    gun,
                    get,
                    fun(_Pid, _Path, _Headers) -> nofin end
                ),

                %% meck:expect(gun, get, 3, meck:seq(
                %%             fun(_Pid, _Path, _Headers) -> {error, "network errors"} end),
                meck:expect(
                    gun,
                    await,
                    3,
                    meck:seq([
                        {error, "network error"},
                        {response, nofin, 500, [{<<"content-type">>, <<"application/json">>}]},
                        {response, nofin, 200, [{<<"content-type">>, <<"application/json">>}]}
                    ])
                ),

                meck:expect(
                    gun,
                    await_body,
                    3,
                    meck:seq([
                        {ok, <<"{\"error\": \"server error\"}">>},
                        {ok, <<"{\"data\": \"value\"}">>}
                    ])
                ),
                {ok, Body, State1} = aws_lib:api_get_request("AWS", "API", State),
                ?assertEqual([{"data", "value"}], Body),
                ?assert(is_record(State1, aws_state)),
                meck:validate(gun)
            end},
            {"gun:open failure re-enters the retry loop rather than raising", fun() ->
                State0 = set_test_credentials("ExpiredKey", "ExpiredAccessKey", undefined, {
                    {3016, 4, 1}, {12, 0, 0}
                }),
                {ok, State} = aws_lib:set_region("us-east-1", State0),

                %% A connection that never opens must be retried and then
                %% reported as the exhausted-retries error, not escape as a
                %% {gun_open_failed, _} exception.
                meck:expect(gun, open, fun(_, _, _) -> {error, econnrefused} end),
                meck:expect(gun, close, fun(_) -> ok end),

                Result = aws_lib:api_get_request("AWS", "API", State),
                ?assertEqual({error, "AWS service is unavailable"}, Result),
                meck:validate(gun)
            end},
            {"gun:await_up failure re-enters the retry loop rather than raising", fun() ->
                State0 = set_test_credentials("ExpiredKey", "ExpiredAccessKey", undefined, {
                    {3016, 4, 1}, {12, 0, 0}
                }),
                {ok, State} = aws_lib:set_region("us-east-1", State0),

                %% The socket opens but the protocol never comes up; this too
                %% must be retried, not raised as {gun_connection_failed, _}.
                meck:expect(gun, open, fun(_, _, _) -> {ok, pid} end),
                meck:expect(gun, close, fun(_) -> ok end),
                meck:expect(gun, await_up, fun(_, _) -> {error, timeout} end),

                Result = aws_lib:api_get_request("AWS", "API", State),
                ?assertEqual({error, "AWS service is unavailable"}, Result),
                meck:validate(gun)
            end}
        ]
    }.

ensure_credentials_valid_test_() ->
    {
        foreach,
        fun() ->
            setup(),
            meck:new(aws_lib_config, []),
            [aws_lib_config]
        end,
        fun(Mods) ->
            teardown(ok),
            meck:unload(Mods)
        end,
        [
            {"expired credentials are refreshed", fun() ->
                State0 = set_test_credentials("ExpiredKey", "ExpiredAccessKey", undefined, {
                    {2016, 4, 1}, {12, 0, 0}
                }),
                {ok, State1} = aws_lib:set_region("us-east-1", State0),

                % Mock config to return new credentials when refresh is called
                NewCreds = #aws_credentials{
                    access_key = "NewKey",
                    secret_key = "NewAccessKey",
                    security_token = undefined,
                    expiration = {{3016, 4, 1}, {12, 0, 0}}
                },
                meck:expect(
                    aws_lib_config,
                    credentials,
                    fun(Config) ->
                        {ok, NewCreds, Config}
                    end
                ),

                {ok, State2} = aws_lib:ensure_credentials_valid(State1),

                {ok, Creds} = aws_lib:get_credentials(State2),
                ?assertEqual("NewKey", Creds#aws_credentials.access_key),
                ?assertEqual("NewAccessKey", Creds#aws_credentials.secret_key),
                ?assertEqual(undefined, Creds#aws_credentials.security_token),
                {ok, Region} = aws_lib:get_region(State2),
                ?assertEqual("us-east-1", Region),
                meck:validate(aws_lib_config)
            end},
            {"valid credentials are returned", fun() ->
                State0 = set_test_credentials("GoodKey", "GoodAccessKey", undefined, {
                    {3016, 4, 1}, {12, 0, 0}
                }),
                {ok, State1} = aws_lib:set_region("us-east-1", State0),

                {ok, State2} = aws_lib:ensure_credentials_valid(State1),

                {ok, Creds} = aws_lib:get_credentials(State2),
                ?assertEqual("GoodKey", Creds#aws_credentials.access_key),
                ?assertEqual("GoodAccessKey", Creds#aws_credentials.secret_key),
                ?assertEqual(undefined, Creds#aws_credentials.security_token),
                {ok, Region} = aws_lib:get_region(State2),
                ?assertEqual("us-east-1", Region),
                meck:validate(aws_lib_config)
            end},
            {"load credentials if missing", fun() ->
                State0 = aws_lib:new("us-east-1"),

                NewCreds = #aws_credentials{
                    access_key = "GoodKey",
                    secret_key = "GoodAccessKey",
                    security_token = undefined,
                    expiration = {{3016, 4, 1}, {12, 0, 0}}
                },
                meck:expect(
                    aws_lib_config,
                    credentials,
                    fun(Config) ->
                        {ok, NewCreds, Config}
                    end
                ),

                {ok, State1} = aws_lib:ensure_credentials_valid(State0),

                {ok, Creds} = aws_lib:get_credentials(State1),
                ?assertEqual("GoodKey", Creds#aws_credentials.access_key),
                ?assertEqual("GoodAccessKey", Creds#aws_credentials.secret_key),
                ?assertEqual(undefined, Creds#aws_credentials.security_token),
                {ok, Region} = aws_lib:get_region(State1),
                ?assertEqual("us-east-1", Region),
                meck:validate(aws_lib_config)
            end}
        ]
    }.

expired_imdsv2_token_test_() ->
    [
        {"imdsv2 token is valid", fun() ->
            [Value] = calendar:local_time_to_universal_time_dst(calendar:local_time()),
            Now = calendar:datetime_to_gregorian_seconds(Value),
            Imdsv2Token = #imdsv2token{token = "value", expiration = Now + 100},
            ?assertEqual(false, aws_lib:expired_imdsv2_token(Imdsv2Token))
        end},
        {"imdsv2 token is expired", fun() ->
            [Value] = calendar:local_time_to_universal_time_dst(calendar:local_time()),
            Now = calendar:datetime_to_gregorian_seconds(Value),
            Imdsv2Token = #imdsv2token{token = "value", expiration = Now - 100},
            ?assertEqual(true, aws_lib:expired_imdsv2_token(Imdsv2Token))
        end},
        {"imdsv2 token is not yet initialized", fun() ->
            ?assertEqual(true, aws_lib:expired_imdsv2_token(undefined))
        end},
        {"imdsv2 token is undefined", fun() ->
            Imdsv2Token = #imdsv2token{token = undefined, expiration = undefined},
            ?assertEqual(true, aws_lib:expired_imdsv2_token(Imdsv2Token))
        end}
    ].

parse_uri_test_() ->
    [
        {"https host with path defaults the port to 443", fun() ->
            ?assertEqual(
                {"s3.amazonaws.com", 443, "/bucket/key"},
                aws_lib:parse_uri("https://s3.amazonaws.com/bucket/key")
            )
        end},
        {"http host with an explicit port", fun() ->
            ?assertEqual(
                {"169.254.169.254", 8080, "/latest/meta-data/"},
                aws_lib:parse_uri("http://169.254.169.254:8080/latest/meta-data/")
            )
        end},
        {"an empty path becomes /", fun() ->
            ?assertEqual(
                {"example.com", 443, "/"},
                aws_lib:parse_uri("https://example.com")
            )
        end},
        %% The query string must be reattached to the path: Path is used directly
        %% as the Gun request target, so dropping the query would send the wrong
        %% request (and diverge from the signed URI).
        {"the query string is reattached to the path", fun() ->
            ?assertEqual(
                {"ec2.us-east-1.amazonaws.com", 443,
                    "/?Action=DescribeTags&Version=2015-10-01"},
                aws_lib:parse_uri(
                    "https://ec2.us-east-1.amazonaws.com/?Action=DescribeTags&Version=2015-10-01"
                )
            )
        end},
        %% Issue #100: malformed input returns an error tuple rather than
        %% crashing with a case_clause.
        {"a scheme-less URI is reported, not crashed", fun() ->
            ?assertEqual(
                {error, {malformed_uri, "ec2.amazonaws.com/path"}},
                aws_lib:parse_uri("ec2.amazonaws.com/path")
            )
        end},
        {"an empty string is reported, not crashed", fun() ->
            ?assertEqual({error, {malformed_uri, ""}}, aws_lib:parse_uri(""))
        end}
    ].
