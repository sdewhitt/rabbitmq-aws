%% Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
%% SPDX-License-Identifier: Apache-2.0
%% vim:ft=erlang:
%% -*- mode: erlang; -*-

%% Interprets AWS HTTP responses: shaping the raw aws_lib_httpc:response()
%% into the plugin's result() (format_response/1), decoding bodies by content
%% type, and classifying a failed response as retriable or not (issue #80).
%% aws_lib_httpc owns the request lifecycle and produces the raw response;
%% this module owns what the response MEANS. aws_lib's retry loop consumes
%% both.
-module(aws_lib_response).

-export([
    format_response/1,
    classify_response/2,
    get_content_type/1,
    maybe_decode_body/2,
    parse_content_type/1
]).

-include("aws_lib.hrl").

%% Substring markers, matched case-insensitively, that identify an error code
%% botocore retries: its _THROTTLED_ERROR_CODES together with its
%% _TRANSIENT_ERROR_CODES (botocore/retries/standard.py), collapsed into
%% lowercase substrings. `throttl' covers Throttling, ThrottlingException,
%% ThrottledException, RequestThrottledException, RequestThrottled, and
%% EC2ThrottledException; `limitexceeded' covers RequestLimitExceeded,
%% BandwidthLimitExceeded, and LimitExceededException; `requesttimeout' covers
%% the transient RequestTimeout and RequestTimeoutException;
%% `priorrequestnotcomplete' appears in both lists; the rest map one to one.
-define(THROTTLING_MARKERS, [
    <<"throttl">>,
    <<"toomanyrequests">>,
    <<"provisionedthroughputexceeded">>,
    <<"limitexceeded">>,
    <<"transactioninprogress">>,
    <<"slowdown">>,
    <<"requesttimeout">>,
    <<"priorrequestnotcomplete">>
]).

%% The body fields an AWS error document carries its error code under:
%% `__type' or `code' for the JSON protocols (Smithy awsJson1.0/1.1 specs) and
%% `Code' for XML error documents (Smithy awsQuery spec). The JSON protocols
%% also allow the code to arrive in the X-Amzn-Errortype header instead, which
%% classify_status/2 consults separately.
-define(ERROR_CODE_KEYS, ["__type", "Code", "code"]).

-define(ERRORTYPE_HEADER, <<"x-amzn-errortype">>).

-spec format_response(Response :: aws_lib_httpc:response()) -> result().
%% @doc Format the httpc response result, returning the request result data
%% structure. The response body will attempt to be decoded by invoking the
%% maybe_decode_body/2 method.
%% @end
%% Any 2xx is a success. Every other status (3xx redirects we do not follow,
%% 4xx, 5xx) is an error: gun is not configured to follow redirects, so a 3xx
%% is a request we could not complete.
format_response({ok, {{_Version, StatusCode, _Message}, Headers, Body}}) when
    StatusCode >= 200, StatusCode < 300
->
    {ok, {Headers, maybe_decode_body(get_content_type(Headers), Body)}};
format_response({ok, {{_Version, _StatusCode, Message}, Headers, Body}}) ->
    {error, Message, {Headers, maybe_decode_body(get_content_type(Headers), Body)}};
format_response({error, Reason}) ->
    {error, Reason, undefined}.

-spec classify_response(Response :: aws_lib_httpc:response(), Formatted :: result()) ->
    retriable | not_retriable.
%% @doc Decide whether a failed request should be retried (issue #80). Retry on
%% 5xx server errors, on HTTP 429, on throttling responses (a throttling error
%% code in the error body or the X-Amzn-Errortype header), and on transport
%% failures (a timeout, a dropped socket). Other 4xx client errors (bad
%% request, not found, access denied) will not succeed on retry, so return
%% them to the caller immediately. Takes the raw response (whose status line
%% format_response/1 collapses into a reason phrase) alongside its
%% already-formatted result (whose body format_response/1 already decoded), so
%% the body is decoded exactly once per response. The two arguments must come
%% from the same response.
classify_response(Response, Formatted) ->
    classify_status(aws_lib_httpc:response_status(Response), Formatted).

-spec classify_status({http, integer()} | transport_error, result()) ->
    retriable | not_retriable.
classify_status({http, StatusCode}, _Formatted) when StatusCode >= 200, StatusCode < 300 ->
    %% A success is never retried; the verdict is ignored on the success branch,
    %% but the function stays total.
    retriable;
classify_status({http, StatusCode}, _Formatted) when StatusCode >= 500 ->
    retriable;
classify_status({http, 429}, _Formatted) ->
    retriable;
classify_status({http, StatusCode}, {error, _Message, {Headers, Decoded}}) when
    StatusCode >= 400
->
    %% An HTTP-level error always formats to {error, Message, {Headers, Body}},
    %% so the decoded body is available here.
    case is_throttling_error(Headers, Decoded) of
        true -> retriable;
        false -> not_retriable
    end;
classify_status({http, _StatusCode}, _Formatted) ->
    %% 3xx (redirects we do not follow) and any other unclassified status: not a
    %% success and not obviously transient, so return it to the caller.
    not_retriable;
classify_status(transport_error, _Formatted) ->
    %% A transport-level failure (timeout, closed socket, connection refused);
    %% these are transient, so retry.
    retriable.

%% Decide whether an error response indicates throttling. The error code is
%% taken from the X-Amzn-Errortype header when present alongside the values
%% stored under the AWS error-code body keys; matching the error code rather
%% than the whole body keeps a marker inside a message or resource name from
%% triggering a retry. A body that could not be decoded (still a raw binary,
%% e.g. text/plain or text/html) carries no structured error code, so only its
%% X-Amzn-Errortype header is consulted: substring-searching the raw bytes
%% would retry a permanent error whenever an unrelated 4xx page (a proxy or ALB
%% error page) happened to contain a marker such as `throttl'. A genuinely
%% transient failure with such a body is still retried via the 5xx or 429
%% status rules in classify_status/2.
-spec is_throttling_error(headers(), list() | body()) -> boolean().
is_throttling_error(Headers, Body) when is_binary(Body) ->
    %% Body itself is not consulted: an undecodable body carries no structured
    %% error code, so classification rests on the header and the status rules.
    lists:any(fun contains_throttling_marker/1, errortype_header_values(Headers));
is_throttling_error(Headers, Decoded) ->
    Candidates = errortype_header_values(Headers) ++ error_code_values(Decoded),
    lists:any(fun contains_throttling_marker/1, Candidates).

%% The X-Amzn-Errortype header values, compared case-insensitively on the
%% header name since HTTP/1.1 servers may vary its casing.
errortype_header_values(Headers) ->
    [Value || {Name, Value} <- Headers, is_errortype_header(Name)].

is_errortype_header(Name) ->
    try string:lowercase(rabbit_data_coercion:to_utf8_binary(Name)) of
        ?ERRORTYPE_HEADER -> true;
        _ -> false
    catch
        _:_ -> false
    end.

%% Collect the values stored under AWS error-code keys anywhere in a decoded
%% body (a nested proplist with string keys).
error_code_values([{Key, Value} | T]) ->
    error_code_values_for(Key, Value) ++ error_code_values(T);
error_code_values([_ | T]) ->
    error_code_values(T);
error_code_values(_) ->
    [].

error_code_values_for(Key, Value) ->
    case lists:member(Key, ?ERROR_CODE_KEYS) of
        true when is_list(Value); is_binary(Value) ->
            [Value];
        true ->
            [];
        false ->
            %% Descend into a nested proplist; a plain string value yields
            %% nothing.
            error_code_values(Value)
    end.

%% Case-insensitive substring match of the throttling markers against an error
%% code or a raw body. to_utf8_binary/1 keeps multi-byte codepoints intact
%% where a bare iolist_to_binary/1 would fail on non-latin1 input; a value that
%% is not chardata at all (e.g. a nested proplist under an error-code key)
%% makes it throw, which simply means "not throttling".
contains_throttling_marker(Value) ->
    try string:lowercase(rabbit_data_coercion:to_utf8_binary(Value)) of
        Text when is_binary(Text) ->
            lists:any(
                fun(Marker) -> binary:match(Text, Marker) =/= nomatch end,
                ?THROTTLING_MARKERS
            );
        _ ->
            false
    catch
        _:_ ->
            false
    end.

-spec get_content_type(Headers :: headers()) -> {Type :: string(), Subtype :: string()}.
%% @doc Fetch the content type from the headers and return it as a tuple of
%%      {Type, Subtype}.
%% @end
get_content_type(Headers) ->
    Value =
        case proplists:get_value(<<"content-type">>, Headers, undefined) of
            undefined ->
                proplists:get_value(<<"Content-Type">>, Headers, "text/xml");
            Other ->
                Other
        end,
    parse_content_type(Value).

-spec maybe_decode_body(ContentType :: {nonempty_string(), nonempty_string()}, Body :: body()) ->
    list() | body().
%% @doc Attempt to decode the response body by its MIME
%% @end
maybe_decode_body(_, <<>>) ->
    <<>>;
maybe_decode_body({"application", Subtype}, Body) ->
    case is_json_subtype(Subtype) of
        true -> aws_lib_json:decode(Body);
        false -> maybe_decode_xml(Subtype, Body)
    end;
maybe_decode_body({_, Subtype}, Body) ->
    maybe_decode_xml(Subtype, Body).

maybe_decode_xml("xml", Body) ->
    aws_lib_xml:parse(Body);
maybe_decode_xml(_Subtype, Body) ->
    Body.

%% Recognise the JSON subtypes AWS services return. Covers plain `json', every
%% AWS JSON protocol version (`x-amz-json-1.0', `x-amz-json-1.1', and any future
%% `x-amz-json-*'), and the RFC 6839 structured `+json' suffix. Secrets Manager
%% and other services use the JSON 1.1 protocol, so matching only 1.0/plain left
%% those responses undecoded (issue #99).
is_json_subtype("json") ->
    true;
is_json_subtype("x-amz-json-" ++ _Version) ->
    true;
is_json_subtype(Subtype) ->
    lists:suffix("+json", Subtype).

-spec parse_content_type(ContentType :: string()) -> {Type :: string(), Subtype :: string()}.
%% @doc parse a content type string returning a tuple of type/subtype
%% @end
parse_content_type(ContentType) when is_binary(ContentType) ->
    parse_content_type(binary_to_list(ContentType));
parse_content_type(ContentType) ->
    Parts = string:tokens(ContentType, ";"),
    [Type, Subtype] = string:tokens(lists:nth(1, Parts), "/"),
    {Type, Subtype}.
