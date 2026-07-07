%% ====================================================================
%% @author Gavin M. Roy <gavinmroy@gmail.com>
%% @copyright 2016, Gavin M. Roy
%% @doc aws_lib client library
%% @end
%% ====================================================================
-module(aws_lib).

%% API exports
-export([
    new/0, new/1,
    get_region/1,
    set_region/2,
    get_credentials/1,
    get/3, get/4, get/5,
    put/5, put/6,
    post/5, post/6,
    refresh_credentials/1,
    request/6, request/7, request/8,
    set_credentials/3,
    set_credentials/4,
    has_credentials/1,
    ensure_credentials_valid/1,
    ensure_imdsv2_token_valid/1,
    expired_imdsv2_token/1,
    local_time/0,
    api_get_request/3,
    api_post_request/5,
    status_text/1,
    open_connection/2, open_connection/3,
    close_connection/1,
    direct_request/7,
    endpoint/4,
    sign_headers/10,
    instance_volumes/1
]).

-export_type([aws_state/0]).

%% Export all for unit tests
-ifdef(TEST).
-compile(export_all).
-endif.

-include("aws_lib.hrl").
-include_lib("kernel/include/logger.hrl").

-opaque aws_state() :: #aws_state{}.
-type connection_handle() :: {pid(), string()}.

%%====================================================================
%% State construction and accessors
%%====================================================================

-spec new() -> aws_state().
%% @doc Create a new AWS state with undefined credentials and default config.
%% @end
new() ->
    #aws_state{credentials = undefined, config = #aws_config{}}.

-spec new(Region :: region()) -> aws_state().
%% @doc Create a new AWS state with the specified region.
%% @end
new(Region) ->
    #aws_state{credentials = undefined, config = #aws_config{region = Region}}.

-spec get_region(State :: aws_state()) -> {ok, region()} | {error, undefined}.
%% @doc Get the region from the state.
%% @end
get_region(#aws_state{config = #aws_config{region = undefined}}) ->
    {error, undefined};
get_region(#aws_state{config = #aws_config{region = Region}}) ->
    {ok, Region}.

-spec set_region(Region :: region(), State :: aws_state()) -> {ok, aws_state()}.
%% @doc Set the region in the state.
%% @end
set_region(Region, State = #aws_state{config = Config}) ->
    {ok, State#aws_state{config = Config#aws_config{region = Region}}}.

-spec get_credentials(State :: aws_state()) -> {ok, aws_credentials()} | {error, undefined}.
%% @doc Get the credentials from the state.
%% @end
get_credentials(#aws_state{credentials = undefined}) ->
    {error, undefined};
get_credentials(#aws_state{credentials = Creds}) ->
    {ok, Creds}.

%%====================================================================
%% Legacy functions - to be updated
%%====================================================================

-spec has_credentials(State :: aws_state()) -> boolean().
%% @doc Check if the state contains valid, non-expired credentials.
%% @end
has_credentials(#aws_state{credentials = undefined}) ->
    false;
has_credentials(#aws_state{credentials = #aws_credentials{expiration = Expiration}}) ->
    not expired_credentials(Expiration).

%%====================================================================
%% exported wrapper functions
%%====================================================================

get(Service, Path, State) ->
    get(Service, Path, [], State).

get(Service, Path, Headers, State) ->
    get(Service, Path, Headers, [], State).

get(Service, Path, Headers, Options, State) ->
    request(Service, get, Path, <<>>, Headers, Options, State).

-spec post(
    Service :: string(),
    Path :: path(),
    Body :: body(),
    Headers :: headers(),
    State :: aws_state()
) -> {ok, {headers(), term()}, aws_state()} | result_error().
%% @doc Perform a HTTP Post request to the AWS API for the specified service. The
%%      response will automatically be decoded if it is either in JSON or XML
%%      format.
%% @end
post(Service, Path, Body, Headers, State) ->
    post(Service, Path, Body, Headers, [], State).

post(Service, Path, Body, Headers, Options, State) ->
    request(Service, post, Path, Body, Headers, Options, State).

-spec put(
    Service :: string(),
    Path :: path(),
    Body :: body(),
    Headers :: headers(),
    State :: aws_state()
) -> {ok, {headers(), term()}, aws_state()} | result_error().
%% @doc Perform a HTTP Put request to the AWS API for the specified service. The
%%      response will automatically be decoded if it is either in JSON or XML
%%      format.
%% @end
put(Service, Path, Body, Headers, State) ->
    put(Service, Path, Body, Headers, [], State).

put(Service, Path, Body, Headers, Options, State) ->
    request(Service, put, Path, Body, Headers, Options, State).

-spec refresh_credentials(State :: aws_state()) -> {ok, aws_state()} | {error, term()}.
%% @doc Manually refresh the credentials from the environment, filesystem or EC2 Instance Metadata Service.
%% @end
refresh_credentials(State) ->
    do_refresh_credentials(State).

%%====================================================================
%% New Concurrent API Functions
%%====================================================================

%% Open a connection and return handle for direct use
-spec open_connection(
    Service :: string(),
    State :: aws_state()
) -> {ok, connection_handle(), aws_state()} | {error, term()}.
open_connection(Service, State) ->
    open_connection(Service, [], State).

-spec open_connection(
    Service :: string(),
    Options :: list(),
    State :: aws_state()
) -> {ok, connection_handle(), aws_state()} | {error, term()}.
open_connection(Service, Options, State0) ->
    % Get region from state or use default
    Region =
        case State0#aws_state.config of
            #aws_config{region = R} when R =/= undefined -> R;
            _ -> ?DEFAULT_REGION
        end,

    % Update state with region if it was default
    State1 =
        case State0#aws_state.config of
            undefined ->
                State0#aws_state{config = #aws_config{region = Region}};
            #aws_config{region = undefined} = C ->
                State0#aws_state{config = C#aws_config{region = Region}};
            _ ->
                State0
        end,

    Host = endpoint_host(Region, Service),
    Port = 443,
    case create_gun_connection(Host, Port, Options) of
        {ok, GunPid} ->
            {ok, {GunPid, Service}, State1};
        {error, _Reason} = Error ->
            Error
    end.

%% Close a direct connection
-spec close_connection(Handle :: connection_handle()) -> ok.
close_connection({GunPid, _Service}) ->
    gun:close(GunPid).

-spec direct_request(
    Handle :: connection_handle(),
    Method :: method(),
    Path :: path(),
    Body :: body(),
    Headers :: headers(),
    Options :: list(),
    State :: aws_state()
) -> {ok, {headers(), term()}, aws_state()} | {error, term()}.
direct_request({GunPid, Service}, Method, Path, Body, Headers, Options, State0) ->
    % Ensure we have credentials
    State1 =
        case has_credentials(State0) of
            false ->
                case refresh_credentials(State0) of
                    {ok, S} -> S;
                    {error, _} -> State0
                end;
            true ->
                State0
        end,

    case State1#aws_state.credentials of
        #aws_credentials{
            access_key = AccessKey,
            secret_key = SecretKey,
            security_token = SecurityToken
        } ->
            % Get region
            Region =
                case State1#aws_state.config of
                    #aws_config{region = R} when R =/= undefined -> R;
                    _ -> ?DEFAULT_REGION
                end,

            Host = endpoint_host(Region, Service),
            URI = create_uri(Host, Path),
            BodyHash = proplists:get_value(payload_hash, Options),
            case
                sign_headers(
                    AccessKey,
                    SecretKey,
                    SecurityToken,
                    Region,
                    Service,
                    Method,
                    URI,
                    Headers,
                    Body,
                    BodyHash
                )
            of
                {ok, SignedHeaders} ->
                    case direct_gun_request(GunPid, Method, Path, SignedHeaders, Body, Options) of
                        {ok, Response} ->
                            {ok, Response, State1};
                        Error ->
                            Error
                    end;
                {error, _} = Error ->
                    Error
            end;
        undefined ->
            {error, no_credentials}
    end.

-spec sign_headers(
    AccessKey :: access_key(),
    SecretKey :: secret_access_key(),
    SecurityToken :: security_token(),
    Region :: region(),
    Service :: string(),
    Method :: method(),
    URI :: string(),
    Headers :: headers(),
    Body :: body(),
    BodyHash :: iodata() | undefined
) -> {ok, headers()} | {error, {malformed_uri, string()}}.
sign_headers(
    AccessKey, SecretKey, SecurityToken, Region, Service, Method, URI, Headers, Body, BodyHash
) ->
    aws_lib_sign:headers(
        #request{
            access_key = AccessKey,
            secret_access_key = SecretKey,
            security_token = SecurityToken,
            region = Region,
            service = Service,
            method = Method,
            uri = URI,
            headers = Headers,
            body = Body
        },
        BodyHash
    ).

-spec request(
    Service :: string(),
    Method :: method(),
    Path :: path(),
    Body :: body(),
    Headers :: headers(),
    State :: aws_state()
) -> {ok, {headers(), term()}, aws_state()} | result_error().
%% @doc Perform a HTTP request to the AWS API for the specified service. The
%%      response will automatically be decoded if it is either in JSON or XML
%%      format.
%% @end
request(Service, Method, Path, Body, Headers, State) ->
    request(Service, Method, Path, Body, Headers, [], State).

-spec request(
    Service :: string(),
    Method :: method(),
    Path :: path(),
    Body :: body(),
    Headers :: headers(),
    HTTPOptions :: http_options(),
    State :: aws_state()
) -> {ok, {headers(), term()}, aws_state()} | result_error().
%% @doc Perform a HTTP request to the AWS API for the specified service. The
%%      response will automatically be decoded if it is either in JSON or XML
%%      format.
%% @end
request(Service, Method, Path, Body, Headers, HTTPOptions, State) ->
    request(Service, Method, Path, Body, Headers, HTTPOptions, undefined, State).

-spec request(
    Service :: string(),
    Method :: method(),
    Path :: path(),
    Body :: body(),
    Headers :: headers(),
    HTTPOptions :: http_options(),
    Endpoint :: host() | undefined,
    State :: aws_state()
) -> {ok, {headers(), term()}, aws_state()} | result_error().
%% @doc Perform a HTTP request to the AWS API for the specified service, overriding
%%      the endpoint URL to use when invoking the API. This is useful for local testing
%%      of services such as DynamoDB. The response will automatically be decoded
%%      if it is either in JSON or XML format.
%% @end
request(Service, Method, Path, Body, Headers, HTTPOptions, Endpoint, State) ->
    perform_request_direct(Service, Method, Headers, Path, Body, HTTPOptions, Endpoint, State).

-spec set_credentials(access_key(), secret_access_key(), aws_state()) -> {ok, aws_state()}.
%% @doc Manually set the access credentials for requests. This should
%%      be used in cases where the client application wants to control
%%      the credentials instead of automatically discovering them from
%%      configuration or the AWS Instance Metadata service.
%% @end
set_credentials(AccessKey, SecretAccessKey, State) ->
    Creds = #aws_credentials{
        access_key = AccessKey,
        secret_key = SecretAccessKey,
        security_token = undefined,
        expiration = undefined
    },
    {ok, State#aws_state{credentials = Creds}}.

-spec set_credentials(access_key(), secret_access_key(), security_token(), aws_state()) ->
    {ok, aws_state()}.
%% @doc Manually set the access credentials for requests. This should
%%      be used in cases where the client application wants to control
%%      the credentials instead of automatically discovering them from
%%      configuration or the AWS Instance Metadata service.
%% @end
set_credentials(AccessKey, SecretAccessKey, SecurityToken, State) ->
    Creds = #aws_credentials{
        access_key = AccessKey,
        secret_key = SecretAccessKey,
        security_token = SecurityToken,
        expiration = undefined
    },
    {ok, State#aws_state{credentials = Creds}}.

-spec ensure_credentials_valid(State :: aws_state()) -> {ok, aws_state()} | {error, term()}.
%% @doc Invoked before each AWS service API request to check if the current credentials are available and that they have not expired.
%%      If the credentials are available and are still current, then move on and perform the request.
%%      If the credentials are not available or have expired, then refresh them before performing the request.
%% @end
ensure_credentials_valid(State) ->
    ?LOG_DEBUG("Making sure AWS credentials are available and still valid"),
    case has_credentials(State) of
        true ->
            {ok, State};
        false ->
            refresh_credentials(State)
    end.

-spec perform_request_direct(
    Service :: string(),
    Method :: method(),
    Headers :: headers(),
    Path :: path(),
    Body :: body(),
    Options :: http_options(),
    Host :: string() | undefined,
    State :: aws_state()
) -> {ok, {headers(), term()}, aws_state()} | result_error().
perform_request_direct(Service, Method, Headers, Path, Body, Options, Host, State0) ->
    % Ensure we have credentials
    State1 =
        case has_credentials(State0) of
            false ->
                case refresh_credentials(State0) of
                    {ok, S} -> S;
                    {error, _} -> State0
                end;
            true ->
                State0
        end,

    % Get credentials and region from state
    case State1#aws_state.credentials of
        #aws_credentials{
            access_key = AccessKey,
            secret_key = SecretKey,
            security_token = SecurityToken
        } ->
            % Get region
            Region =
                case State1#aws_state.config of
                    #aws_config{region = R} when R =/= undefined -> R;
                    _ -> ?DEFAULT_REGION
                end,

            URI = endpoint(Region, Host, Service, Path),
            case
                sign_headers(
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
            of
                {ok, SignedHeaders} ->
                    case gun_request(Method, URI, SignedHeaders, Body, Options) of
                        {ok, Response} ->
                            {ok, Response, State1};
                        Error ->
                            Error
                    end;
                {error, _} = Error ->
                    Error
            end;
        undefined ->
            {error, no_credentials}
    end.

-spec endpoint(
    Region :: region(),
    Host :: string() | undefined,
    Service :: string(),
    Path :: string()
) -> string().
endpoint(Region, undefined, Service, Path) ->
    lists:flatten(["https://", endpoint_host(Region, Service), Path]);
endpoint(_, Host, _, Path) ->
    lists:flatten(["https://", Host, Path]).
%% @doc Construct the endpoint hostname for the request based upon the service
%%      and region.
%% @end
endpoint_host(Region, Service) ->
    lists:flatten(string:join([Service, Region, endpoint_tld(Region)], ".")).

-spec endpoint_tld(Region :: region()) -> host().
%% @doc Construct the endpoint hostname TLD for the request based upon the region.
%%      See https://docs.aws.amazon.com/general/latest/gr/rande.html#ec2_region for details.
%% @end
endpoint_tld("cn-north-1") ->
    "amazonaws.com.cn";
endpoint_tld("cn-northwest-1") ->
    "amazonaws.com.cn";
endpoint_tld("us-iso-east-1") ->
    "c2s.ic.gov";
endpoint_tld("us-iso-west-1") ->
    "c2s.ic.gov";
endpoint_tld("us-isob-east-1") ->
    "sc2s.sgov.gov";
endpoint_tld("us-isof-east-1") ->
    "csp.hci.ic.gov";
endpoint_tld("us-isof-south-1") ->
    "csp.hci.ic.gov";
endpoint_tld("eusc-de-east-1") ->
    "amazonaws.eu";
endpoint_tld(_Other) ->
    "amazonaws.com".

-spec do_refresh_credentials(State :: aws_state()) -> {ok, aws_state()} | {error, term()}.
%% @doc Refresh credentials from environment, filesystem, or EC2 Instance Metadata Service.
%% @end
do_refresh_credentials(State0) ->
    % Get or detect region
    {Region, State1} =
        case State0#aws_state.config of
            #aws_config{region = undefined} ->
                {ok, R, _} = aws_lib_config:region(#aws_config{}),
                {R, State0#aws_state{config = #aws_config{region = R}}};
            #aws_config{region = R} ->
                {R, State0}
        end,

    % Load credentials
    Config =
        case State1#aws_state.config of
            undefined -> #aws_config{region = Region};
            C -> C
        end,

    case aws_lib_config:credentials(Config) of
        {ok, Creds, Config2} ->
            {ok, State1#aws_state{credentials = Creds, config = Config2}};
        {error, Reason} ->
            {error, Reason}
    end.

-spec format_response(Response :: httpc_result()) -> result().
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

-spec expired_credentials(Expiration :: calendar:datetime()) -> boolean().
%% @doc Indicates if the date that is passed in has expired.
%% end
expired_credentials(undefined) ->
    false;
expired_credentials(Expiration) ->
    Now = calendar:datetime_to_gregorian_seconds(local_time()),
    Expires = calendar:datetime_to_gregorian_seconds(Expiration),
    Now >= Expires.

-spec local_time() -> calendar:datetime().
%% @doc Return the current local time.
%% @end
local_time() ->
    [Value] = calendar:local_time_to_universal_time_dst(calendar:local_time()),
    Value.

-spec maybe_decode_body(ContentType :: {nonempty_string(), nonempty_string()}, Body :: body()) ->
    list() | body().
%% @doc Attempt to decode the response body by its MIME
%% @end
maybe_decode_body(_, <<>>) ->
    <<>>;
maybe_decode_body({"application", "x-amz-json-1.0"}, Body) ->
    aws_lib_json:decode(Body);
maybe_decode_body({"application", "json"}, Body) ->
    aws_lib_json:decode(Body);
maybe_decode_body({_, "xml"}, Body) ->
    aws_lib_xml:parse(Body);
maybe_decode_body(_ContentType, Body) ->
    Body.

-spec parse_content_type(ContentType :: string()) -> {Type :: string(), Subtype :: string()}.
%% @doc parse a content type string returning a tuple of type/subtype
%% @end
parse_content_type(ContentType) when is_binary(ContentType) ->
    parse_content_type(binary_to_list(ContentType));
parse_content_type(ContentType) ->
    Parts = string:tokens(ContentType, ";"),
    [Type, Subtype] = string:tokens(lists:nth(1, Parts), "/"),
    {Type, Subtype}.

-spec expired_imdsv2_token('undefined' | imdsv2token()) -> boolean().
%% @doc Determine whether or not an Imdsv2Token has expired.
%% @end
expired_imdsv2_token(undefined) ->
    ?LOG_DEBUG("EC2 IMDSv2 token has not yet been obtained"),
    true;
expired_imdsv2_token(#imdsv2token{expiration = undefined}) ->
    ?LOG_DEBUG("EC2 IMDSv2 token is not available"),
    true;
expired_imdsv2_token(#imdsv2token{expiration = Expiration}) ->
    Now = calendar:datetime_to_gregorian_seconds(local_time()),
    HasExpired = Now >= Expiration,
    ?LOG_DEBUG("EC2 IMDSv2 token has expired: ~tp", [HasExpired]),
    HasExpired.

-spec get_imdsv2_token(State :: aws_state()) -> {ok, imdsv2token() | undefined}.
%% @doc return the current Imdsv2Token used to perform instance metadata service requests.
%% @end
get_imdsv2_token(#aws_state{config = #aws_config{imdsv2_token = Token}}) ->
    {ok, Token};
get_imdsv2_token(#aws_state{config = undefined}) ->
    {ok, undefined}.

-spec set_imdsv2_token(
    Token :: imdsv2token(),
    State :: aws_state()
) -> {ok, aws_state()}.
%% @doc Manually set the Imdsv2Token used to perform instance metadata service requests.
%% @end
set_imdsv2_token(Token, State = #aws_state{config = Config}) when Config =/= undefined ->
    {ok, State#aws_state{config = Config#aws_config{imdsv2_token = Token}}};
set_imdsv2_token(Token, State) ->
    {ok, State#aws_state{config = #aws_config{imdsv2_token = Token}}}.

-spec ensure_imdsv2_token_valid(State :: aws_state()) -> {ok, security_token(), aws_state()}.
ensure_imdsv2_token_valid(State0) ->
    {ok, Imdsv2Token} = get_imdsv2_token(State0),
    case expired_imdsv2_token(Imdsv2Token) of
        true ->
            Value = aws_lib_config:load_imdsv2_token(),
            Expiration =
                calendar:datetime_to_gregorian_seconds(local_time()) + ?METADATA_TOKEN_TTL_SECONDS,
            NewToken = #imdsv2token{token = Value, expiration = Expiration},
            {ok, State1} = set_imdsv2_token(NewToken, State0),
            {ok, Value, State1};
        _ ->
            {ok, Imdsv2Token#imdsv2token.token, State0}
    end.

-spec api_get_request(
    Service :: string(),
    Path :: path(),
    State :: aws_state()
) -> {ok, list(), aws_state()} | {error, term()}.
%% @doc Invoke an API call to an AWS service.
%% @end
api_get_request(Service, Path, State) ->
    ?LOG_DEBUG("invoking AWS get request {Service: ~tp; Path: ~tp}...", [Service, Path]),
    api_request_with_retries(
        Service,
        get,
        Path,
        "",
        [],
        ?MAX_RETRIES,
        ?LINEAR_BACK_OFF_MILLIS,
        State
    ).

-spec api_post_request(
    Service :: string(),
    Path :: path(),
    Body :: body(),
    Headers :: headers(),
    State :: aws_state()
) -> {ok, list(), aws_state()} | {error, term()}.
%% @doc Perform a HTTP Post request to the AWS API for the specified service. The
%%      response will automatically be decoded if it is either in JSON or XML
%%      format.
%% @end
api_post_request(Service, Path, Body, Headers, State) ->
    ?LOG_DEBUG("invoking AWS post request {Service: ~tp; Path: ~tp}...", [Service, Path]),
    api_request_with_retries(
        Service,
        post,
        Path,
        Body,
        Headers,
        ?MAX_RETRIES,
        ?LINEAR_BACK_OFF_MILLIS,
        State
    ).

-spec instance_volumes(State :: aws_state()) -> {ok, volumes_list(), aws_state()} | {error, term()}.
%% @doc Return the EBS volumes attached to the current instance from the EC2 API.
%% @end
instance_volumes(State0 = #aws_state{config = Config0}) ->
    case aws_lib_config:instance_id(Config0) of
        {ok, InstanceId, Config1} ->
            Path =
                "/?Action=DescribeVolumes&Filter.1.Name=attachment.instance-id&Filter.1.Value.1=" ++
                    InstanceId ++ "&Version=2016-11-15",
            case aws_lib:api_get_request("ec2", Path, State0) of
                {ok, Response, _State1} ->
                    case parse_volumes_response(Response) of
                        {ok, Volumes} ->
                            {ok, Volumes, State0#aws_state{config = Config1}};
                        Error ->
                            Error
                    end;
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

%% -----------------------------------------------------------------------------
%% Private / Internal Methods
%% -----------------------------------------------------------------------------

-spec api_request_with_retries(
    Service :: string(),
    Method :: method(),
    Path :: path(),
    Body :: body(),
    Headers :: headers(),
    Retries :: integer(),
    WaitTime :: integer(),
    State :: aws_state()
) ->
    {ok, list(), aws_state()} | {error, term()}.
%% @doc Invoke an API call to an AWS service with retries.
%% @end
api_request_with_retries(_Service, _Method, _Path, _Body, _Headers, Retries, _WaitTime, _State) when
    Retries =< 0
->
    ?LOG_ERROR("Request to AWS service has failed after ~b retries", [?MAX_RETRIES]),
    {error, "AWS service is unavailable"};
api_request_with_retries(Service, Method, Path, Body, Headers, Retries, WaitTime, State0) ->
    case ensure_credentials_valid(State0) of
        {ok, State1} ->
            case request(Service, Method, Path, Body, Headers, State1) of
                {ok, {_Headers, Payload}, State2} ->
                    ?LOG_DEBUG("AWS request: ~ts~nResponse: ~tp", [Path, Payload]),
                    {ok, Payload, State2};
                {error, Message, Response} ->
                    %% Message may be a status string (from format_response/1
                    %% on an HTTP error) or a tuple such as
                    %% {gun_open_failed, Reason} on a connection failure, so
                    %% use ~tp rather than ~ts.
                    ?LOG_WARNING("Error occurred: ~tp", [Message]),
                    case Response of
                        {_, Payload} ->
                            ?LOG_WARNING("Failed AWS request: ~ts~nResponse: ~tp", [
                                Path, Payload
                            ]);
                        _ ->
                            ok
                    end,
                    ?LOG_WARNING("Will retry AWS request, remaining retries: ~b", [Retries]),
                    timer:sleep(WaitTime),
                    api_request_with_retries(
                        Service, Method, Path, Body, Headers, Retries - 1, WaitTime, State1
                    )
            end;
        {error, Reason} ->
            {error, {credentials, Reason}}
    end.

%% Gun HTTP client functions
gun_request(Method, URI, Headers, Body, Options) ->
    %% A parse or connection failure is returned as {error, Reason} (not raised)
    %% so it flows through format_response/1 into the {error, _, _} shape the
    %% retry loop in api_request_with_retries/8 matches, rather than escaping it.
    case aws_lib_uri:parse(URI) of
        {ok, Uri} ->
            Host = aws_lib_uri:host(Uri),
            Port = aws_lib_uri:port(Uri),
            %% target/1 carries the query: Path is the Gun request line.
            Path = aws_lib_uri:target(Uri),
            case create_gun_connection(Host, Port, Options) of
                {ok, GunPid} ->
                    Reply = direct_gun_request(GunPid, Method, Path, Headers, Body, Options),
                    gun:close(GunPid),
                    Reply;
                {error, _Reason} = Error ->
                    format_response(Error)
            end;
        {error, _Reason} = Error ->
            format_response(Error)
    end.

do_gun_request(ConnPid, get, Path, Headers, _Body) ->
    gun:get(ConnPid, Path, Headers);
do_gun_request(ConnPid, post, Path, Headers, Body) ->
    gun:post(ConnPid, Path, Headers, Body, #{});
do_gun_request(ConnPid, put, Path, Headers, Body) ->
    gun:put(ConnPid, Path, Headers, Body, #{});
do_gun_request(ConnPid, head, Path, Headers, _Body) ->
    gun:head(ConnPid, Path, Headers, #{});
do_gun_request(ConnPid, delete, Path, Headers, _Body) ->
    gun:delete(ConnPid, Path, Headers, #{});
do_gun_request(ConnPid, patch, Path, Headers, Body) ->
    gun:patch(ConnPid, Path, Headers, Body, #{});
do_gun_request(ConnPid, options, Path, Headers, _Body) ->
    gun:options(ConnPid, Path, Headers, #{}).

create_gun_connection(Host, Port, Options) ->
    % Map HTTP version to Gun protocols, always include http as fallback
    HttpVersion = proplists:get_value(version, Options, "HTTP/1.1"),
    Protocols =
        case HttpVersion of
            "HTTP/2" -> [http2, http];
            "HTTP/2.0" -> [http2, http];
            "HTTP/1.1" -> [http];
            "HTTP/1.0" -> [http];
            % Default: try HTTP/2, fallback to HTTP/1.1
            _ -> [http2, http]
        end,
    ConnectTimeout = proplists:get_value(connect_timeout, Options, infinity),
    Opts = #{
        transport =>
            if
                Port == 443 -> tls;
                true -> tcp
            end,
        protocols => Protocols,
        connect_timeout => ConnectTimeout
    },
    case gun:open(Host, Port, Opts) of
        {ok, ConnPid} ->
            case gun:await_up(ConnPid, ConnectTimeout) of
                {ok, _Protocol} ->
                    {ok, ConnPid};
                {error, Reason} ->
                    gun:close(ConnPid),
                    {error, {gun_connection_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {gun_open_failed, Reason}}
    end.

create_uri(Host, Path) when is_list(Path) ->
    "https://" ++ Host ++ Path;
create_uri(Host, {Bucket, Key}) ->
    "https://" ++ Bucket ++ "." ++ Host ++ "/" ++ Key.

status_text(200) -> "OK";
status_text(206) -> "Partial Content";
status_text(400) -> "Bad Request";
status_text(401) -> "Unauthorized";
status_text(403) -> "Forbidden";
status_text(404) -> "Not Found";
status_text(416) -> "Range Not Satisfiable";
status_text(500) -> "Internal Server Error";
status_text(Code) -> integer_to_list(Code).

-spec direct_gun_request(
    GunPid :: pid(),
    Method :: method(),
    Path :: path(),
    Headers :: headers(),
    Body :: body(),
    Options :: list()
) -> result().
direct_gun_request(GunPid, Method, {_, Path}, Headers, Body, Options) ->
    direct_gun_request(GunPid, Method, [$/ | Path], Headers, Body, Options);
direct_gun_request(GunPid, Method, Path, Headers, Body, Options) ->
    HeadersBin = lists:map(
        fun({Key, Value}) ->
            {list_to_binary(Key), list_to_binary(Value)}
        end,
        Headers
    ),
    Timeout = proplists:get_value(timeout, Options, ?DEFAULT_HTTP_TIMEOUT),
    Response =
        try
            StreamRef = do_gun_request(GunPid, Method, Path, HeadersBin, Body),
            case gun:await(GunPid, StreamRef, Timeout) of
                {response, fin, Status, RespHeaders} ->
                    {ok, {{http_version, Status, status_text(Status)}, RespHeaders, <<>>}};
                {response, nofin, Status, RespHeaders} ->
                    %% await_body/3 can return {error, timeout} (and other
                    %% {error, _} reasons); surface it cleanly rather than
                    %% letting a hard match turn it into a {badmatch, _} term.
                    case gun:await_body(GunPid, StreamRef, Timeout) of
                        {ok, RespBody} ->
                            {ok, {
                                {http_version, Status, status_text(Status)}, RespHeaders, RespBody
                            }};
                        {error, Reason} ->
                            {error, Reason}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end
        catch
            _:Error ->
                {error, Error}
        end,
    format_response(Response).

-spec parse_volumes_response(term()) -> {'ok', volumes_list()} | {'error', 'parse_error'}.
%% @doc Parse the DescribeVolumes XML response into a list of volume information.
%% @end
parse_volumes_response([{"DescribeVolumesResponse", VolumeData}]) ->
    case proplists:get_value("volumeSet", VolumeData, []) of
        [] ->
            {ok, []};
        VolumeSet when is_list(VolumeSet) ->
            Volumes = lists:map(fun parse_volume/1, VolumeSet),
            {ok, Volumes};
        _ ->
            {error, parse_error}
    end;
parse_volumes_response(_) ->
    {error, parse_error}.

-spec parse_volume(term()) -> volume_info().
%% @doc Parse individual volume data from XML response.
%% @end
parse_volume({"item", VolumeProps}) ->
    VolumeId = proplists:get_value("volumeId", VolumeProps, ""),
    Size = proplists:get_value("size", VolumeProps, ""),
    VolumeType = proplists:get_value("volumeType", VolumeProps, ""),
    State = proplists:get_value("status", VolumeProps, ""),

    AttachmentSet = proplists:get_value("attachmentSet", VolumeProps, []),
    Attachment =
        case AttachmentSet of
            [{"item", AttachProps}] ->
                [
                    {device, proplists:get_value("device", AttachProps, "")},
                    {state, proplists:get_value("status", AttachProps, "")}
                ];
            _ ->
                []
        end,

    [
        {volume_id, VolumeId},
        {size, Size},
        {volume_type, VolumeType},
        {state, State},
        {attachment, Attachment}
    ];
parse_volume(_) ->
    [].
