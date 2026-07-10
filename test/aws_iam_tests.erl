-module(aws_iam_tests).

-include_lib("eunit/include/eunit.hrl").
-include("aws_lib.hrl").

%% End-to-end guard for the STS AssumeRole response path: a real AssumeRole XML
%% document decoded by aws_lib_xml:parse/1 must still thread the returned
%% credentials into the state. This pins the shape parse_assume_role_response/2
%% depends on, so a change to the XML parser cannot silently break it.
parse_assume_role_response_test_() ->
    [
        {"credentials are threaded into the state", fun() ->
            Xml =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<AssumeRoleResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">"
                "<AssumeRoleResult>"
                "<Credentials>"
                "<AccessKeyId>AKIDEXAMPLE</AccessKeyId>"
                "<SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>"
                "<SessionToken>AQoEXAMPLEtoken</SessionToken>"
                "<Expiration>2026-01-01T00:00:00Z</Expiration>"
                "</Credentials>"
                "</AssumeRoleResult>"
                "</AssumeRoleResponse>",
            Body = aws_lib_xml:parse(Xml),
            {ok, State} = aws_iam:parse_assume_role_response(Body, aws_lib:new()),
            {ok, Creds} = aws_lib:get_credentials(State),
            ?assertEqual("AKIDEXAMPLE", Creds#aws_credentials.access_key),
            ?assertEqual(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Creds#aws_credentials.secret_key
            ),
            ?assertEqual("AQoEXAMPLEtoken", Creds#aws_credentials.security_token)
        end}
    ].
