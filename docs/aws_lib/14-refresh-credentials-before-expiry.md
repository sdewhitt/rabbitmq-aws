---
title: "`aws_lib`: Refresh credentials before expiry, not after (add buffer window)"
type: bug
labels: [bug]
related: [08]
---

# `aws_lib`: Refresh credentials before expiry, not after (add buffer window)

## Problem

`expired_credentials/1` only treats credentials as expired once the expiration time has actually passed:

```erlang
expired_credentials(Expiration) ->
    Now = calendar:datetime_to_gregorian_seconds(local_time()),
    Expires = calendar:datetime_to_gregorian_seconds(Expiration),
    Now >= Expires.
```

This means credentials valid for one more second pass the check. A request using them may then fail mid-flight when the credentials expire during the request, returning an authentication error rather than transparently refreshing.

## Reference

Both erlcloud and boto3 refresh credentials proactively when they are within a buffer window of expiry. erlcloud uses 5 minutes:

```erlang
%% Get new credentials if these will expire in less than 5 minutes
case Expiration - Now < 300 of
    true -> Fun(Config);
    false -> {ok, Credentials}
end
```

boto3 uses 15 minutes for the advisory refresh and 10 minutes for mandatory refresh.

## Proposed fix

Add a refresh buffer (e.g., 5 minutes) to `expired_credentials/1` so credentials are refreshed before they expire, not after:

```erlang
expired_credentials(Expiration) ->
    Now = calendar:datetime_to_gregorian_seconds(erlang:universal_time()),
    Expires = calendar:datetime_to_gregorian_seconds(Expiration),
    Now >= (Expires - ?CREDENTIAL_REFRESH_BUFFER_SECONDS).
```

Note: this interacts with [the `local_time()` DST bug](08-local-time-dst-crash.md) - the fix should use `calendar:universal_time()`.
