---
title: "`aws_lib`: Logging crash in retry loop when error is a tuple"
type: bug
labels: [bug]
related: [19]
---

# `aws_lib`: Logging crash in retry loop when error is a tuple

## Problem

In `api_request_with_retries`, the error logging uses `~ts` format:

```erlang
?LOG_WARNING("Error occurred: ~ts", [Message]),
```

`Message` here is the `Message` element of a `{error, Message, Response}` return from `request/6`, which originates in `format_response/1`. On a transport error from `gun:await/3` it is the raw `Reason` term (e.g. `{stream_error, _}` or `timeout` from the await), not necessarily a string. The `~ts` format directive expects a string or binary and crashes with `badarg` when given a non-string term such as a tuple.

Note: the connection-open failures `{gun_open_failed, _}` and `{gun_connection_failed, _}` do *not* reach this log line - they are raised as exceptions from `create_gun_connection/3` and escape the retry loop entirely before any error tuple is produced. See [connection-open failures bypass the retry loop](19-connection-open-failures-bypass-retry.md).

Verified:

```erlang
> io_lib:format("~ts", [{foo, bar}]).
** exception error: bad argument
```

## Impact

The retry loop crashes on the logging call instead of retrying. The request fails with an unrelated exception rather than the actual connection error.

## Fix

Use `~tp` instead of `~ts` for error messages that may be arbitrary terms:

```erlang
?LOG_WARNING("Error occurred: ~tp", [Message]),
```
