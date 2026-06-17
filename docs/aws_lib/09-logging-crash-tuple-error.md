---
title: "`aws_lib`: Logging crash in retry loop when error is a tuple"
type: bug
labels: [bug]
---

# `aws_lib`: Logging crash in retry loop when error is a tuple

## Problem

In `api_request_with_retries`, the error logging uses `~ts` format:

```erlang
?LOG_WARNING("Error occurred: ~ts", [Message]),
```

When a Gun connection fails, `Message` is a tuple like `{gun_connection_failed, timeout}` or `{gun_open_failed, econnrefused}`. The `~ts` format directive expects a string or binary and crashes with `badarg` when given a tuple.

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
