---
title: "`aws_lib`: gun:await_body timeout crashes aws_lib_config with badmatch"
type: bug
labels: [bug]
modules: [aws_lib_config]
---

# `aws_lib`: gun:await_body timeout crashes aws_lib_config with badmatch

## Problem

In `aws_lib_config.erl`, calls to `gun:await_body/3` use assertive pattern matching:

```erlang
{ok, Body} = gun:await_body(ConnPid, StreamRef, ?DEFAULT_HTTP_TIMEOUT),
```

`gun:await_body/3` can return `{error, timeout}` or `{error, Reason}` if the body delivery times out or the connection drops after headers have been received. These calls are NOT inside a try/catch block, so a timeout on body delivery crashes with `badmatch`.

This affects:
- `perform_http_get_with_conn/3`
- `perform_http_get_instance_metadata/2`
- `load_imdsv2_token/0`

## Impact

If the EC2 Instance Metadata Service responds with headers (200 status) but the body delivery is delayed beyond 2250ms, credential loading crashes instead of returning `{error, timeout}`.

## Fix

Handle the error case from `gun:await_body`:

```erlang
case gun:await_body(ConnPid, StreamRef, ?DEFAULT_HTTP_TIMEOUT) of
    {ok, Body} -> ...;
    {error, Reason} -> {error, Reason}
end
```
