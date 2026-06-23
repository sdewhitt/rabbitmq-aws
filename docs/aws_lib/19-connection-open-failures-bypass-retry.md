---
title: "`aws_lib`: Connection-open failures bypass the retry loop and crash the caller"
type: bug
labels: [bug]
modules: [aws_lib]
related: [01, 09, 12]
---

# `aws_lib`: Connection-open failures bypass the retry loop and crash the caller

## Problem

`create_gun_connection/3` signals connection failures by raising an exception rather than returning an error tuple:

```erlang
case gun:open(Host, Port, Opts) of
    {ok, ConnPid} ->
        case gun:await_up(ConnPid, ConnectTimeout) of
            {ok, _Protocol} ->
                ConnPid;
            {error, Reason} ->
                gun:close(ConnPid),
                error({gun_connection_failed, Reason})
        end;
    {error, Reason} ->
        error({gun_open_failed, Reason})
end.
```

The one-shot request path calls it from `gun_request/5`:

```erlang
gun_request(Method, URI, Headers, Body, Options) ->
    {Host, Port, Path} = parse_uri(URI),
    GunPid = create_gun_connection(Host, Port, Options),
    ...
```

Only the request/response exchange in `direct_gun_request/6` is wrapped in a try/catch. `create_gun_connection/3` runs *before* that, and neither `gun_request/5`, `perform_request_direct/8`, nor the `case request(...)` clause in `api_request_with_retries/8` catches exceptions. As a result, a raised `{gun_open_failed, _}` / `{gun_connection_failed, _}` propagates straight out of the retry loop.

## Impact

The most common transient failures - `econnrefused`, connect timeout, DNS failure, TLS handshake failure - all surface from `gun:open`/`gun:await_up` and are therefore raised as exceptions. These are exactly the failures the retry loop exists to absorb, yet they crash the entire call instead of being retried. The retry machinery only ever observes errors that come back from `gun:await/3` (which is inside the try/catch); a connection that never comes up is never retried.

## Fix

Make connection failures return an error tuple that flows through `format_response/1` and the existing retry path, instead of raising. For example, have `create_gun_connection/3` return `{ok, ConnPid} | {error, Reason}` and have `gun_request/5` short-circuit to `{error, Reason, undefined}` on failure, so `api_request_with_retries/8` treats it as a retriable error.

This interacts with [response classification](01-response-classification-non-retriable.md) (connect errors should be classified retriable), with [the logging crash](09-logging-crash-tuple-error.md) (the same error terms reach the log call), and with [connection reuse](12-one-shot-tls-connection-per-attempt.md) (a reuse strategy must still handle connect failures).
