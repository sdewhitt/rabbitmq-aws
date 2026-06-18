---
title: "`aws_lib`: One-shot requests create a fresh TLS connection per attempt"
type: enhancement
labels: [enhancement]
modules: [aws_lib]
---

# `aws_lib`: One-shot requests create a fresh TLS connection per attempt

## Problem

The one-shot request path (`request/6-8` -> `perform_request_direct` -> `gun_request`) creates a fresh TCP+TLS connection for every single request and tears it down immediately after:

```erlang
gun_request(Method, URI, Headers, Body, Options) ->
    {Host, Port, Path} = parse_uri(URI),
    GunPid = create_gun_connection(Host, Port, Options),
    Reply = direct_gun_request(GunPid, Method, Path, Headers, Body, Options),
    gun:close(GunPid),
    Reply.
```

A TLS handshake to an AWS endpoint adds 50-150ms per request. For retry loops (up to 5 attempts), this means up to 750ms of TLS handshake overhead alone.

aws-erlang uses hackney which has built-in connection pooling. The `open_connection/2` + `direct_request/7` API in aws_lib provides explicit connection reuse, but the default path (which `api_get_request` and `api_post_request` use) always creates fresh connections.

## Proposed behavior

Reuse the connection within `api_request_with_retries` - open once, retry on the same connection, close when done. This requires handling the case where a connection goes stale between retries (reconnect on failure).

Alternatively, integrate a Gun connection pool so all one-shot requests benefit from connection reuse.
