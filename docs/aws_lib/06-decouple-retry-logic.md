---
title: "`aws_lib`: Decouple retry logic from request functions"
type: refactor
labels: [refactor]
related: [01, 02]
---

# `aws_lib`: Decouple retry logic from request functions

## Problem

`api_request_with_retries` calls `ensure_credentials_valid` before each attempt, but a credential failure at this point returns `{error, {credentials, Reason}}` immediately. There is no mechanism for callers to configure retry behavior - the constants are compiled in:

- `?MAX_RETRIES` (5)
- `?LINEAR_BACK_OFF_MILLIS` (500)

## Reference implementations

aws-erlang decouples retry from the request logic entirely. The request function is wrapped in a closure and passed to `aws_request:request(RequestFun, Options)`, where `Options` can include `retry_options` to configure the retry strategy.

erlcloud goes further with a fully pluggable retry function stored in config:

```erlang
-type retry_fun() :: fun((#aws_request{}) -> should_retry()).
-type should_retry() :: {retry | error, #aws_request{}}.
```

The config carries `retry` (the retry decision function), `retry_num` (max attempts), and `retry_response_type` (classifies a response as ok/error). Callers can supply `no_retry/1`, `default_retry/1`, or their own. This makes retry behavior per-config and testable in isolation - `erlcloud_retry:request/3` has no knowledge of the specific service or HTTP client.

## Current behavior

Retry is hardcoded inside `api_request_with_retries`. The lower-level `request/6-8` functions have no retry at all - callers must implement their own.

## Proposed behavior

Extract retry into a standalone function that accepts a request closure and options:

```erlang
-spec with_retries(fun(() -> Result), retry_options()) -> Result.
```

This would allow both the high-level `api_get_request`/`api_post_request` functions and external callers to use configurable retry with the same mechanism. The retry strategy (max attempts, backoff, response classification) should be configurable, ideally carried in `aws_config()` so it threads through state.

Related: [response classification](01-response-classification-non-retriable.md), [backoff strategy](02-exponential-backoff-jitter.md).
