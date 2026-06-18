---
title: "`aws_lib`: Add response classification to avoid retrying non-retriable errors"
type: refactor
labels: [refactor]
related: [02, 06]
---

# `aws_lib`: Add response classification to avoid retrying non-retriable errors

## Problem

`api_request_with_retries` currently retries on any `{error, Message, Response}` return from `request/6`, including 4xx client errors (bad request, not found, access denied) that will never succeed on retry.

aws-erlang has an explicit `classify_response/1` function that returns `ok | error | retriable`, distinguishing between:
- **retriable**: 5xx, connection closed, timeout, checkout_timeout, service_unavailable
- **error**: 4xx, other non-retriable failures
- **ok**: 2xx success

erlcloud takes a similar approach with a pluggable response-type function (`Config#aws_config.retry_response_type`) plus helpers like `only_http_errors/1` and `lambda_fun_errors/1`. It also has `is_throttling_error_response/1` which treats HTTP 429 and any response body containing `Throttl` as retriable - throttling/rate-limit errors are a special case that SHOULD be retried (with backoff) even though they may surface as 400-class errors.

## Current behavior

All non-success responses are retried up to 5 times with 500ms delay, wasting time on permanent failures. Conversely, there is no special handling for throttling responses.

## Proposed behavior

Add a `classify_response/1` function that determines whether a failed response should be retried:
- Retry on 5xx status codes and transient transport errors (closed, timeout)
- Retry on throttling responses (HTTP 429, or error code/body indicating `Throttling`/`ThrottlingException`/`RequestLimitExceeded`)
- Return other 4xx errors immediately to the caller

Related: [backoff strategy](02-exponential-backoff-jitter.md), [decoupling retry logic](06-decouple-retry-logic.md).
