---
title: "`aws_lib`: Expose decoded AWS error details to callers of api_get_request and api_post_request"
type: enhancement
labels: [enhancement]
related: [01]
---

# `aws_lib`: Expose decoded AWS error details to callers of api_get_request and api_post_request

## Problem

`api_get_request/3` and `api_post_request/5` discard the decoded error body when a request fails after all retries. The final return to callers is `{error, "AWS service is unavailable"}` - a generic string that tells the caller nothing about what went wrong.

Meanwhile, `format_response` already decodes the response body on 4xx/5xx errors, producing structured data like `[{"Error", [{"Code", "ThrottlingException"}, {"Message", "Rate exceeded"}]}]`. This information is available inside the retry loop but lost before it reaches the caller.

## Why this matters

Callers need to distinguish between failure modes:
- "ThrottlingException" - back off and retry at a higher level
- "InvalidParameterValue" - fix the request, don't retry
- "ResourceNotFoundException" - handle gracefully
- "AccessDeniedException" - credential/permission issue

## Proposed behavior

When `api_request_with_retries` exhausts retries or encounters a non-retriable error (once [response classification](01-response-classification-non-retriable.md) is implemented), return the decoded AWS error to the caller rather than a generic string. The exact shape is a design decision - options include:

1. Return the last `result_error()` as-is: `{error, Message, {Headers, DecodedBody}}`
2. Return a simplified form: `{error, {ServiceError, DecodedBody}}`
3. Keep the current `{error, term()}` spec but populate it with the actual error

This interacts with [response classification](01-response-classification-non-retriable.md) since non-retriable errors would be returned immediately with their full context.
