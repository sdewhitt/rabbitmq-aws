---
title: "`aws_lib`: Default request timeout (2250ms) is too aggressive for AWS API calls"
type: bug
labels: [bug]
modules: [aws_lib]
---

# `aws_lib`: Default request timeout (2250ms) is too aggressive for AWS API calls

## Problem

`?DEFAULT_HTTP_TIMEOUT` is 2250ms and is used as the default timeout for AWS API requests in `direct_gun_request`:

```erlang
Timeout = proplists:get_value(timeout, Options, ?DEFAULT_HTTP_TIMEOUT),
```

The comment in `aws_lib.hrl` explains the value:

```
% Note: this timeout must not be greater than the default
% gen_server:call timeout of 5000ms.
```

This constraint came from the old gen_server architecture where `request/5` was a `gen_server:call`. That gen_server no longer exists - requests are now direct function calls with no call timeout.

2250ms is too aggressive for many AWS API operations. Operations like `CreateSnapshot`, S3 uploads, or DynamoDB batch writes can routinely exceed this.

## Reference

erlcloud stores a configurable `timeout` in `aws_config` (via `erlcloud_aws:get_timeout/1`) and threads it through every request. The default is 10000ms. Timeout is a per-config concern, not a compile-time constant.

## Proposed fix

1. Separate the IMDS timeout (2250ms is appropriate for the local metadata service) from the AWS API timeout.
2. Set a more reasonable default for AWS API requests (e.g., 30000ms, matching the AWS SDK defaults).
3. Make the timeout configurable via `aws_config()` so it threads through state rather than being a compile-time constant.
4. Remove the outdated gen_server comment.
