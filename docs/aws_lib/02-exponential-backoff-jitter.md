---
title: "`aws_lib`: Replace fixed retry delay with exponential backoff and jitter"
type: refactor
labels: [refactor]
related: [01, 06]
---

# `aws_lib`: Replace fixed retry delay with exponential backoff and jitter

## Problem

`api_request_with_retries` uses a fixed 500ms delay (`?LINEAR_BACK_OFF_MILLIS`) between every retry attempt. When a service is under load, all retrying clients wake up at the same cadence and send requests in sync, amplifying the problem.

## Reference implementations

aws-erlang uses exponential backoff with jitter:

```erlang
Temp = min(CapSleepTime, BaseSleepTime * trunc(math:pow(2, N))),
Sleep = Temp div 2 + rand:uniform(Temp div 2)
```

erlcloud uses a simpler exponential backoff with full jitter:

```erlang
backoff(1) -> ok;
backoff(Attempt) ->
    timer:sleep(erlcloud_util:rand_uniform((1 bsl (Attempt - 1)) * 100)).
```

Both spread retry attempts over time and reduce contention on recovering services.

## Proposed behavior

Replace the fixed 500ms delay with exponential backoff and jitter, configurable via base sleep time, cap, and max attempts - similar to aws-erlang's `{exponential_with_jitter, {MaxAttempts, BaseSleepTime, CapSleepTime}}` pattern.

Related: [response classification](01-response-classification-non-retriable.md), [decoupling retry logic](06-decouple-retry-logic.md).
