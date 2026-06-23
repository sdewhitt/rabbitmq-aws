---
title: "`aws_lib`: local_time() crashes during DST fall-back transition"
type: bug
labels: [bug]
modules: [aws_lib, aws_lib_sign]
---

# `aws_lib`: local_time() crashes during DST fall-back transition

## Problem

`local_time()` in both `aws_lib.erl` and `aws_lib_sign.erl` uses this pattern:

```erlang
local_time() ->
    [Value] = calendar:local_time_to_universal_time_dst(calendar:local_time()),
    Value.
```

During DST "fall back" transitions (e.g., the first Sunday of November in the US), `calendar:local_time_to_universal_time_dst/1` returns a list of TWO datetimes because the local time is ambiguous. The `[Value] =` pattern match will crash with `badmatch`.

Verified:

```erlang
> calendar:local_time_to_universal_time_dst({{2024,11,3},{1,30,0}}).
[{{2024,11,3},{8,30,0}},{{2024,11,3},{9,30,0}}]
```

## Impact

Any request or credential refresh occurring during the ~1 hour DST transition window will crash the caller. This affects both request signing timestamps and credential expiration checks.

## Fix

Use `calendar:universal_time()` directly, as aws-erlang does:

```erlang
aws_signature:sign_v4(AccessKeyID, SecretAccessKey, Region, Service,
                      calendar:universal_time(), Method, URL, Headers, Body, Options)
```

This avoids the local-to-UTC conversion entirely and eliminates the DST ambiguity.
