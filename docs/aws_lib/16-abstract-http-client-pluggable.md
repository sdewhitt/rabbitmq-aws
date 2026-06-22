---
title: "`aws_lib`: Abstract HTTP client behind a pluggable interface"
type: refactor
labels: [refactor]
modules: [aws_lib, aws_lib_config, aws_lib_httpc]
related: [11, 12]
---

# `aws_lib`: Abstract HTTP client behind a pluggable interface

## Observation

aws_lib hardcodes Gun as the HTTP client throughout `aws_lib.erl` and `aws_lib_config.erl` - `gun:open`, `gun:await_up`, `gun:get`, `gun:await`, `gun:await_body`, `gun:close` are called directly in many places.

## Reference

erlcloud abstracts the HTTP client behind a single pluggable interface (`erlcloud_httpc`):

```erlang
-type request_fun() ::
    lhttpc | httpc | hackney |
    {module(), atom()} |
    fun((URL, Method, Headers, Body, Timeout, Config) -> result()).
```

The client is selected via `Config#aws_config.http_client` and all request code goes through `erlcloud_httpc:request/6`. This gives:

1. **Testability** - tests inject a fun that returns canned responses, no need to mock `gun` (the current tests mock `gun` extensively with `meck`, which couples tests to Gun's exact API).
2. **Flexibility** - users can bring their own client (httpc for zero deps, hackney/lhttpc for pooling).
3. **A single conversion boundary** - binary/string conversion, header normalization, and response shaping happen in one place instead of being scattered.

## Proposed behavior

Introduce an `aws_lib_httpc` abstraction module with a single `request/N` entry point. Route all HTTP calls (both AWS API requests and IMDS/metadata requests) through it. Default to Gun, but allow overriding via `aws_config()`.

This is a larger refactor but it would simplify the codebase considerably - the metadata request code in `aws_lib_config` currently duplicates the full Gun open/await/body/close dance three times (`perform_http_get_with_conn`, `perform_http_get_instance_metadata`, `load_imdsv2_token`).

Related: [duplicated Gun await_body error handling](11-gun-await-body-timeout-badmatch.md), [connection reuse](12-one-shot-tls-connection-per-attempt.md).
