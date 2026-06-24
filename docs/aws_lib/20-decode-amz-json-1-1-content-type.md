---
title: "`aws_lib`: maybe_decode_body does not decode application/x-amz-json-1.1 responses"
type: bug
labels: [bug]
modules: [aws_lib]
related: [04]
---

# `aws_lib`: maybe_decode_body does not decode application/x-amz-json-1.1 responses

## Problem

`maybe_decode_body/2` only recognizes two JSON content types - `application/x-amz-json-1.0` and `application/json`:

```erlang
maybe_decode_body(_, <<>>) ->
    <<>>;
maybe_decode_body({"application", "x-amz-json-1.0"}, Body) ->
    aws_lib_json:decode(Body);
maybe_decode_body({"application", "json"}, Body) ->
    aws_lib_json:decode(Body);
maybe_decode_body({_, "xml"}, Body) ->
    aws_lib_xml:parse(Body);
maybe_decode_body(_ContentType, Body) ->
    Body.
```

AWS services using the JSON 1.1 protocol respond with `Content-Type: application/x-amz-json-1.1`. That subtype (`x-amz-json-1.1`) matches none of the clauses, so the body falls through to the catch-all and is returned **undecoded**, despite the documented contract that responses "will automatically be decoded if it is either in JSON or XML format".

## Why this matters for the migration

Secrets Manager is a JSON 1.1 service, and the plugin's `aws_sms:fetch_secret/2` already sends `{"Content-Type", "application/x-amz-json-1.1"}`. Today the plugin decodes the response body itself (`rabbit_json:decode`), so the gap is latent. Once `aws_sms` migrates to `aws_lib:api_post_request/5` (issue #53) and relies on the library's auto-decoding, it would receive a raw binary instead of a decoded structure.

## Fix

Match all AWS JSON subtypes, for example by treating any `application/x-amz-json-*` and any `*+json` subtype as JSON:

```erlang
maybe_decode_body({"application", "x-amz-json-1.0"}, Body) -> aws_lib_json:decode(Body);
maybe_decode_body({"application", "x-amz-json-1.1"}, Body) -> aws_lib_json:decode(Body);
maybe_decode_body({"application", "json"}, Body) -> aws_lib_json:decode(Body);
```

or, more robustly, classify the subtype with a helper that catches `json`, `x-amz-json-1.0`, and `x-amz-json-1.1`.

Related: [handling all 2xx status codes](04-handle-all-2xx-as-success.md) - both are gaps in `format_response`/response decoding.
