---
title: "`aws_lib`: Handle all 2xx status codes as success in format_response"
type: bug
labels: [bug]
---

# `aws_lib`: Handle all 2xx status codes as success in format_response

## Problem

`format_response/1` only handles status codes 200, 206, and 400+. Any response with status 201, 202, 204, or 3xx will crash with a `function_clause` error because no clause matches.

aws-erlang handles 200, 202, 204, 206 as success. Some AWS APIs return 201 (Created) or 204 (No Content) on success.

## Current code

```erlang
format_response({ok, {{_Version, 200, _Message}, Headers, Body}}) ->
    {ok, {Headers, maybe_decode_body(get_content_type(Headers), Body)}};
format_response({ok, {{_Version, 206, _Message}, Headers, Body}}) ->
    {ok, {Headers, maybe_decode_body(get_content_type(Headers), Body)}};
format_response({ok, {{_Version, StatusCode, Message}, Headers, Body}}) when StatusCode >= 400 ->
    {error, Message, {Headers, maybe_decode_body(get_content_type(Headers), Body)}};
format_response({error, Reason}) ->
    {error, Reason, undefined}.
```

## Proposed fix

Handle all 2xx status codes as success, 3xx-5xx as error:

```erlang
format_response({ok, {{_Version, StatusCode, _Message}, Headers, Body}})
  when StatusCode >= 200, StatusCode < 300 ->
    {ok, {Headers, maybe_decode_body(get_content_type(Headers), Body)}};
format_response({ok, {{_Version, _StatusCode, Message}, Headers, Body}}) ->
    {error, Message, {Headers, maybe_decode_body(get_content_type(Headers), Body)}};
format_response({error, Reason}) ->
    {error, Reason, undefined}.
```
