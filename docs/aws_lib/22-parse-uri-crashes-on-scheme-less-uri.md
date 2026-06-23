---
title: "`aws_lib`: parse_uri crashes on a scheme-less or malformed URI"
type: bug
labels: [bug]
modules: [aws_lib]
---

# `aws_lib`: parse_uri crashes on a scheme-less or malformed URI

## Problem

`aws_lib:parse_uri/1` assumes the input always contains a `://` scheme separator:

```erlang
parse_uri(URI) ->
    case string:split(URI, "://", leading) of
        [Scheme, Rest] ->
            case string:split(Rest, "/", leading) of
                [HostPort] ->
                    {Host, Port} = parse_host_port(HostPort, Scheme),
                    {Host, Port, "/"};
                [HostPort, Path] ->
                    {Host, Port} = parse_host_port(HostPort, Scheme),
                    {Host, Port, "/" ++ Path}
            end
    end.
```

When the URI has no `://`, `string:split/3` returns a single-element list `[URI]`, which matches neither clause of the `case`, so the call crashes with `case_clause`. There is no clause for malformed or relative input - the function only ever succeeds for a well-formed `scheme://host[:port][/path]` string.

## Impact

Low today: every internal caller builds the URI from a known-good template (`endpoint/4`, `instance_metadata_url/1`), so the `://` is always present. The risk is that `parse_uri/1` is a general-looking helper with no input validation - any future caller passing a scheme-less host, a relative path, or an empty string gets a hard `case_clause` crash rather than an `{error, _}` return.

Note this differs from `aws_lib_uri:parse/1`, which delegates to `uri_string:parse/1` and is more tolerant; the two URI paths in the codebase do not behave the same way on malformed input.

## Fix

Add a fallback clause that either returns `{error, badarg}` (and have callers handle it) or treats a scheme-less input as a default `https` host. For example:

```erlang
parse_uri(URI) ->
    case string:split(URI, "://", leading) of
        [_Scheme, _Rest] = Parts -> parse_uri_parts(Parts);
        [_NoScheme] -> {error, {malformed_uri, URI}}
    end.
```
