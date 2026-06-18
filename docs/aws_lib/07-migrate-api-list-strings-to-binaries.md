---
title: "`aws_lib`: Consider migrating API from list strings to binaries"
type: refactor
labels: [refactor]
modules: [aws_lib, aws_lib_config, aws_lib_json]
---

# `aws_lib`: Consider migrating API from list strings to binaries

## Problem

aws_lib uses Erlang list strings throughout its API (headers, paths, regions, credentials, etc.). aws-erlang and the broader Erlang ecosystem (Gun, hackney, uri_string) use binaries. This means aws_lib must convert between binaries and lists at every boundary:

- `direct_gun_request` converts all header keys/values to binary before sending
- `aws_lib_json:decode` converts all thoas binary output back to list strings
- `aws_lib_config:parse_credentials_response` converts binary JSON values to lists
- Callers working with modern Erlang libraries must convert to lists before calling aws_lib

This creates unnecessary allocations and makes interop awkward.

## Context

The original rabbitmq_aws was written for httpc which uses list strings. The migration to Gun already requires binary conversion at the transport layer. The JSON library (thoas) returns binaries natively.

## Proposed behavior

Move to binaries for the public API. This is a breaking change but the library is pre-alpha with no external consumers yet.

Key areas:
- Headers: `[{binary(), binary()}]`
- Paths, service names, regions: `binary()`
- Credentials: `binary()`
- Response bodies from JSON/XML: return native types (maps with binary keys from thoas, or keep proplists but with binary values)

This eliminates the conversion layers and aligns with Gun, uri_string, and thoas natively.
