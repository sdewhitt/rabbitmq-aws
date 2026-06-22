---
title: "`aws_lib`: Support AWS_ENDPOINT_URL override for local development"
type: enhancement
labels: [enhancement]
modules: [aws_lib]
---

# `aws_lib`: Support AWS_ENDPOINT_URL override for local development

## Problem

aws_lib hardcodes `https://` for all AWS service endpoints. There is no way to use a local development endpoint (LocalStack, moto, DynamoDB Local) over plain HTTP or on a custom port without going through the `request/8` Endpoint parameter.

aws-erlang supports this via the client map which carries `proto`, `port`, and `endpoint` fields. It also supports the standard `AWS_ENDPOINT_URL` and per-service `AWS_ENDPOINT_URL_<SERVICE>` environment variables that the AWS CLI v2 and all official SDKs support.

## Current behavior

- `endpoint/4` always prepends `https://`
- `open_connection/3` always uses port 443 and TLS
- No support for `AWS_ENDPOINT_URL` env vars

## Proposed behavior

1. Support `AWS_ENDPOINT_URL` and `AWS_ENDPOINT_URL_<SERVICE>` environment variables (matching the official AWS SDK convention)
2. Allow custom scheme (http/https) and port in the endpoint configuration
3. Store endpoint override in `aws_config()` so it threads through state like everything else

This enables local testing with tools like LocalStack without mocking the HTTP layer.
