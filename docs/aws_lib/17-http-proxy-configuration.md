---
title: "`aws_lib`: Support HTTP proxy configuration"
type: enhancement
labels: [enhancement]
modules: [aws_lib]
related: [16]
---

# `aws_lib`: Support HTTP proxy configuration

## Feature request

Support HTTP(S) proxy configuration for AWS API requests.

## Reference

erlcloud supports proxies through its HTTP client abstraction - both lhttpc (`{proxy, HttpProxy}`) and hackney (`{proxy, Proxy}, {proxy_auth, ProxyAuth}`) variants carry proxy settings from `aws_config`.

## Why this matters

Corporate and locked-down network environments frequently route all outbound HTTP through a proxy. The standard AWS SDKs honor `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` environment variables. aws_lib currently connects directly via Gun with no proxy support.

## Proposed behavior

1. Honor `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` environment variables.
2. Allow explicit proxy configuration via `aws_config()`.
3. Apply to both AWS API requests and (where appropriate) metadata requests - note IMDS at 169.254.169.254 and ECS at 169.254.170.2 should generally bypass the proxy (NO_PROXY semantics).

Depends on / relates to [HTTP client abstraction](16-abstract-http-client-pluggable.md) - proxy support is cleanest to implement once the client is behind a single interface.
