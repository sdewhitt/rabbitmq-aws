---
title: "`aws_lib`: Support ECS task role / container credentials"
type: enhancement
labels: [enhancement]
related: [13]
---

# `aws_lib`: Support ECS task role / container credentials

## Feature request

Support ECS task role / container credentials as a credential source.

When running inside an ECS task (or other container environments using the credential endpoint), AWS exposes temporary credentials via a link-local HTTP endpoint identified by environment variables:

- `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` - relative path, fetched from `http://169.254.170.2<RelativeUri>`
- `AWS_CONTAINER_CREDENTIALS_FULL_URI` - full URI (used outside ECS, e.g. EKS Pod Identity)
- `AWS_CONTAINER_AUTHORIZATION_TOKEN` / `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` - optional auth token for the full-URI form

## Reference

erlcloud implements the relative-URI form in `erlcloud_ecs_container_credentials`:

```erlang
get_container_credentials(Config) ->
    RelativeUri = os:getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"),
    case RelativeUri of
      false -> {error, container_credentials_unavailable};
      _ ->
        CredentialsPath = "http://169.254.170.2" ++ RelativeUri,
        erlcloud_aws:http_body(...)
    end.
```

The credentials response is the same JSON format as IMDS (`AccessKeyId`, `SecretAccessKey`, `Token`, `Expiration`).

## Why this matters

ECS is a very common deployment target. Without this, a container running an ECS task role cannot obtain credentials through aws_lib - it would fall through to IMDS (which may not be available or may return the host's instance role rather than the task role).

## Credential discovery chain change

This adds a step between file-based credentials and IMDS:

1. Environment variables
2. Config file / credentials file
3. **ECS container credentials** (new) - when `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or `AWS_CONTAINER_CREDENTIALS_FULL_URI` is set
4. EC2 Instance Metadata Service

Related: [IAM Roles Anywhere - another credential source](13-iam-roles-anywhere-credential-process.md).
