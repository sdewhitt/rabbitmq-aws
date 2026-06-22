---
title: "`aws_lib`: Support role_arn / source_profile chaining in config files"
type: enhancement
labels: [enhancement]
modules: [aws_lib, aws_lib_config]
related: [13, 15]
---

# `aws_lib`: Support role_arn / source_profile chaining in config files

## Feature request

Support profile-based `role_arn` / `source_profile` chaining in `~/.aws/config`, matching the AWS CLI.

## Reference

erlcloud's `profile/2` interprets the standard AWS CLI config conventions:

```ini
[profile prod]
role_arn = arn:aws:iam::892406118791:role/centralized-users
source_profile = default
external_id = ...
```

When a profile specifies `role_arn` + `source_profile`, erlcloud loads the source profile's credentials, then calls STS AssumeRole to obtain credentials for the target role. It also supports `external_id` and a configurable session name.

## Why this matters

This is a very common pattern for cross-account access. The rabbitmq-aws plugin already does a manual `assume_role` (in `aws_iam.erl`), but doing it through the standard config-file convention would let operators configure cross-account access declaratively without custom code.

## Current state

aws_lib's `aws_lib_config` parses INI profiles and reads `aws_access_key_id` / `aws_secret_access_key` / `aws_session_token`, but ignores `role_arn`, `source_profile`, and `external_id`.

## Proposed behavior

When a profile contains `role_arn`:
1. Resolve `source_profile` (or fall back to current credentials) for the base credentials.
2. Call STS AssumeRole with the role_arn, optional external_id, and a session name.
3. Return the temporary credentials.

This requires an STS AssumeRole implementation in aws_lib (currently the rabbitmq-aws plugin implements this itself).

Related: [Roles Anywhere](13-iam-roles-anywhere-credential-process.md), [ECS credentials](15-ecs-task-role-container-credentials.md) - all credential-source features.
