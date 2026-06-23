---
title: "`aws_lib`: Support IAM Roles Anywhere via credential_process"
type: enhancement
labels: [enhancement]
---

# `aws_lib`: Support IAM Roles Anywhere via credential_process

## Feature request

Support [IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html) as a credential source.

IAM Roles Anywhere allows workloads outside of AWS to obtain temporary AWS credentials using X.509 certificates, without needing long-lived access keys or running on EC2. It uses a credential helper (`aws_signing_helper`) that returns temporary credentials in the standard JSON format.

## Why this matters

For RabbitMQ deployments running outside EC2 (on-premises, other clouds, containers without IMDS), IAM Roles Anywhere provides a secure credential source that doesn't require storing static access keys. This is particularly relevant for the rabbitmq-aws plugin which currently relies on either environment variables, config files, or EC2 IMDS.

## Integration approach

The credential helper is an external process that outputs credentials in JSON format. Integration options:

1. **Process credential provider** - Shell out to `aws_signing_helper credential-process` and parse the standard JSON response (`AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration`). This matches how the AWS CLI integrates via `credential_process` in `~/.aws/config`.

2. **Native implementation** - Implement the CreateSession API call with X.509 certificate signing directly. More complex but avoids the external process dependency.

Option 1 is simpler and aligns with how other tools integrate. The `credential_process` config setting is already a standard:

```ini
[profile roles-anywhere]
credential_process = aws_signing_helper credential-process \
  --certificate /path/to/cert.pem \
  --private-key /path/to/key.pem \
  --trust-anchor-arn arn:aws:rolesanywhere:... \
  --profile-arn arn:aws:rolesanywhere:... \
  --role-arn arn:aws:iam::...
```

## Credential discovery chain change

This would add a new step in the credential discovery chain, likely between file-based credentials and IMDS:

1. Environment variables
2. Config file (direct credentials)
3. Credentials file
4. **credential_process from config** (new)
5. EC2 Instance Metadata Service
