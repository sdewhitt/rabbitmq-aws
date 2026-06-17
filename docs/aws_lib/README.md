# `aws_lib` backlog

Captured improvement notes for the imported `aws_lib*` modules. Each file is a self-contained description of a bug, enhancement, or refactor, ready to be filed as a GitHub issue once the `aws_lib` migration work is merged.

Each note carries YAML front matter (`title`, `type`, `labels`, optional `modules` and `related`) so the contents can be turned into issues with minimal rework. The `title` field is also the document's H1 and is the intended issue title.

Note on labels: the `refactor` notes use `labels: [refactor]`, but the `amazon-mq/rabbitmq-aws` repository does not currently define a `refactor` label. It will need to be created before those notes are filed as issues, or they should be relabelled to an existing label.

## Bugs

- [`aws_lib`: Handle all 2xx status codes as success in format_response](04-handle-all-2xx-as-success.md)
- [`aws_lib`: local_time() crashes during DST fall-back transition](08-local-time-dst-crash.md)
- [`aws_lib`: Logging crash in retry loop when error is a tuple](09-logging-crash-tuple-error.md)
- [`aws_lib`: Default request timeout (2250ms) is too aggressive for AWS API calls](10-default-request-timeout-too-aggressive.md)
- [`aws_lib`: gun:await_body timeout crashes aws_lib_config with badmatch](11-gun-await-body-timeout-badmatch.md)
- [`aws_lib`: Refresh credentials before expiry, not after (add buffer window)](14-refresh-credentials-before-expiry.md)

## Enhancements

- [`aws_lib`: Expose decoded AWS error details to callers of api_get_request and api_post_request](03-expose-decoded-aws-error-details.md)
- [`aws_lib`: Support AWS_ENDPOINT_URL override for local development](05-aws-endpoint-url-override.md)
- [`aws_lib`: One-shot requests create a fresh TLS connection per attempt](12-one-shot-tls-connection-per-attempt.md)
- [`aws_lib`: Support IAM Roles Anywhere via credential_process](13-iam-roles-anywhere-credential-process.md)
- [`aws_lib`: Support ECS task role / container credentials](15-ecs-task-role-container-credentials.md)
- [`aws_lib`: Support HTTP proxy configuration](17-http-proxy-configuration.md)
- [`aws_lib`: Support role_arn / source_profile chaining in config files](18-role-arn-source-profile-chaining.md)

## Refactors

- [`aws_lib`: Add response classification to avoid retrying non-retriable errors](01-response-classification-non-retriable.md)
- [`aws_lib`: Replace fixed retry delay with exponential backoff and jitter](02-exponential-backoff-jitter.md)
- [`aws_lib`: Decouple retry logic from request functions](06-decouple-retry-logic.md)
- [`aws_lib`: Consider migrating API from list strings to binaries](07-migrate-api-list-strings-to-binaries.md)
- [`aws_lib`: Abstract HTTP client behind a pluggable interface](16-abstract-http-client-pluggable.md)
