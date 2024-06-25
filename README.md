[![Go Reference](https://pkg.go.dev/badge/github.com/peterHoburg/aws-sdk-go-v2-sso-login.svg)](https://pkg.go.dev/github.com/peterHoburg/aws-sdk-go-v2-sso-login)

# AWS SDK Go V2 SSO Login
Package aws_sdk_go_v2_sso_login implements the AWS SSO OIDC flow, including optionally opening a browser with the AWS SSO auth URL.


**THIS IS NOT AN OFFICIAL PART OF aws-sdk-go-v2. This was not created, endorsed, checked by Amazon/AWS.**

## Why This Package Exists
The official [github.com/aws/aws-sdk-go-v2/service/sso](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/sso)
does not contain a `login` function. AWS recommends using the AWS CLI `aws sso login` which requires the user has the
AWS CLI installed on their system.

## Goal of Package
This package's goal is to remove the need for a user to have anything installed when using AWS SSO, and enabling
developers to create tools that do not need to rely on the AWS CLI.

## Prerequisites
The user must have a `~/.aws/config` file with at least one `[profile <profileName>]` section in it. Read
[these AWS docs](https://docs.aws.amazon.com/cli/latest/userguide/sso-configure-profile-token.html) for more
information.

## References
This package was inspired by, and aims to solve this GH issue: https://github.com/aws/aws-sdk-go-v2/issues/1222

