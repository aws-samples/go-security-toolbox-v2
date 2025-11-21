# AWS Security Toolbox v2

Automated IAM policy compliance scanning using AWS Config, Access Analyzer, and Lambda. Built with AWS SDK for Go v2.

## Features

- **Policy Compliance Scanning**: Detects IAM policies containing restricted actions using AWS Access Analyzer
- **Orphan Policy Detection**: Identifies unattached customer-managed IAM policies
- **AWS Config Integration**: Automated compliance reporting and remediation tracking
- **Serverless Architecture**: Single Lambda function handling multiple security rules

## Prerequisites

- AWS CLI configured with appropriate permissions
- AWS SAM CLI installed
- Go 1.21+ (for local development)
- AWS Config enabled in target regions
- AWS Access Analyzer enabled

## Quick Start

### 1. Deploy the Solution

```bash
cd deployment/configrule
make build
make deploy
```

### 2. Configure Security Rules

Create a configuration file in S3:

```json
{
  "restrictedActions": [
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "s3:DeleteBucket"
  ],
  "precompliantIamIdentities": [
    "arn:aws:iam::123456789012:role/approved-role"
  ],
  "testMode": false
}
```

### 3. Set Environment Variables

```bash
export CONFIG_FILE_BUCKET_NAME="your-config-bucket"
export CONFIG_FILE_KEY="security-config.json"
```

## Security Rules

### check-access-not-granted

Scans all IAM roles and users for policies containing restricted actions.

**Compliance**: `NON_COMPLIANT` if any policy grants restricted actions

### orphan-policy-finder

Identifies customer-managed policies not attached to any IAM principals.

**Compliance**: `NON_COMPLIANT` if policy has zero attachments

## Architecture

```
AWS Config → Lambda Function → Access Analyzer
     ↓              ↓               ↓
Compliance    S3 Configuration   Policy Analysis
Reporting        & Logging        & Validation
```

## Development

### Local Testing

```bash
# Run tests
go test ./...

# Build binary
go build ./cmd/configrule

# Run with test event
./configrule < test-event.json
```

### Project Structure

```
├── cmd/configrule/          # Lambda entry point
├── internal/
│   ├── handlers/            # Config rule handlers
│   ├── worker/              # Policy scanning logic
│   ├── config/              # Configuration management
│   └── logger/              # Structured logging
└── deployment/configrule/   # SAM deployment
```

## Configuration Reference

| Parameter | Type | Description |
|-----------|------|-------------|
| `restrictedActions` | `[]string` | IAM actions to flag as non-compliant |
| `precompliantIamIdentities` | `[]string` | IAM ARNs to skip scanning |
| `testMode` | `bool` | Skip Config service reporting when `true` |

## IAM Permissions

The Lambda function requires:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListRoles",
        "iam:ListUsers",
        "iam:ListPolicies",
        "iam:GetRolePolicy",
        "iam:GetUserPolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListAttachedRolePolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListEntitiesForPolicy",
        "access-analyzer:CheckAccessNotGranted",
        "config:PutEvaluations",
        "s3:GetObject"
      ],
      "Resource": "*"
    }
  ]
}
```

## Troubleshooting

**Config rule not triggering**: Verify AWS Config is enabled and the rule is active

**Access denied errors**: Check Lambda execution role has required IAM permissions

**Configuration not loading**: Ensure S3 bucket/key environment variables are set correctly

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

This project is licensed under the MIT-0 License. See [LICENSE](LICENSE) file.