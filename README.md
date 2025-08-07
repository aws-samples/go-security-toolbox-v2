# go-security-toolbox-v2

**Note** - uses the AWS go v2 SDK

This repo contains a collection of solutions that help customers maintain a high security posture in the cloud while also being easy to deploy. All solutions are deployed as a single Lambda function with multiple AWS Config rules.

## Deployment

Deploy the unified security toolbox:

```bash
cd deployment/configrule
make build
make deploy
```

## Available Solutions

- **CheckAccessNotGranted** (Config Rule: `check-access-not-granted`)

    Performs a scan of all IAM policies in your AWS account(s), checks to see if they contain any actions from the list of restricted actions and reports the findings to AWS Config and S3.
    
- **OrphanPolicyFinder** (Config Rule: `orphan-policy-finder`)

    Performs a scan of all IAM policies in your AWS account(s), checks to see if any are not attached to IAM principals and reports the findings to AWS Config and S3.

## Configuration

Both solutions use the same configuration file format. You specify the AWS accounts and other attributes via a config file stored in S3. The Lambda function will route to the appropriate handler based on the AWS Config rule name that invoked it.