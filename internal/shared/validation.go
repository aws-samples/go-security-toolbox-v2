package shared

import (
	"regexp"
)

var (
	// pre-compiled regex patterns for better performance
	awsAccountIdRegex        = regexp.MustCompile(`^\d{12}$`)
	awsIamPolicyArnRegex     = regexp.MustCompile(`arn:aws:iam::\d{12}:policy\/[a-zA-Z_0-9+=,.@\-_/]+`)
	awsIamUserArnRegex       = regexp.MustCompile(`arn:aws:iam::\d{12}:user\/[a-zA-Z_0-9+=,.@\-_]+`)
	awsIamRoleArnRegex       = regexp.MustCompile(`arn:aws:iam::\d{12}:role\/[a-zA-Z_0-9+=,.@\-_]+`)
	awsPolicyNameRegex       = regexp.MustCompile(`[\w+=,.@-]+`)
	awsRoleNameRegex         = regexp.MustCompile(`[\w+=,.@-]+`)
	awsUserNameRegex         = regexp.MustCompile(`[\w+=,.@-]+`)
	dynamodbTableNameRegex   = regexp.MustCompile(`[a-zA-Z0-9_.-]+`)
	iamActionRegex           = regexp.MustCompile(`^[a-zA-Z0-9_-]+:[a-zA-Z0-9_\*]+$`)
)

// validate aws account Id
func IsValidAwsAccountId(accountId string) bool {
	return awsAccountIdRegex.MatchString(accountId)
}

// validate iam iam identity arn
func IsValidIamIdentityArn(identityArn string) bool {

	isValidRoleArn := IsValidIamRoleArn(identityArn)
	isValidUserArn := IsValidIamUserArn(identityArn)

	return isValidRoleArn || isValidUserArn
}

// validate iam policy arn
func IsValidIamPolicyArn(policyArn string) bool {
	// iam policy arn pattern: arn:aws:iam::<account-id>:policy/<policy-name>
	return awsIamPolicyArnRegex.MatchString(policyArn)
}

// valid iam role arn
func IsValidIamRoleArn(roleArn string) bool {
	// iam role arn pattern: arn:aws:iam::<account-id>:role/<role-name>
	return awsIamRoleArnRegex.MatchString(roleArn)
}

// valid iam user arn
func IsValidIamUserArn(userArn string) bool {
	// iam user arn pattern: arn:aws:iam::<account-id>:user/<user-name>
	return awsIamUserArnRegex.MatchString(userArn)
}

// validate dynamobd table
func IsValidDynamodbTableName(tableName string) bool {
	return dynamodbTableNameRegex.MatchString(tableName)
}

// validate action from configuration file
func IsValidAction(action string) bool {
	// IAM action pattern: <service-namespace>:<action-name>
	return iamActionRegex.MatchString(action)
}

// validate iam policy name
func IsValidIamPolicyName(policyName string) bool {
	// iam policy name pattern: <policy-name>
	return awsPolicyNameRegex.MatchString(policyName)
}

// validate iam role name
func IsValidIamRoleName(roleName string) bool {
	// iam role name pattern: <role-name>
	return awsRoleNameRegex.MatchString(roleName)
}

// validate iam user name
func IsValidIamUserName(userName string) bool {
	// iam user name pattern: <user-name>
	return awsUserNameRegex.MatchString(userName)
}

func ValidateAnnotation(str string, maxLength int) string {
	if str != "" {
		return truncateString(str, maxLength)
	}
	return "N/A"
}

func truncateString(str string, maxLength int) string {
	if len(str) > maxLength {
		if maxLength > 3 {
			return str[:maxLength-3] + "..."
		}
		return str[:maxLength]
	}
	return str
}
