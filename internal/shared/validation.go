package shared

import (
	"log"
	"regexp"
)

const (

	// regex patterns for input validation
	awsAccountIdPattern = `^\d{12}$`

	awsIamPolicyArnPattern = `arn:aws:iam::\d{12}:policy\/[a-zA-Z_0-9+=,.@\-_/]+`
	awsIamUserArnPattern   = `arn:aws:iam::\d{12}:user\/[a-zA-Z_0-9+=,.@\-_]+`
	awsIamRoleArnPattern   = `arn:aws:iam::\d{12}:role\/[a-zA-Z_0-9+=,.@\-_]+`

	awsPolicyNamePattern = `[\w+=,.@-]+`
	awsRoleNamePattern   = `[\w+=,.@-]+`
	awsUserNamePattern   = `[\w+=,.@-]+`

	dynamodbTableNamePattern = `[a-zA-Z0-9_.-]+`
)

// validate aws account Id
func IsValidAwsAccountId(accountId string) bool {
	matched, err := regexp.MatchString(awsAccountIdPattern, accountId)
	if err != nil {
		log.Printf("error validating aws account id: %s", err)
		return false
	}
	return matched
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
	matched, err := regexp.MatchString(awsIamPolicyArnPattern, policyArn)
	if err != nil {
		log.Printf("error validating iam policy arn: %s", err)
		return false
	}
	return matched
}

// valid iam role arn
func IsValidIamRoleArn(roleArn string) bool {
	// iam role arn pattern: arn:aws:iam::<account-id>:role/<role-name>
	matched, err := regexp.MatchString(awsIamRoleArnPattern, roleArn)
	if err != nil {
		log.Printf("error validating iam role arn: %s", err)
		return false
	}
	return matched
}

// valid iam user arn
func IsValidIamUserArn(userArn string) bool {
	// iam user arn pattern: arn:aws:iam::<account-id>:user/<user-name>
	matched, err := regexp.MatchString(awsIamUserArnPattern, userArn)
	if err != nil {
		log.Printf("error validating iam user arn: %s", err)
		return false
	}
	return matched
}

// validate dynamobd table
func IsValidDynamodbTableName(tableName string) bool {
	pattern := dynamodbTableNamePattern
	matched, err := regexp.MatchString(pattern, tableName)
	if err != nil {
		log.Printf("error validating dynamodb table name: %s", err)
		return false
	}
	return matched
}

// validate action from configuration file
func IsValidAction(action string) bool {
	// IAM action pattern: <service-namespace>:<action-name>
	iamActionRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+:[a-zA-Z0-9_\*]+$`)
	return iamActionRegex.MatchString(action)
}

// validate iam policy name
func IsValidIamPolicyName(policyName string) bool {
	// iam policy name pattern: <policy-name>
	matched, err := regexp.MatchString(awsPolicyNamePattern, policyName)
	if err != nil {
		log.Printf("error validating iam policy name: %s", err)
		return false
	}
	return matched
}

// validate iam role name
func IsValidIamRoleName(roleName string) bool {
	// iam role name pattern: <role-name>
	matched, err := regexp.MatchString(awsRoleNamePattern, roleName)
	if err != nil {
		log.Printf("error validating iam role name: %s", err)
		return false
	}
	return matched
}

// validate iam user name
func IsValidIamUserName(userName string) bool {
	// iam user name pattern: <user-name>
	matched, err := regexp.MatchString(awsUserNamePattern, userName)
	if err != nil {
		log.Printf("error validating iam user name: %s", err)
		return false
	}
	return matched
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
