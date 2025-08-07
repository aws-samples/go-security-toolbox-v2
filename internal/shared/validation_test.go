package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidAwsAccountId(t *testing.T) {
	tests := []struct {
		name      string
		accountId string
		expected  bool
	}{
		{"valid account ID", "123456789012", true},
		{"empty string", "", false},
		{"too short", "12345678901", false},
		{"too long", "1234567890123", false},
		{"contains letters", "12345678901a", false},
		{"contains special chars", "123456789-12", false},
		{"all zeros", "000000000000", true},
		{"all nines", "999999999999", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidAwsAccountId(tt.accountId)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidIamIdentityArn(t *testing.T) {
	tests := []struct {
		name        string
		identityArn string
		expected    bool
	}{
		{"valid role ARN", "arn:aws:iam::123456789012:role/MyRole", true},
		{"valid user ARN", "arn:aws:iam::123456789012:user/MyUser", true},
		{"invalid policy ARN", "arn:aws:iam::123456789012:policy/MyPolicy", false},
		{"empty string", "", false},
		{"invalid format", "not-an-arn", false},
		{"role with path", "arn:aws:iam::123456789012:role/path/MyRole", true},
		{"user with path", "arn:aws:iam::123456789012:user/path/MyUser", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidIamIdentityArn(tt.identityArn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidIamPolicyArn(t *testing.T) {
	tests := []struct {
		name      string
		policyArn string
		expected  bool
	}{
		{"valid policy ARN", "arn:aws:iam::123456789012:policy/MyPolicy", true},
		{"policy with path", "arn:aws:iam::123456789012:policy/path/MyPolicy", true},
		{"invalid role ARN", "arn:aws:iam::123456789012:role/MyRole", false},
		{"empty string", "", false},
		{"invalid format", "not-an-arn", false},
		{"policy with special chars", "arn:aws:iam::123456789012:policy/My-Policy_123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidIamPolicyArn(tt.policyArn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidIamRoleArn(t *testing.T) {
	tests := []struct {
		name    string
		roleArn string
		expected bool
	}{
		{"valid role ARN", "arn:aws:iam::123456789012:role/MyRole", true},
		{"role with path", "arn:aws:iam::123456789012:role/path/MyRole", true},
		{"invalid user ARN", "arn:aws:iam::123456789012:user/MyUser", false},
		{"empty string", "", false},
		{"invalid format", "not-an-arn", false},
		{"role with special chars", "arn:aws:iam::123456789012:role/My-Role_123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidIamRoleArn(tt.roleArn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidIamUserArn(t *testing.T) {
	tests := []struct {
		name    string
		userArn string
		expected bool
	}{
		{"valid user ARN", "arn:aws:iam::123456789012:user/MyUser", true},
		{"user with path", "arn:aws:iam::123456789012:user/path/MyUser", true},
		{"invalid role ARN", "arn:aws:iam::123456789012:role/MyRole", false},
		{"empty string", "", false},
		{"invalid format", "not-an-arn", false},
		{"user with special chars", "arn:aws:iam::123456789012:user/My-User_123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidIamUserArn(tt.userArn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidDynamodbTableName(t *testing.T) {
	tests := []struct {
		name      string
		tableName string
		expected  bool
	}{
		{"valid table name", "MyTable", true},
		{"table with numbers", "Table123", true},
		{"table with underscore", "My_Table", true},
		{"table with dash", "My-Table", true},
		{"table with dot", "My.Table", true},
		{"empty string", "", false},
		{"table with space", "My Table", true},
		{"table with special chars", "My@Table", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidDynamodbTableName(tt.tableName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidAction(t *testing.T) {
	tests := []struct {
		name     string
		action   string
		expected bool
	}{
		{"valid action", "s3:GetObject", true},
		{"action with wildcard", "s3:*", true},
		{"action with underscore", "iam:Get_User", true},
		{"action with dash", "ec2:describe-instances", false},
		{"empty string", "", false},
		{"missing colon", "s3GetObject", false},
		{"multiple colons", "s3:get:object", false},
		{"starts with colon", ":GetObject", false},
		{"ends with colon", "s3:", false},
		{"action with numbers", "s3:GetObject123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidAction(tt.action)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidIamPolicyName(t *testing.T) {
	tests := []struct {
		name       string
		policyName string
		expected   bool
	}{
		{"valid policy name", "MyPolicy", true},
		{"policy with numbers", "Policy123", true},
		{"policy with underscore", "My_Policy", true},
		{"policy with dash", "My-Policy", true},
		{"policy with dot", "My.Policy", true},
		{"policy with plus", "My+Policy", true},
		{"policy with equals", "My=Policy", true},
		{"policy with comma", "My,Policy", true},
		{"policy with at", "My@Policy", true},
		{"empty string", "", false},
		{"policy with space", "My Policy", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidIamPolicyName(tt.policyName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidIamRoleName(t *testing.T) {
	tests := []struct {
		name     string
		roleName string
		expected bool
	}{
		{"valid role name", "MyRole", true},
		{"role with numbers", "Role123", true},
		{"role with underscore", "My_Role", true},
		{"role with dash", "My-Role", true},
		{"role with dot", "My.Role", true},
		{"role with plus", "My+Role", true},
		{"role with equals", "My=Role", true},
		{"role with comma", "My,Role", true},
		{"role with at", "My@Role", true},
		{"empty string", "", false},
		{"role with space", "My Role", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidIamRoleName(tt.roleName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidIamUserName(t *testing.T) {
	tests := []struct {
		name     string
		userName string
		expected bool
	}{
		{"valid user name", "MyUser", true},
		{"user with numbers", "User123", true},
		{"user with underscore", "My_User", true},
		{"user with dash", "My-User", true},
		{"user with dot", "My.User", true},
		{"user with plus", "My+User", true},
		{"user with equals", "My=User", true},
		{"user with comma", "My,User", true},
		{"user with at", "My@User", true},
		{"empty string", "", false},
		{"user with space", "My User", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidIamUserName(tt.userName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateAnnotation(t *testing.T) {
	tests := []struct {
		name      string
		str       string
		maxLength int
		expected  string
	}{
		{"empty string", "", 10, "N/A"},
		{"string within limit", "hello", 10, "hello"},
		{"string at limit", "1234567890", 10, "1234567890"},
		{"string over limit", "12345678901", 10, "1234567..."},
		{"string over limit with small max", "hello", 3, "hel"},
		{"string over limit with max 2", "hello", 2, "he"},
		{"string over limit with max 1", "hello", 1, "h"},
		{"string over limit with max 0", "hello", 0, ""},
		{"long string", "this is a very long string that exceeds the limit", 20, "this is a very lo..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateAnnotation(tt.str, tt.maxLength)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name      string
		str       string
		maxLength int
		expected  string
	}{
		{"string within limit", "hello", 10, "hello"},
		{"string at limit", "1234567890", 10, "1234567890"},
		{"string over limit", "12345678901", 10, "1234567..."},
		{"string over limit with small max", "hello", 3, "hel"},
		{"string over limit with max 2", "hello", 2, "he"},
		{"string over limit with max 1", "hello", 1, "h"},
		{"string over limit with max 0", "hello", 0, ""},
		{"empty string", "", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.str, tt.maxLength)
			assert.Equal(t, tt.expected, result)
		})
	}
}