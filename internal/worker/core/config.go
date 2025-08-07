package core

const (
	// Worker configuration
	DefaultWorkerCount    = 3
	DefaultBufferSize     = 100
	WorkerCountEnvVar     = "WORKER_COUNT"

	// AWS API limits
	MaxPageSize          = 1000
	DefaultRetryAttempts = 3
	DefaultRegion        = "us-east-1"

	// Semaphore limits
	MaxConcurrentScans = 3

	// Cache settings
	CacheEnabled = true

	// Output settings
	ErrorCSVHeaders  = "timestamp,principal_arn,error_message"
	ResultCSVHeaders = "principal_arn,principal_type,compliance_status,policy_name,violation_reason"

	// Principal types
	PrincipalTypeRole = "AWS::IAM::Role"
	PrincipalTypeUser = "AWS::IAM::User"
)