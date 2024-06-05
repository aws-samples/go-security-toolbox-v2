package shared

const (
	AwsIamRole   string = "AWS::IAM::Role"
	AwsIamUser   string = "AWS::IAM::User"
	AwsIamPolicy string = "AWS::IAM::Policy"

	// variables for retrieving config file from s3
	EnvBucketName    string = "CONFIG_FILE_BUCKET_NAME"
	EnvConfigFileKey string = "CONFIG_FILE_KEY"

	DenyOnlyErrMsg string = "You must include at least one allow statement for analysis"
)

type Key struct {
	PrimaryKey string `json:"primaryKey"`
	SortKey    string `json:"sortKey"`
}

type AWSAccount struct {
	AccountId string `json:"accountId"`
	RoleArn   string `json:"roleArn"`
}

func (k *Key) ToString() string {
	return k.PrimaryKey + "||" + k.SortKey
}
