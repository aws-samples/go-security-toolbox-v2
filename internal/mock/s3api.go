package mock

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type MockS3Api struct {
}

// get object
func (s *MockS3Api) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{}, nil
}

// put object
func (s *MockS3Api) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return &s3.PutObjectOutput{}, nil
}
