package s3client

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3API defines the interface for S3 operations
type S3API interface {
	// GetObject retrieves an object from S3
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	// PutObject stores an object in S3
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

type s3SDKClient struct {
	s3Client *s3.Client
}

func NewS3Client(client *s3.Client) S3API {
	return &s3SDKClient{
		s3Client: client,
	}
}

// GetObject retrieves an object from S3
func (c *s3SDKClient) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return c.s3Client.GetObject(ctx, params, optFns...)
}

// PutObject stores an object in S3
func (c *s3SDKClient) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return c.s3Client.PutObject(ctx, params, optFns...)
}
