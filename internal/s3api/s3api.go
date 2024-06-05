package s3api

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Api interface {
	// get object
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	// put object
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

type _S3SDKClient struct {
	s3Client *s3.Client
}

func NewS3SDKClient(client *s3.Client) S3Api {
	return &_S3SDKClient{
		s3Client: client,
	}
}

// get object
func (c *_S3SDKClient) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return c.s3Client.GetObject(ctx, params, optFns...)
}

// put object
func (c *_S3SDKClient) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return c.s3Client.PutObject(ctx, params, optFns...)
}
