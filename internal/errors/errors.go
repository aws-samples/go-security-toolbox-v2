package errors

import (
	"fmt"
)

// Predefined error variables for common errors
var (
	ErrConfigManagerRequired     = New("config manager is required", nil)
	ErrLoaderNil                = New("loader is nil", nil)
	ErrConfigManagerNil         = New("config manager is nil", nil)
	ErrS3APINil                 = New("S3 API is nil", nil)
	ErrConfigNil                = New("config is nil", nil)
	ErrRestrictedActionsEmpty   = New("restricted actions are empty", nil)
	ErrFailedToGetConfigFromS3  = func(cause error) *AppError { return New("failed to get config file from S3", cause) }
	ErrFailedToReadConfigContent = func(cause error) *AppError { return New("failed to read config file content", cause) }
	ErrFailedToUnmarshalConfig  = func(cause error) *AppError { return New("failed to unmarshal config file", cause) }
	ErrFailedToDiscoverPrincipals = func(cause error) *AppError { return New("failed to discover IAM principals", cause) }
	ErrFailedToDiscoverPolicies = func(cause error) *AppError { return New("failed to discover policies", cause) }
	ErrInvalidRestrictedAction  = func(action string) *AppError { return New("invalid restricted action: "+action, nil) }
	ErrInvalidPrecompliantIdentity = func(identity string) *AppError { return New("invalid precompliant IAM identity: "+identity, nil) }
)

type AppError struct {
	message string
	cause   error
}

func (e *AppError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", e.message, e.cause)
	}
	return e.message
}

func (e *AppError) Unwrap() error {
	return e.cause
}

func New(message string, cause error) *AppError {
	return &AppError{
		message: message,
		cause:   cause,
	}
}