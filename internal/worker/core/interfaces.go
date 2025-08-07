package core

import "context"

// Processor defines the interface for processing work items
type Processor[T, R any] interface {
	Process(ctx context.Context, input T) (R, error)
}

// ErrorHandler defines the interface for handling worker errors
type ErrorHandler interface {
	HandleError(ctx context.Context, err error, input interface{})
}