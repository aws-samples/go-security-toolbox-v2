package errorhandling

import (
	"context"
	"fmt"
	"time"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/logger"
)

type LoggerErrorHandler struct {
	logger logger.Logger
}

func NewLoggerErrorHandler(logger logger.Logger) *LoggerErrorHandler {
	return &LoggerErrorHandler{
		logger: logger,
	}
}

func (h *LoggerErrorHandler) HandleError(ctx context.Context, err error, input interface{}) {
	timestamp := time.Now().Format(time.RFC3339)
	
	// Extract principal ARN from input if possible
	principalArn := h.extractPrincipalArn(input)
	
	// Log the error with structured context
	h.logger.Error("Worker processing failed principal_arn=%s error=%v timestamp=%s", principalArn, err, timestamp)
	
	// Format error for CSV output
	errorMsg := fmt.Sprintf("%s,%s,%s", timestamp, principalArn, err.Error())
	h.logger.Debug("Error record formatted csv_record=%s", errorMsg)
}

// extractPrincipalArn attempts to extract principal ARN from various input types
func (h *LoggerErrorHandler) extractPrincipalArn(input interface{}) string {
	switch v := input.(type) {
	case map[string]interface{}:
		if arn, ok := v["PrincipalArn"].(string); ok {
			return arn
		}
		if arn, ok := v["principal_arn"].(string); ok {
			return arn
		}
	case interface{ GetPrincipalArn() string }:
		return v.GetPrincipalArn()
	}
	return "unknown"
}