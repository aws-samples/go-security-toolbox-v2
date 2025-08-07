package shared

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/logger"
)

// function to convert accessAnalyzerTypes.ReasonSummary to []string
func ConvertReasonsToString(reasons []accessAnalyzerTypes.ReasonSummary, log logger.Logger) []string {
	var reasonsStrs []string
	if reasons == nil {
		if log != nil {
			log.Debug("ConvertReasonsToString: reasons null, returning empty strings")
		}
		return reasonsStrs
	}
	for _, reason := range reasons {
		if description := aws.ToString(reason.Description); description != "" {
			reasonsStrs = append(reasonsStrs, description)
		}
	}
	return reasonsStrs
}
