package shared

import (
	"log"

	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
)

// function to convert accessAnalyzerTypes.ReasonSummary to []string
func ConvertReasonsToString(reasons []accessAnalyzerTypes.ReasonSummary) []string {
	var reasonsStrs []string
	if reasons == nil {
		log.Println("reasons null. returning empty strings")
		return reasonsStrs
	}
	for _, reason := range reasons {
		reasonsStrs = append(reasonsStrs, *reason.Description)
	}
	return reasonsStrs
}
