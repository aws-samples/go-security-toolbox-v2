package worker

import (
	"context"
	"errors"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/iamapi"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
)

type OrphanPolicyWorker struct {
	configEvaluationChan chan interface{} // channel for sending aws config evaluations
	eventTime            time.Time        // time of event
	Worker               Worker           // worker interface
}

type OrphanPolicyWorkerConfig struct {
	ConfigEvaluationChan chan interface{}
	EventTime            time.Time
	WorkerConfig         WorkerConfig
}

type OrphanPolicyWorkerRequest struct {
	AccountId     string // account id to scan policies for
	iamapi.IamApi        // iam api to use to scan policies
}

// create new orphan policy worker
func NewOrphanPolicyWorker(config OrphanPolicyWorkerConfig) (*OrphanPolicyWorker, error) {

	worker, err := NewWorker(config.WorkerConfig)
	if err != nil {
		return nil, errors.New("invalid worker config: " + err.Error())
	}

	if config.ConfigEvaluationChan == nil {
		return nil, errors.New("invalid orphan policy worker configuration: config evaluation channel is nil")
	}

	if config.EventTime.IsZero() {
		return nil, errors.New("invalid orphan policy worker configuration: event time is zero")
	}

	opw := &OrphanPolicyWorker{
		configEvaluationChan: config.ConfigEvaluationChan,
		eventTime:            config.EventTime,
		Worker:               worker,
	}

	worker.SetRequestHandler(opw) // set request handler to worker interface
	worker.SetFinalizer(opw)      // set finalize to worker interface

	return opw, nil
}

// handle request
func (opw *OrphanPolicyWorker) Handle(params interface{}) {
	request := params.(OrphanPolicyWorkerRequest)    // type assert to orphan policy worker request
	errorChan := opw.Worker.GetErrorChannel()        // get error channel
	configEvaluationChan := opw.configEvaluationChan // get config evaluation channel

	listPoliciesPaginator := iam.NewListPoliciesPaginator(request.IamApi, &iam.ListPoliciesInput{})
	for listPoliciesPaginator.HasMorePages() {
		listPoliciesOutput, err := listPoliciesPaginator.NextPage(context.Background())
		if err != nil {
			errorChan <- err
			log.Printf("worker [%v] had an error while listing policies for account [%v]: [%v]\n", opw.Worker.GetId(), request.AccountId, err.Error())
			continue
		}
		for _, policy := range listPoliciesOutput.Policies {
			if *policy.AttachmentCount == int32(0) {
				annotationMsg := []string{}
				annotationMsg = append(annotationMsg, "policy is orphaned")
				annotationMsg = append(annotationMsg, "Created date : ["+policy.CreateDate.Format(time.RFC3339)+"]")
				annotationMsg = append(annotationMsg, "Updated date : ["+policy.UpdateDate.Format(time.RFC3339)+"]")
				joinedString := strings.Join(annotationMsg, "\n")
				configEvaluation := configServiceTypes.Evaluation{
					ComplianceResourceId:   policy.Arn,
					ComplianceResourceType: aws.String(shared.AwsIamPolicy),
					ComplianceType:         configServiceTypes.ComplianceTypeNonCompliant,
					OrderingTimestamp:      aws.Time(opw.eventTime),
					Annotation:             aws.String(joinedString),
				}

				// send config evaluation to config evaluation worker
				configEvaluationChan <- ConfigEvaluationWorkerRequest{
					ConfigEvaluation: configEvaluation,
				}

			} else {
				attachmentCount := strconv.Itoa(int(*policy.AttachmentCount))
				configEvaluation := configServiceTypes.Evaluation{
					ComplianceResourceId:   policy.Arn,
					ComplianceResourceType: aws.String(shared.AwsIamPolicy),
					ComplianceType:         configServiceTypes.ComplianceTypeCompliant,
					OrderingTimestamp:      aws.Time(opw.eventTime),
					Annotation:             aws.String("policy is attached to [" + attachmentCount + "] iam principals"),
				}

				// send config evaluation to config evaluation worker
				configEvaluationChan <- ConfigEvaluationWorkerRequest{
					ConfigEvaluation: configEvaluation,
				}
			}
		}
	}
	log.Printf("worker [%v] finished processing policies for account [%v]\n", opw.Worker.GetId(), request.AccountId)
}

// finalize worker
func (opw *OrphanPolicyWorker) Finalize() {
	log.Printf("worker [%v] finalized\n", opw.Worker.GetId())
}
