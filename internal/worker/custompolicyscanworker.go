package worker

import (
	"context"
	"errors"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/accessanalyzerapi"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/cache"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/iamapi"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
)

// interface for an iam identity.  This will help process the policies in a testabale manner
type IamIdentity interface {
	GetIdentityType() string
	GetIdentityName() string
	GetIdentityArn() string
	ProcessPolicyCompliance(ctx context.Context, input ProcessPolicyComplianceInput) error
}

type _IamIdentity struct {
	IdentityType string // type of iam principal "user || role"
	Arn          string // arn of iam principal
	Name         string // name of iam principal
}

type IamIdentityConfig struct {
	IdentityType string // type of iam principal "user || role"
	Arn          string // arn of iam principal
	Name         string // name of iam principal
}

// create new iam identity
func NewIamIdentity(config IamIdentityConfig) (IamIdentity, error) {
	// perform nil checks
	if config.IdentityType == "" || config.Arn == "" || config.Name == "" {
		return nil, errors.New("error creating iam identity. required field(s) are nil")
	}
	return &_IamIdentity{
		IdentityType: config.IdentityType,
		Arn:          config.Arn,
		Name:         config.Name,
	}, nil
}

type ProcessPolicyComplianceInput struct {
	AccountId            string                              // aws account id
	RestrictedActions    []string                            // restricted actions to scan policies from
	EventTime            time.Time                           // time of event
	IamIdentity          IamIdentity                         // iam identity to process
	ErrorChan            chan<- error                        // write only channel for errors
	ComplianceResults    chan interface{}                    // channel to collect results from each individual policy associated to an iam principal
	ConfigEvaluationChan chan interface{}                    // channel to send aws config evaluation
	IamApi               iamapi.IamApi                       // iam api interface
	Accessanalyzerapi    accessanalyzerapi.AccessAnalyzerApi // access analyzer api interface
	Cache                cache.CustomPolicyScanResultsCache  // cache for accessing custom policy scan results
	ErrorHandler         handler                             // error handler
}

// get identity type
func (i *_IamIdentity) GetIdentityType() string {
	return i.IdentityType
}

// get identity name
func (i *_IamIdentity) GetIdentityName() string {
	return i.Name
}

// get identity arn
func (i *_IamIdentity) GetIdentityArn() string {
	return i.Arn
}

// process policy compliance
func (i *_IamIdentity) ProcessPolicyCompliance(ctx context.Context, input ProcessPolicyComplianceInput) error {
	// perform nil checks for required fields
	if len(input.RestrictedActions) == 0 || input.ErrorChan == nil || input.ComplianceResults == nil || input.AccountId == "" ||
		input.Accessanalyzerapi == nil || input.IamApi == nil || input.ErrorHandler == nil || input.ConfigEvaluationChan == nil {
		return errors.New("error processing policy compliance. required field(s) are nil")
	}

	var (
		done            = make(chan bool)
		batch           []CustomPolicyScanResult
		inlinePolicyWg  = new(sync.WaitGroup)
		managedPolicyWg = new(sync.WaitGroup)
		resultWg        = new(sync.WaitGroup)
	)

	// increment wait groups for go routines
	inlinePolicyWg.Add(1)
	managedPolicyWg.Add(1)
	resultWg.Add(1)

	// batch results until go routines signal completion
	go func() {
		defer resultWg.Done()
		for {
			select {
			case result := <-input.ComplianceResults:
				{
					batch = append(batch, result.(CustomPolicyScanResult))
				}
			case <-done:
				{
					log.Printf("managed and inline policy compliance completed\n")
					return
				}
			}
		}
	}()

	// process inline and managed policy compliance in go routines
	go processInlinePolicyCompliance(ctx, inlinePolicyWg, input)
	go processManagedPolicyCompliance(ctx, managedPolicyWg, input)

	// wait for go routines to complete and signal completion
	go func() {
		inlinePolicyWg.Wait()
		managedPolicyWg.Wait()
		done <- true
	}()

	resultWg.Wait() // wait for batch to complete
	log.Printf("batch is completed\n")

	// create aws config evaluation
	evaluation, err := createConfigEvaluation(createConfigEvaluationInput{
		results:                batch,
		complianceResourceType: input.IamIdentity.GetIdentityType(),
		configEvaluationChan:   input.ComplianceResults,
		errorChan:              input.ErrorChan,
	})

	// check to make sure evaluation is not empty
	if (evaluation == configServiceTypes.Evaluation{}) {
		log.Printf("error creating config evaluation for [%v]", input.IamIdentity.GetIdentityArn()+" : "+err.Error())
		return errors.New("error creating config evaluation for " + input.IamIdentity.GetIdentityArn() + " : " + err.Error())
	}

	// send config evaluation to channel
	input.ConfigEvaluationChan <- ConfigEvaluationWorkerRequest{
		ConfigEvaluation: evaluation,
	}
	log.Printf("config evaluation for [%v] is completed", input.IamIdentity.GetIdentityArn())

	return nil
}

type createConfigEvaluationInput struct {
	results                []CustomPolicyScanResult
	complianceResourceType string
	configEvaluationChan   chan<- interface{}
	errorChan              chan<- error
}

func createConfigEvaluation(input createConfigEvaluationInput) (configServiceTypes.Evaluation, error) {
	var (
		currentComplianceStatus = configServiceTypes.ComplianceTypeCompliant // set to compliant by default
		annotation              = []string{}                                 // aggregating all reasons & messages for each result
		complianceResourceId    = ""
	)

	for index, result := range input.results {
		if index == 0 {
			complianceResourceId = result.ResourceArn // save resource id for first entry
		}
		switch string(result.Compliance) {
		case "NON_COMPLIANT":
			{
				currentComplianceStatus = configServiceTypes.ComplianceTypeNonCompliant
				annotation = append(annotation, result.Reasons...) // add reasons to annotation
			}
		case "COMPLIANT":
			{
				annotation = append(annotation, result.Message) // add message to annotation
			}
		default:
			{
				return configServiceTypes.Evaluation{}, errors.New("error while creating config evaluation. invalid compliance type")
			}
		}
	}

	validatedAnnotation := shared.ValidateAnnotation(strings.Join(annotation, "\n"), 250)
	trimmedAnnotation := strings.TrimSpace(validatedAnnotation)

	return configServiceTypes.Evaluation{
		ComplianceResourceId:   aws.String(complianceResourceId),
		ComplianceResourceType: aws.String(input.complianceResourceType),
		ComplianceType:         currentComplianceStatus,
		Annotation:             aws.String(trimmedAnnotation),
		OrderingTimestamp:      aws.Time(time.Now()),
	}, nil
}

func processInlinePolicyCompliance(ctx context.Context, wg *sync.WaitGroup, input ProcessPolicyComplianceInput) {
	defer wg.Done() // decrement wait group

	// process iam identity based on type
	switch input.IamIdentity.GetIdentityType() {
	case shared.AwsIamUser:
		{
			// process inline policies for iam user
			processInlinePoliciesForIamUser(ctx, input)
			log.Printf("inline policy compliance completed for [%v]\n", input.IamIdentity.GetIdentityArn())
			return
		}
	case shared.AwsIamRole:
		{
			// process inline policies for iam role
			processInlinePoliciesForIamRole(ctx, input)
			log.Printf("inline policy compliance completed for [%v]\n", input.IamIdentity.GetIdentityArn())
			return
		}
	default:
		{
			log.Printf("unknown identity type\n")
		}
	}
}

func processInlinePoliciesForIamUser(ctx context.Context, input ProcessPolicyComplianceInput) {

	listUserPoliciesPaginator := iam.NewListUserPoliciesPaginator(input.IamApi, &iam.ListUserPoliciesInput{
		UserName: aws.String(input.IamIdentity.GetIdentityName()),
	})
	for listUserPoliciesPaginator.HasMorePages() {
		listUserPoliciesOutput, err := listUserPoliciesPaginator.NextPage(ctx)
		if err != nil {
			input.ErrorChan <- err
			log.Printf("error while listing inline policies for %v. %v", input.IamIdentity.GetIdentityArn(), err)
			return
		}
		for _, policyName := range listUserPoliciesOutput.PolicyNames {
			// get inline policy document
			getUserPolicyOutput, err := input.IamApi.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
				PolicyName: aws.String(policyName),
				UserName:   aws.String(input.IamIdentity.GetIdentityName()),
			})
			if err != nil {
				input.ErrorHandler.Handle(handleCustomPolicyscanErrorInput{
					err: CustomPolicyScanError{
						IAMPrincipalArn:    input.IamIdentity.GetIdentityArn(),
						Message:            err.Error(),
						PolicyDocumentName: policyName,
					},
					errorChan:                   input.ErrorChan,
					customPolicyScanResultsChan: input.ComplianceResults,
					cache:                       input.Cache,
					complianceResultInput: complianceResultInput{
						compliance:  configServiceTypes.ComplianceTypeNonCompliant,
						reasons:     nil,
						message:     err.Error(),
						policyName:  policyName,
						resourceArn: input.IamIdentity.GetIdentityArn(),
					},
				})
				continue
			}

			// check cache first
			if input.Cache != nil {
				result, ok := input.Cache.Get(cache.CustomPolicyScanCacheKey{
					PolicyName: policyName,
					AccountID:  input.AccountId,
				})
				if ok {
					// send result to channel
					log.Printf("cache hit for " + policyName)
					cacheResult := result.(cache.CustomPolicyScanCacheResult)
					customPolicyScanResult := CustomPolicyScanResult{
						PolicyDocumentName: policyName,
						ResourceArn:        input.IamIdentity.GetIdentityArn(),
						Compliance:         cacheResult.Compliance,
						Reasons:            cacheResult.Reasons,
						Message:            cacheResult.Message,
					}
					input.ComplianceResults <- customPolicyScanResult
					log.Printf("sent compliance result for " + customPolicyScanResult.PolicyDocumentName + " to results channel")
					continue
				}
				log.Printf("cache miss for " + policyName)
			}

			// decode policy document
			decodedPolicyDocument, _ := url.QueryUnescape(*getUserPolicyOutput.PolicyDocument)

			// check policy compliance
			result, _ := isCompliant(isCompliantInput{
				ctx:                  ctx,
				accessAnalyzerClient: input.Accessanalyzerapi,
				policyDocument:       decodedPolicyDocument,
				restrictedActions:    input.RestrictedActions,
				policyDocumentName:   policyName,
				resourceArn:          input.IamIdentity.GetIdentityArn(),
			})

			// write result to cache
			if input.Cache != nil {
				_ = input.Cache.Set(cache.CustomPolicyScanCacheKey{
					PolicyName: policyName,
					AccountID:  input.AccountId,
				}, cache.CustomPolicyScanCacheResult{
					Compliance: result.Compliance,
					Reasons:    result.Reasons,
					Message:    result.Message,
				})
				input.ComplianceResults <- result // send result to channel
				continue
			}
			input.ComplianceResults <- result // send result to channel
			log.Printf("sent compliance result for " + result.PolicyDocumentName + " to result channel")
			continue
		}
	}
}

func processInlinePoliciesForIamRole(ctx context.Context, input ProcessPolicyComplianceInput) {
	listRolePoliciesPaginator := iam.NewListRolePoliciesPaginator(input.IamApi, &iam.ListRolePoliciesInput{
		RoleName: aws.String(input.IamIdentity.GetIdentityName()),
	})
	for listRolePoliciesPaginator.HasMorePages() {
		listRolePoliciesOutput, err := listRolePoliciesPaginator.NextPage(ctx)
		if err != nil {
			input.ErrorChan <- err
			return
		}
		for _, policyName := range listRolePoliciesOutput.PolicyNames {
			// get inline policy document
			getRolePolicyOutput, err := input.IamApi.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				PolicyName: aws.String(policyName),
				RoleName:   aws.String(input.IamIdentity.GetIdentityName()),
			})

			// handle errors
			if err != nil {
				input.ErrorHandler.Handle(handleCustomPolicyscanErrorInput{
					err: CustomPolicyScanError{
						IAMPrincipalArn:    input.IamIdentity.GetIdentityArn(),
						Message:            err.Error(),
						PolicyDocumentName: policyName,
					},
					errorChan:                   input.ErrorChan,
					customPolicyScanResultsChan: input.ComplianceResults,
					cache:                       input.Cache,
					complianceResultInput: complianceResultInput{
						compliance:  configServiceTypes.ComplianceTypeNonCompliant,
						reasons:     nil,
						message:     err.Error(),
						policyName:  policyName,
						resourceArn: input.IamIdentity.GetIdentityArn(),
					},
				})
				continue
			}

			// check cache first
			if input.Cache != nil {
				result, ok := input.Cache.Get(cache.CustomPolicyScanCacheKey{
					PolicyName: policyName,
					AccountID:  input.AccountId,
				})
				if ok {
					// send result to channel
					log.Printf("cache hit for " + policyName)
					cacheResult := result.(cache.CustomPolicyScanCacheResult)
					customPolicyScanResult := CustomPolicyScanResult{
						PolicyDocumentName: policyName,
						ResourceArn:        input.IamIdentity.GetIdentityArn(),
						Compliance:         cacheResult.Compliance,
						Reasons:            cacheResult.Reasons,
						Message:            cacheResult.Message,
					}
					input.ComplianceResults <- customPolicyScanResult
					log.Printf("sent compliance result for " + customPolicyScanResult.PolicyDocumentName + " to results channel")
					continue
				}
				log.Printf("cache miss for " + policyName)
			}

			// decode policy document
			decodedPolicyDocument, _ := url.QueryUnescape(*getRolePolicyOutput.PolicyDocument)

			// check policy compliance
			result, _ := isCompliant(isCompliantInput{
				ctx:                  ctx,
				accessAnalyzerClient: input.Accessanalyzerapi,
				policyDocument:       decodedPolicyDocument,
				restrictedActions:    input.RestrictedActions,
				policyDocumentName:   policyName,
				resourceArn:          input.IamIdentity.GetIdentityArn(),
			})

			// write result to cache
			if input.Cache != nil {
				_ = input.Cache.Set(cache.CustomPolicyScanCacheKey{
					PolicyName: policyName,
					AccountID:  input.AccountId,
				}, cache.CustomPolicyScanCacheResult{
					Compliance: result.Compliance,
					Reasons:    result.Reasons,
					Message:    result.Message,
				})

				input.ComplianceResults <- result // send result to channel
				log.Printf("sent compliance result for " + result.PolicyDocumentName + " to result channel")
				continue
			}
			input.ComplianceResults <- result // send result to channel
			log.Printf("sent compliance result for " + result.PolicyDocumentName + " to result channel")
			continue
		}
	}
}

func processManagedPolicyCompliance(ctx context.Context, wg *sync.WaitGroup, input ProcessPolicyComplianceInput) {
	defer wg.Done() // decrement wait group

	switch input.IamIdentity.GetIdentityType() {
	case shared.AwsIamUser:
		{
			// process managed policies for iam user
			processManagedPoliciesForIamUser(ctx, input)
			return
		}
	case shared.AwsIamRole:
		{
			// process managed policies for iam role
			processManagedPoliciesForIamRole(ctx, input)
			return
		}
	}
}

func processManagedPoliciesForIamUser(ctx context.Context, input ProcessPolicyComplianceInput) {

	listAttachedUserPoliciesPaginator := iam.NewListAttachedUserPoliciesPaginator(input.IamApi, &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(input.IamIdentity.GetIdentityName()),
	})

	for listAttachedUserPoliciesPaginator.HasMorePages() {
		listAttachedUserPoliciesOutput, err := listAttachedUserPoliciesPaginator.NextPage(ctx)
		if err != nil {
			input.ErrorChan <- err
			return
		}

		for _, attachedUserPolicy := range listAttachedUserPoliciesOutput.AttachedPolicies {
			// get managed policy document
			getManagedPolicyOutput, err := input.IamApi.GetPolicy(ctx, &iam.GetPolicyInput{
				PolicyArn: attachedUserPolicy.PolicyArn,
			})
			// return errors
			if err != nil {
				input.ErrorHandler.Handle(handleCustomPolicyscanErrorInput{
					err: CustomPolicyScanError{
						IAMPrincipalArn:    input.IamIdentity.GetIdentityArn(),
						Message:            err.Error(),
						PolicyDocumentName: *attachedUserPolicy.PolicyName,
					},
					errorChan:                   input.ErrorChan,
					customPolicyScanResultsChan: input.ComplianceResults,
					cache:                       input.Cache,
					complianceResultInput: complianceResultInput{
						compliance:  configServiceTypes.ComplianceTypeNonCompliant,
						reasons:     nil,
						message:     err.Error(),
						policyName:  *attachedUserPolicy.PolicyName,
						resourceArn: input.IamIdentity.GetIdentityArn(),
					},
				})
				continue
			}

			getPolicyVersionOutput, err := input.IamApi.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: getManagedPolicyOutput.Policy.Arn,
				VersionId: getManagedPolicyOutput.Policy.DefaultVersionId,
			})
			// return errors
			if err != nil {
				input.ErrorHandler.Handle(handleCustomPolicyscanErrorInput{
					err: CustomPolicyScanError{
						IAMPrincipalArn:    input.IamIdentity.GetIdentityArn(),
						Message:            err.Error(),
						PolicyDocumentName: *attachedUserPolicy.PolicyName,
					},
					errorChan:                   input.ErrorChan,
					customPolicyScanResultsChan: input.ComplianceResults,
					cache:                       input.Cache,
					complianceResultInput: complianceResultInput{
						compliance:  configServiceTypes.ComplianceTypeNonCompliant,
						reasons:     nil,
						message:     err.Error(),
						policyName:  *attachedUserPolicy.PolicyName,
						resourceArn: input.IamIdentity.GetIdentityArn(),
					},
				})
				continue
			}

			// check cache first
			if input.Cache != nil {
				result, ok := input.Cache.Get(cache.CustomPolicyScanCacheKey{
					PolicyName: *attachedUserPolicy.PolicyName,
					AccountID:  input.AccountId,
				})
				if ok {
					log.Printf("cache hit for " + *attachedUserPolicy.PolicyName)
					cacheResult := result.(cache.CustomPolicyScanCacheResult)
					customPolicyScanResult := CustomPolicyScanResult{
						PolicyDocumentName: *attachedUserPolicy.PolicyName,
						ResourceArn:        input.IamIdentity.GetIdentityArn(),
						Compliance:         cacheResult.Compliance,
						Reasons:            cacheResult.Reasons,
						Message:            cacheResult.Message,
					}
					input.ComplianceResults <- customPolicyScanResult // send result to channel
					log.Printf("sent compliance result for " + customPolicyScanResult.PolicyDocumentName + " to results channel")
					continue
				}
				log.Printf("cache miss for " + *attachedUserPolicy.PolicyName)
			}

			// decode policy document
			decodedPolicyDocument, _ := url.QueryUnescape(*getPolicyVersionOutput.PolicyVersion.Document)

			// check policy compliance
			result, _ := isCompliant(isCompliantInput{
				ctx:                  ctx,
				accessAnalyzerClient: input.Accessanalyzerapi,
				policyDocument:       decodedPolicyDocument,
				restrictedActions:    input.RestrictedActions,
				policyDocumentName:   *attachedUserPolicy.PolicyName,
				resourceArn:          input.IamIdentity.GetIdentityArn(),
			})

			// write result to cache
			if input.Cache != nil {
				_ = input.Cache.Set(cache.CustomPolicyScanCacheKey{
					PolicyName: *attachedUserPolicy.PolicyName,
					AccountID:  input.AccountId,
				}, cache.CustomPolicyScanCacheResult{
					Compliance: result.Compliance,
					Reasons:    result.Reasons,
					Message:    result.Message,
				})
				input.ComplianceResults <- result // send result to channel
				log.Printf("sent compliance result for " + result.PolicyDocumentName + " to result channel")
				continue
			}
			input.ComplianceResults <- result // send result to channel
			log.Printf("sent compliance result for " + result.PolicyDocumentName + " to result channel")
			continue
		}
	}
}

func processManagedPoliciesForIamRole(ctx context.Context, input ProcessPolicyComplianceInput) {
	listAttachedRolePoliciesPaginator := iam.NewListAttachedRolePoliciesPaginator(input.IamApi, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(input.IamIdentity.GetIdentityName()),
	})

	for listAttachedRolePoliciesPaginator.HasMorePages() {
		listAttachedRolePoliciesOutput, err := listAttachedRolePoliciesPaginator.NextPage(ctx)
		if err != nil {
			input.ErrorChan <- err
			return
		}

		for _, attachedRolePolicy := range listAttachedRolePoliciesOutput.AttachedPolicies {
			// get managed policy document
			getManagedPolicyOutput, err := input.IamApi.GetPolicy(ctx, &iam.GetPolicyInput{
				PolicyArn: attachedRolePolicy.PolicyArn,
			})
			// handle errors
			if err != nil {
				input.ErrorHandler.Handle(handleCustomPolicyscanErrorInput{
					err: CustomPolicyScanError{
						IAMPrincipalArn:    input.IamIdentity.GetIdentityArn(),
						Message:            err.Error(),
						PolicyDocumentName: *attachedRolePolicy.PolicyName,
					},
					errorChan:                   input.ErrorChan,
					customPolicyScanResultsChan: input.ComplianceResults,
					cache:                       input.Cache,
					complianceResultInput: complianceResultInput{
						compliance:  configServiceTypes.ComplianceTypeNonCompliant,
						reasons:     nil,
						message:     err.Error(),
						policyName:  *attachedRolePolicy.PolicyName,
						resourceArn: input.IamIdentity.GetIdentityArn(),
					},
				})
				continue
			}

			getPolicyVersionOutput, err := input.IamApi.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: getManagedPolicyOutput.Policy.Arn,
				VersionId: getManagedPolicyOutput.Policy.DefaultVersionId,
			})
			// handle errors
			if err != nil {
				input.ErrorHandler.Handle(handleCustomPolicyscanErrorInput{
					err: CustomPolicyScanError{
						IAMPrincipalArn:    input.IamIdentity.GetIdentityArn(),
						Message:            err.Error(),
						PolicyDocumentName: *attachedRolePolicy.PolicyName,
					},
					errorChan:                   input.ErrorChan,
					customPolicyScanResultsChan: input.ComplianceResults,
					cache:                       input.Cache,
					complianceResultInput: complianceResultInput{
						compliance:  configServiceTypes.ComplianceTypeNonCompliant,
						reasons:     nil,
						message:     err.Error(),
						policyName:  *attachedRolePolicy.PolicyName,
						resourceArn: input.IamIdentity.GetIdentityArn(),
					},
				})
				continue
			}

			// check cache first
			if input.Cache != nil {
				result, ok := input.Cache.Get(cache.CustomPolicyScanCacheKey{
					PolicyName: *attachedRolePolicy.PolicyName,
					AccountID:  input.AccountId,
				})
				if ok {
					log.Printf("cache hit for " + *attachedRolePolicy.PolicyName)
					cacheResult := result.(cache.CustomPolicyScanCacheResult)
					customPolicyScanResult := CustomPolicyScanResult{
						PolicyDocumentName: *attachedRolePolicy.PolicyName,
						ResourceArn:        input.IamIdentity.GetIdentityArn(),
						Compliance:         cacheResult.Compliance,
						Reasons:            cacheResult.Reasons,
						Message:            cacheResult.Message,
					}
					input.ComplianceResults <- customPolicyScanResult // send result to channel
					log.Printf("sent compliance result for " + customPolicyScanResult.PolicyDocumentName + " to results channel")
					continue
				}
				log.Printf("cache miss for " + *attachedRolePolicy.PolicyName)
			}

			// decode policy document
			decodedPolicyDocument, _ := url.QueryUnescape(*getPolicyVersionOutput.PolicyVersion.Document)

			// check policy compliance
			result, _ := isCompliant(isCompliantInput{
				ctx:                  ctx,
				accessAnalyzerClient: input.Accessanalyzerapi,
				policyDocument:       decodedPolicyDocument,
				restrictedActions:    input.RestrictedActions,
				policyDocumentName:   *attachedRolePolicy.PolicyName,
				resourceArn:          input.IamIdentity.GetIdentityArn(),
			})

			// write result to cache
			if input.Cache != nil {
				_ = input.Cache.Set(cache.CustomPolicyScanCacheKey{
					PolicyName: *attachedRolePolicy.PolicyName,
					AccountID:  input.AccountId,
				}, cache.CustomPolicyScanCacheResult{
					Compliance: result.Compliance,
					Reasons:    result.Reasons,
					Message:    result.Message,
				})
				input.ComplianceResults <- result // send result to channel
				log.Printf("sent compliance result for " + result.PolicyDocumentName + " to result channel")
				continue
			}
			input.ComplianceResults <- result // send result to channel
			log.Printf("sent compliance result for " + result.PolicyDocumentName + " to result channel")
			continue
		}
	}
}

type handler interface {
	Handle(params interface{}) error
}

type handlePrecompliantIamIdentityRequestInput struct {
	request              CustomPolicyScanWorkerRequest
	configEvaluationChan chan<- interface{}
	eventTime            time.Time
}

type _PrecompliantIamIdentityHandler struct {
}

func (h *_PrecompliantIamIdentityHandler) Handle(params interface{}) error {
	input := params.(handlePrecompliantIamIdentityRequestInput)
	configEvaluation := configServiceTypes.Evaluation{
		ComplianceResourceId:   aws.String(input.request.IamIdentity.GetIdentityArn()),
		ComplianceResourceType: aws.String(input.request.ResourceType),
		ComplianceType:         configServiceTypes.ComplianceTypeCompliant,
		OrderingTimestamp:      aws.Time(time.Now()),
		Annotation:             aws.String("marked as pre-compliant"),
	}
	input.configEvaluationChan <- ConfigEvaluationWorkerRequest{
		ConfigEvaluation: configEvaluation,
	}
	return nil
}

type _CustomPolicyScanErrorHandler struct {
}

func (h *_CustomPolicyScanErrorHandler) Handle(params interface{}) error {
	input := params.(handleCustomPolicyscanErrorInput)
	log.Printf("handling custom policy scan error [%v]\n", input.err.Error())
	errorChan := input.errorChan
	if errorChan == nil {
		log.Printf("cannot handle custom policy scan error with empty error channel: [%+v]\n", input)
		return errors.New("cannot handle custom policy scan error with empty error channel")
	}
	customPolicyScanResultsChan := input.customPolicyScanResultsChan
	if customPolicyScanResultsChan == nil {
		log.Printf("cannot handle custom policy scan error with empty custom policy results channel: [%+v]\n", input)
		return errors.New("cannot handle custom policy scan error with empty results channel")
	}

	errorChan <- input.err // send error to error channel
	log.Println("error handler sent error to error channel")

	// create custom policy scan result and send to
	customPolicyScanResults, err := newCustomPolicyScanResult(input.complianceResultInput)
	if err != nil {
		log.Printf("error handler failed to create custom policy scan result: [%v]\n", err.Error())
		return err
	}
	customPolicyScanResultsChan <- customPolicyScanResults // send compliance result to channel
	log.Printf("error handler sent compliance result to channel for [%+v]\n", customPolicyScanResults.ResourceArn)

	// write result to cache if provided
	if input.cache != nil {
		log.Printf("error handler writing custom policy scan result for [%v] to cache\n", customPolicyScanResults.ResourceArn)

	}
	return nil
}

type CustomPolicyScanWorker struct {
	restrictedActions              []string
	configEvaluationChan           chan interface{}
	semaphoreChan                  chan chan interface{}
	eventTime                      time.Time
	customPolicyScanResultsCache   cache.CustomPolicyScanResultsCache
	errorHandler                   handler
	precompliantIamIdentityHandler handler
	Worker                         Worker
}

type CustomPolicyScanWorkerConfig struct {
	RestrictedActions    []string
	ConfigEvaluationChan chan interface{}
	SemaphoreChan        chan chan interface{}
	EventTime            time.Time
	EnableCache          bool
	WorkerConfig         WorkerConfig
}

type CustomPolicyScanWorkerRequest struct {
	AccountId                      string                              // aws account id to scan
	ResourceType                   string                              // resource type to scan ex : AWS::IAM::Role , AWS::IAM::User etc..
	IamIdentity                    IamIdentity                         // structure for iam principal
	IamApi                         iamapi.IamApi                       // iam client for accessing IAM service
	AccessAnalyzerApi              accessanalyzerapi.AccessAnalyzerApi // accessanalyzer client for accessing Access Analyzer service
	PrecompliantIamIdentityRequest bool                                // signal to mark IAM identity as compliant
}

type IAMRole struct {
	Arn  string
	Name string
}

type IAMPolicy struct {
	Arn  string // arn of policy document
	Name string // name of policy document
}

type CustomPolicyScanResult struct {
	Compliance         configServiceTypes.ComplianceType
	Reasons            []string
	Message            string
	PolicyDocumentName string
	ResourceArn        string
}

type CustomPolicyScanError struct {
	IAMPrincipalArn    string // arn of iam principal in which error occured
	PolicyDocumentName string // name of policy document in which error occured
	Message            string // error message
}

func (cpse CustomPolicyScanError) Error() string {
	return "[" + cpse.IAMPrincipalArn + "] [" + cpse.PolicyDocumentName + "] " + cpse.Message
}

func NewCustomPolicyScanWorker(config CustomPolicyScanWorkerConfig) (*CustomPolicyScanWorker, error) {
	log.Printf("semaphore capacity size : %v \n", cap(config.SemaphoreChan))
	//  perform nil checks for required fields
	if config.RestrictedActions == nil || config.ConfigEvaluationChan == nil || config.SemaphoreChan == nil || config.EventTime.IsZero() {
		return nil, errors.New("required field(s) cannot be nil")
	}

	// create cache if specified
	var customPolicyResultsCache cache.CustomPolicyScanResultsCache
	if config.EnableCache {
		customPolicyResultsCache = cache.NewCustomPolicyScanResultsCache()
	}

	// initalize worker interface
	worker, err := NewWorker(config.WorkerConfig)
	if err != nil {
		return nil, err
	}

	// initialize semaphore channels
	for i := 0; i < cap(config.SemaphoreChan); i++ {
		config.SemaphoreChan <- make(chan interface{}, 1)
	}

	// create custom policy scan worker
	customPolicyScanWorker := &CustomPolicyScanWorker{
		restrictedActions:              config.RestrictedActions,
		configEvaluationChan:           config.ConfigEvaluationChan,
		semaphoreChan:                  config.SemaphoreChan,
		eventTime:                      config.EventTime,
		customPolicyScanResultsCache:   customPolicyResultsCache,
		errorHandler:                   &_CustomPolicyScanErrorHandler{},
		precompliantIamIdentityHandler: &_PrecompliantIamIdentityHandler{},
		Worker:                         worker,
	}

	worker.SetRequestHandler(customPolicyScanWorker) // set request handler
	worker.SetFinalizer(customPolicyScanWorker)      // set finalizer
	log.Printf("custom policy scan worker created with semaphore size [%v]\n", len(config.SemaphoreChan))

	return customPolicyScanWorker, nil
}

// handle requests
func (cpw *CustomPolicyScanWorker) Handle(request interface{}) {
	customPolicyScanWorkerRequest := request.(CustomPolicyScanWorkerRequest) // type assert to custom policy scan request
	errorChan := cpw.Worker.GetErrorChannel()                                // get error channel
	configEvaluationChan := cpw.configEvaluationChan                         // get config Evaluation channel
	semaphoreChan := cpw.semaphoreChan                                       // get semaphore channel of channel
	restrictedActions := cpw.restrictedActions                               // get restricted actions
	iamClient := customPolicyScanWorkerRequest.IamApi                        // get iam client
	accessAnalyzerClient := customPolicyScanWorkerRequest.AccessAnalyzerApi  // get access analyzer client
	accountId := customPolicyScanWorkerRequest.AccountId                     // get account id
	iamIdentity := customPolicyScanWorkerRequest.IamIdentity                 // iam identity
	customPolicyScanResultsCache := cpw.customPolicyScanResultsCache         // get cache

	// handle precompliant requests
	if customPolicyScanWorkerRequest.PrecompliantIamIdentityRequest {
		log.Printf("handling precompliant iam identity request for [%v]\n", iamIdentity.GetIdentityArn())
		cpw.precompliantIamIdentityHandler.Handle(handlePrecompliantIamIdentityRequestInput{
			request:              customPolicyScanWorkerRequest,
			configEvaluationChan: configEvaluationChan,
		})
		return
	}

	log.Printf("handling custom policy scan request for [%v]\n", iamIdentity.GetIdentityArn())
	complianceResultsChan := <-semaphoreChan // take channel from semaphore
	log.Println("got channel from semaphore")

	// process role compliance for iam identity
	err := iamIdentity.ProcessPolicyCompliance(context.Background(), ProcessPolicyComplianceInput{
		AccountId:            accountId,
		RestrictedActions:    restrictedActions,
		EventTime:            cpw.eventTime,
		IamIdentity:          iamIdentity,
		ErrorChan:            errorChan,
		ComplianceResults:    complianceResultsChan,
		ConfigEvaluationChan: configEvaluationChan,
		IamApi:               iamClient,
		Accessanalyzerapi:    accessAnalyzerClient,
		Cache:                customPolicyScanResultsCache,
		ErrorHandler:         cpw.errorHandler,
	})

	semaphoreChan <- complianceResultsChan // return channel to semaphore
	log.Println("returned channel to semaphore")

	if err != nil {
		log.Printf("error occured while processing policy compliance for iam identity [%v]: [%v]\n", iamIdentity.GetIdentityArn(), err.Error())
		errorChan <- err
		return
	}

}

// finalize processings
func (cpw *CustomPolicyScanWorker) Finalize() {
}

type isCompliantInput struct {
	ctx                  context.Context
	accessAnalyzerClient accessanalyzerapi.AccessAnalyzerApi
	policyDocument       string
	policyDocumentName   string
	resourceArn          string
	restrictedActions    []string
}

func isCompliant(input isCompliantInput) (CustomPolicyScanResult, error) {
	// perform nil checks
	if len(input.restrictedActions) == 0 || input.policyDocument == "" || input.policyDocumentName == "" || input.resourceArn == "" {
		return CustomPolicyScanResult{}, errors.New("policy document name, policy document and resource arn cannot be empty")
	}

	log.Printf("checking if policy [%v] is compliant\n", input.policyDocumentName)

	checkAccessNotGrantedInput := accessanalyzer.CheckAccessNotGrantedInput{
		Access: []accessAnalyzerTypes.Access{
			{
				Actions: input.restrictedActions,
			},
		},
		PolicyDocument: aws.String(input.policyDocument),
		PolicyType:     accessAnalyzerTypes.AccessCheckPolicyTypeIdentityPolicy,
	}

	output, err := input.accessAnalyzerClient.CheckAccessNotGranted(input.ctx, &checkAccessNotGrantedInput)
	// return errors
	if err != nil {
		log.Printf("error occured while checking if policy [%v] is compliant: [%v]\n", input.policyDocumentName, err.Error())
		if strings.Contains(err.Error(), shared.DenyOnlyErrMsg) {
			log.Printf("policy [%v] is compliant\n", input.policyDocumentName)
			customPolicyScanResults, err := newCustomPolicyScanResult(complianceResultInput{
				compliance:  configServiceTypes.ComplianceTypeCompliant,
				reasons:     nil,
				message:     "",
				policyName:  input.policyDocumentName,
				resourceArn: input.resourceArn,
			})
			if err != nil {
				log.Printf("error occured while creating compliance result for policy [%v]: [%v]\n", input.policyDocumentName, err.Error())
				return CustomPolicyScanResult{
					Compliance:         configServiceTypes.ComplianceTypeNonCompliant,
					Reasons:            nil,
					Message:            err.Error(),
					PolicyDocumentName: input.policyDocumentName,
					ResourceArn:        input.resourceArn,
				}, err
			}
			log.Printf("returning [%v] compliance result for policy [%v]\n", configServiceTypes.ComplianceTypeCompliant, input.policyDocumentName)
			return customPolicyScanResults, nil
		} else {
			log.Printf("policy [%v] is not compliant\n", input.policyDocumentName)
			return CustomPolicyScanResult{
				Compliance:         configServiceTypes.ComplianceTypeNonCompliant,
				Reasons:            []string{err.Error()},
				Message:            "",
				PolicyDocumentName: input.policyDocumentName,
				ResourceArn:        input.resourceArn,
			}, err
		}
	}

	// check if policy is compliant
	if output.Result == accessAnalyzerTypes.CheckAccessNotGrantedResultPass {
		customPolicyScanResults, _ := newCustomPolicyScanResult(complianceResultInput{
			compliance:  configServiceTypes.ComplianceTypeCompliant,
			reasons:     output.Reasons,
			message:     *output.Message,
			policyName:  input.policyDocumentName,
			resourceArn: input.resourceArn,
		})

		log.Printf("returning [%v] compliance result for policy [%v]\n", configServiceTypes.ComplianceTypeCompliant, input.policyDocumentName)
		return customPolicyScanResults, nil
	} else {
		customPolicyScanResults, err := newCustomPolicyScanResult(complianceResultInput{
			compliance:  configServiceTypes.ComplianceTypeNonCompliant,
			reasons:     output.Reasons,
			message:     *output.Message,
			policyName:  input.policyDocumentName,
			resourceArn: input.resourceArn,
		})
		if err != nil {
			log.Printf("error occured while creating compliance result for policy [%v]: [%v]\n", input.policyDocumentName, err.Error())
			return CustomPolicyScanResult{}, err
		}
		log.Printf("returning [%v] compliance result for policy [%v]\n", configServiceTypes.ComplianceTypeNonCompliant, input.policyDocumentName)
		return customPolicyScanResults, nil
	}
}

type complianceResultInput struct {
	compliance  configServiceTypes.ComplianceType
	reasons     []accessAnalyzerTypes.ReasonSummary
	message     string
	policyName  string
	resourceArn string
}

func newCustomPolicyScanResult(input complianceResultInput) (CustomPolicyScanResult, error) {

	if input.compliance == "" {
		log.Printf("cannot create compliance result without compliance type : [%+v]\n", input)
		return CustomPolicyScanResult{}, errors.New("cannot create compliance result without compliance type")
	}

	if input.resourceArn == "" {
		log.Printf("cannot create compliance result without resource arn : [%+v]\n", input)
		return CustomPolicyScanResult{}, errors.New("cannot create compliance result without resource arn")
	}

	if input.message != "" && input.reasons == nil {
		return CustomPolicyScanResult{
			Compliance:         input.compliance,
			Reasons:            []string{input.message},
			Message:            input.message,
			PolicyDocumentName: input.policyName,
			ResourceArn:        input.resourceArn,
		}, nil
	}

	return CustomPolicyScanResult{
		Compliance:         input.compliance,
		Reasons:            shared.ConvertReasonsToString(input.reasons),
		Message:            input.message,
		PolicyDocumentName: input.policyName,
		ResourceArn:        input.resourceArn,
	}, nil
}

type handleCustomPolicyscanErrorInput struct {
	err                         CustomPolicyScanError
	errorChan                   chan<- error
	customPolicyScanResultsChan chan<- interface{}
	cache                       cache.CustomPolicyScanResultsCache
	complianceResultInput       complianceResultInput
}
