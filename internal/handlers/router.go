package handlers

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/config"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/logger"
)

const (
	CheckAccessNotGrantedRule = "check-access-not-granted"
	OrphanPolicyFinderRule    = "orphan-policy-finder"
)

type RuleRouter struct {
	handlers map[string]interface{}
	logger   logger.Logger
}

func NewRuleRouter(cfg aws.Config, log logger.Logger, configMgr config.ConfigManager) (*RuleRouter, error) {
	if log == nil {
		log = logger.NewLogger()
	}

	handlers := make(map[string]interface{})

	// Register CheckAccessNotGranted handler
	cangHandler, err := NewCheckAccessNotGrantedHandler(cfg, log, configMgr)
	if err != nil {
		return nil, fmt.Errorf("failed to create CheckAccessNotGranted handler: %w", err)
	}
	handlers[CheckAccessNotGrantedRule] = cangHandler

	// Register OrphanPolicyFinder handler
	opfHandler, err := NewOrphanPolicyFinder(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create OrphanPolicyFinder handler: %w", err)
	}
	handlers[OrphanPolicyFinderRule] = opfHandler

	return &RuleRouter{
		handlers: handlers,
		logger:   log,
	}, nil
}

func (r *RuleRouter) Route(ctx context.Context, event events.ConfigEvent) error {
	ruleName := event.ConfigRuleName
	r.logger.Info("routing request for rule: [%s]", ruleName)

	handler, exists := r.handlers[ruleName]
	if !exists {
		return fmt.Errorf("unsupported config rule: %s", ruleName)
	}

	// Route to appropriate handler based on rule name
	switch ruleName {
	case CheckAccessNotGrantedRule:
		if h, ok := handler.(Handler[CheckAccessNotGrantedEvent]); ok {
			return h.Handle(ctx, CheckAccessNotGrantedEvent{ConfigEvent: event})
		}
	case OrphanPolicyFinderRule:
		if h, ok := handler.(Handler[OrphanPolicyFinderEvent]); ok {
			return h.Handle(ctx, OrphanPolicyFinderEvent{ConfigEvent: event})
		}
	}
	return fmt.Errorf("unsupported config rule: %s", ruleName)
}