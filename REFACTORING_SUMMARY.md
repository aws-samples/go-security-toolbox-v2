# Refactoring Summary: Single Lambda with Rule-Based Routing

## Overview
Successfully refactored the project from two separate Lambda functions to a single unified Lambda function that routes requests based on AWS Config rule names.

## Changes Made

### New Files Created
- `cmd/configrule/main.go` - Unified Lambda entry point
- `internal/handlers/router.go` - Rule-based routing logic
- `deployment/configrule/template.yaml` - Unified SAM template
- `deployment/configrule/Makefile` - Build and deployment commands
- `deployment/configrule/samconfig.toml` - SAM configuration

### Files to Remove (Manual Cleanup Required)
- `cmd/checkaccessnotgranted/main.go`
- `cmd/orphanpolicyfinder/main.go`
- `deployment/checkaccessnotgranted/` (entire directory)
- `deployment/orphanpolicyfinder/` (entire directory)

### Modified Files
- `README.md` - Updated with new deployment instructions

## Architecture Changes

### Before
- Two separate Lambda functions
- Two separate deployment configurations
- Duplicate initialization code

### After
- Single Lambda function with rule-based routing
- Single deployment configuration
- Shared initialization and error handling
- Route based on `event.ConfigRuleName`

## Config Rule Names
- `check-access-not-granted` → CheckAccessNotGrantedHandler
- `orphan-policy-finder` → OrphanPolicyFinderHandler

## Deployment
```bash
cd deployment/configrule
make build
make deploy
```

## Benefits Achieved
1. **Reduced Complexity**: Single deployment artifact
2. **Code Reuse**: Shared AWS config loading and error handling
3. **Maintainability**: Centralized routing logic
4. **Cost Efficiency**: Single Lambda function vs multiple
5. **Scalability**: Easy to add new rule handlers

## Testing
- Build completed successfully with `sam build`
- All existing handler logic preserved
- No breaking changes to existing functionality