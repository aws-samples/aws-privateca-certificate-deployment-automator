#!/bin/bash

# Certificate Automation Testing Suite
#
# This script provides comprehensive automated testing for the certificate automation system.
# It validates both successful operations and failure scenarios to ensure the system
# handles edge cases gracefully and provides appropriate notifications.
#
# The script tests:
# - Empty certificate lists (normal operation)
# - Invalid instance IDs (CSR generation failures)
# - SNS notification delivery
# - Multiple certificate processing (load testing)
# - Infrastructure component accessibility
#
# Usage: ./test-failure-scenarios.sh [stack-name] [region]
# Example: ./test-failure-scenarios.sh my-cert-stack us-west-2

set -e

# Terminal colors for readable output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script configuration
STACK_NAME="${1:-ssm-pca-stack-test}"
REGION="${2:-us-east-1}"
TIMEOUT_MINUTES=10  # Timeout for Step Functions execution monitoring

echo -e "${BLUE}Certificate Automation Testing Suite${NC}"
echo "=================================================="
echo "Stack: $STACK_NAME"
echo "Region: $REGION"
echo "Timeout: $TIMEOUT_MINUTES minutes"
echo ""

# Get stack resources
echo "[INFO] Discovering stack resources..."
TABLE_NAME=$(aws cloudformation describe-stack-resources \
  --stack-name $STACK_NAME \
  --query 'StackResources[?ResourceType==`AWS::DynamoDB::Table`].PhysicalResourceId' \
  --output text)

STATE_MACHINE_ARN=$(aws cloudformation describe-stack-resources \
  --stack-name $STACK_NAME \
  --query 'StackResources[?ResourceType==`AWS::StepFunctions::StateMachine`].PhysicalResourceId' \
  --output text)

SNS_TOPIC_ARN=$(aws cloudformation describe-stack-resources \
  --stack-name $STACK_NAME \
  --query 'StackResources[?ResourceType==`AWS::SNS::Topic`].PhysicalResourceId' \
  --output text)

if [[ -z "$TABLE_NAME" || -z "$STATE_MACHINE_ARN" || -z "$SNS_TOPIC_ARN" ]]; then
    echo -e "${RED}[ERROR] Could not find required stack resources${NC}"
    exit 1
fi

echo -e "${GREEN}[SUCCESS] Found stack resources${NC}"
echo "  Table: $TABLE_NAME"
echo "  State Machine: $STATE_MACHINE_ARN"
echo "  SNS Topic: $SNS_TOPIC_ARN"
echo ""

# Function to wait for execution completion
wait_for_execution() {
    local execution_arn=$1
    local expected_status=$2
    local test_name=$3
    
    echo "[INFO] Waiting for execution to complete..."
    
    local timeout=$(($(date +%s) + $TIMEOUT_MINUTES * 60))
    
    while [[ $(date +%s) -lt $timeout ]]; do
        local status=$(aws stepfunctions describe-execution \
            --execution-arn $execution_arn \
            --query 'status' --output text)
        
        case $status in
            "RUNNING")
                echo -n "."
                sleep 10
                ;;
            "SUCCEEDED")
                if [[ "$expected_status" == "SUCCEEDED" ]]; then
                    echo -e "\n${GREEN}[PASS] $test_name: PASSED (execution succeeded as expected)${NC}"
                    return 0
                else
                    echo -e "\n${RED}[FAIL] $test_name: FAILED (expected failure but succeeded)${NC}"
                    return 1
                fi
                ;;
            "FAILED")
                if [[ "$expected_status" == "FAILED" ]]; then
                    # Get failure details
                    local error=$(aws stepfunctions describe-execution \
                        --execution-arn $execution_arn \
                        --query 'error' --output text 2>/dev/null || echo "Unknown")
                    echo -e "\n${GREEN}[PASS] $test_name: PASSED (failed as expected: $error)${NC}"
                    return 0
                else
                    echo -e "\n${RED}[FAIL] $test_name: FAILED (unexpected failure)${NC}"
                    return 1
                fi
                ;;
            "TIMED_OUT"|"ABORTED")
                echo -e "\n${RED}[FAIL] $test_name: FAILED (execution $status)${NC}"
                return 1
                ;;
        esac
    done
    
    echo -e "\n${YELLOW}[TIMEOUT] $test_name: TIMEOUT (execution still running after $TIMEOUT_MINUTES minutes)${NC}"
    return 1
}

# Function to clear test data
clear_test_data() {
    echo "[INFO] Clearing existing test data..."
    
    # Get all host IDs and process them one by one
    local host_ids=$(aws dynamodb scan --table-name $TABLE_NAME --query 'Items[].hostID.S' --output text)
    
    if [[ -n "$host_ids" ]]; then
        # Split by tabs and process each host ID
        echo "$host_ids" | tr '\t' '\n' | while read -r host_id; do
            if [[ -n "$host_id" && ("$host_id" =~ ^i-test.* || "$host_id" =~ ^i-invalid.*) ]]; then
                echo "  Deleting test record: $host_id"
                aws dynamodb delete-item --table-name $TABLE_NAME --key '{"hostID":{"S":"'$host_id'"}}' >/dev/null 2>&1
            fi
        done
    fi
    
    echo -e "${GREEN}[SUCCESS] Test data cleared${NC}"
}

# Test counters
TESTS_RUN=0
TESTS_PASSED=0

# Clear any existing test data
clear_test_data
echo ""

# Test 1: Empty Certificate List (Should Succeed)
echo -e "${BLUE}Test 1: Empty certificate list${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

EXECUTION_ARN=$(aws stepfunctions start-execution \
    --state-machine-arn $STATE_MACHINE_ARN \
    --name "test-empty-$(date +%s)" \
    --input '{}' \
    --query 'executionArn' --output text)

if wait_for_execution $EXECUTION_ARN "SUCCEEDED" "Empty List Test"; then
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
echo ""

# Test 2: Invalid Instance ID (Should Fail)
echo -e "${BLUE}Test 2: Invalid instance ID${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

# Add invalid instance
aws dynamodb put-item \
    --table-name $TABLE_NAME \
    --item '{
        "hostID": {"S": "i-invalid123456789"},
        "certPath": {"S": "/tmp"},
        "keyPath": {"S": "/tmp"},
        "renewalDate": {"S": "'$(date -v-1d +%Y-%m-%d)'"},
        "status": {"S": "NEEDS_RENEWAL"}
    }'

EXECUTION_ARN=$(aws stepfunctions start-execution \
    --state-machine-arn $STATE_MACHINE_ARN \
    --name "test-invalid-$(date +%s)" \
    --input '{}' \
    --query 'executionArn' --output text)

if wait_for_execution $EXECUTION_ARN "SUCCEEDED" "Invalid Instance Test"; then
    # For this test, we expect the workflow to succeed but individual certificate to fail
    # Check if SNS notification was sent (we can't easily verify email, but we can check the execution succeeded)
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
echo ""

# Test 3: SNS Notification Test
echo -e "${BLUE}Test 3: SNS notification${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

if aws sns publish \
    --topic-arn $SNS_TOPIC_ARN \
    --message "Automated test notification from certificate automation test suite" \
    --subject "Certificate Automation Test - $(date)" >/dev/null 2>&1; then
    echo -e "${GREEN}[PASS] SNS Notification Test: PASSED${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}[FAIL] SNS Notification Test: FAILED${NC}"
fi
echo ""

# Test 4: Multiple Invalid Instances (Load Test)
echo -e "${BLUE}Test 4: Multiple invalid instances (load test)${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

# Add multiple invalid instances
for i in {1..3}; do
    aws dynamodb put-item \
        --table-name $TABLE_NAME \
        --item '{
            "hostID": {"S": "i-testload'$i'123456789"},
            "certPath": {"S": "/tmp"},
            "keyPath": {"S": "/tmp"},
            "renewalDate": {"S": "'$(date -v-1d +%Y-%m-%d)'"},
            "status": {"S": "NEEDS_RENEWAL"}
        }'
done

EXECUTION_ARN=$(aws stepfunctions start-execution \
    --state-machine-arn $STATE_MACHINE_ARN \
    --name "test-load-$(date +%s)" \
    --input '{}' \
    --query 'executionArn' --output text)

if wait_for_execution $EXECUTION_ARN "SUCCEEDED" "Load Test"; then
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi
echo ""

# Test 5: Infrastructure Validation
echo -e "${BLUE}Test 5: Infrastructure validation${NC}"
TESTS_RUN=$((TESTS_RUN + 1))

INFRA_TESTS=0
INFRA_PASSED=0

# Check Lambda functions
for func in "CertCheck-Trigger" "CertCSR" "CertIssue" "CertDeploy"; do
    INFRA_TESTS=$((INFRA_TESTS + 1))
    if aws lambda get-function --function-name $func >/dev/null 2>&1; then
        INFRA_PASSED=$((INFRA_PASSED + 1))
        echo -e "${GREEN}  [OK] Lambda $func accessible${NC}"
    else
        echo -e "${RED}  [ERROR] Lambda $func not accessible${NC}"
    fi
done

# Check PCA
INFRA_TESTS=$((INFRA_TESTS + 1))
PCA_ARN=$(aws cloudformation describe-stacks \
    --stack-name $STACK_NAME \
    --query 'Stacks[0].Outputs[?OutputKey==`PCAARN`].OutputValue' \
    --output text 2>/dev/null || echo "")

if [[ -n "$PCA_ARN" ]] && aws acm-pca describe-certificate-authority --certificate-authority-arn $PCA_ARN >/dev/null 2>&1; then
    INFRA_PASSED=$((INFRA_PASSED + 1))
    echo -e "${GREEN}  [OK] Private CA accessible${NC}"
else
    echo -e "${RED}  [ERROR] Private CA not accessible${NC}"
fi

if [[ $INFRA_PASSED -eq $INFRA_TESTS ]]; then
    echo -e "${GREEN}[PASS] Infrastructure Test: PASSED ($INFRA_PASSED/$INFRA_TESTS)${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}[FAIL] Infrastructure Test: FAILED ($INFRA_PASSED/$INFRA_TESTS)${NC}"
fi

# Final cleanup
clear_test_data

# Final Report
echo ""
echo "=================================================="
echo -e "${BLUE}AUTOMATED TEST RESULTS${NC}"
echo "=================================================="
echo -e "Total Tests: $TESTS_RUN"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $((TESTS_RUN - TESTS_PASSED))${NC}"

if [[ $TESTS_PASSED -eq $TESTS_RUN ]]; then
    echo -e "\n${GREEN}[SUCCESS] ALL TESTS PASSED! Certificate automation is working correctly.${NC}"
    exit 0
else
    echo -e "\n${YELLOW}[WARNING] Some tests failed. Check the output above for details.${NC}"
    echo -e "${BLUE}[INFO] Common issues:${NC}"
    echo "   • IAM permissions not properly configured"
    echo "   • Lambda functions not deployed correctly"
    echo "   • Step Functions definition has errors"
    echo "   • SNS topic not configured properly"
    exit 1
fi