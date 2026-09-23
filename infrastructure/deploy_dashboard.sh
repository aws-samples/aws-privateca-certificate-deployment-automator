#!/bin/bash
#
# Deploy (or preview) the optional CloudWatch dashboard stack.
#
# This helper keeps the dashboard stack fully independent of the main stack.
# It reads the *deployed* main stack, discovers the resources the dashboard
# references (Step Functions state machine ARN, DynamoDB table name, SNS topic
# name, ACM PCA ARN), and passes them to infrastructure/dashboard.yaml as
# CloudFormation parameters. Nothing in the main stack is modified.
#
# Discovery is read-only (describe/list calls). Deployment uses
# `aws cloudformation deploy`, which creates and applies a change set; the
# dashboard stack contains only an AWS::CloudWatch::Dashboard resource, so it is
# safe to create, update, and delete without affecting the main stack.
#
# Usage:
#   ./deploy_dashboard.sh MAIN_STACK_NAME [options]
#
# Options:
#   --deploy                       Actually deploy. Without this, the script
#                                  only prints discovered parameters (read-only).
#   --dashboard-stack-name NAME    Dashboard stack name.
#                                  Default: <MAIN_STACK_NAME>-dashboard
#   --region REGION                AWS region. Default: environment/profile region.
#   -h, --help                     Show this help.
#
# Examples:
#   ./deploy_dashboard.sh ssm-pca-stack
#   ./deploy_dashboard.sh ssm-pca-stack --deploy
#   ./deploy_dashboard.sh ssm-pca-stack --deploy --region us-east-1

set -euo pipefail

# Terminal colors for readable output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_PATH="${SCRIPT_DIR}/dashboard.yaml"

# Main-stack output key that already exports the PCA ARN.
PCA_OUTPUT_KEY="PCAARN"

usage() {
    sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^#//; s/^ //'
}

err() {
    echo -e "${RED}[ERROR] $*${NC}" >&2
}

# --- Parse arguments -------------------------------------------------------

MAIN_STACK_NAME=""
DO_DEPLOY=0
DASHBOARD_STACK_NAME=""
REGION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deploy)
            DO_DEPLOY=1
            shift
            ;;
        --dashboard-stack-name)
            DASHBOARD_STACK_NAME="${2:-}"
            if [[ -z "$DASHBOARD_STACK_NAME" ]]; then
                err "--dashboard-stack-name requires a value"
                exit 1
            fi
            shift 2
            ;;
        --region)
            REGION="${2:-}"
            if [[ -z "$REGION" ]]; then
                err "--region requires a value"
                exit 1
            fi
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            err "Unknown option: $1"
            usage
            exit 1
            ;;
        *)
            if [[ -n "$MAIN_STACK_NAME" ]]; then
                err "Unexpected extra argument: $1"
                exit 1
            fi
            MAIN_STACK_NAME="$1"
            shift
            ;;
    esac
done

if [[ -z "$MAIN_STACK_NAME" ]]; then
    err "MAIN_STACK_NAME is required."
    usage
    exit 1
fi

if [[ ! -f "$TEMPLATE_PATH" ]]; then
    err "Dashboard template not found at $TEMPLATE_PATH"
    exit 1
fi

if ! command -v aws &> /dev/null; then
    err "The 'aws' CLI was not found on PATH. Install it and retry."
    exit 1
fi

DASHBOARD_STACK_NAME="${DASHBOARD_STACK_NAME:-${MAIN_STACK_NAME}-dashboard}"

# Region flag shared by all aws calls (empty expands to nothing).
REGION_ARGS=()
if [[ -n "$REGION" ]]; then
    REGION_ARGS=(--region "$REGION")
fi

# --- Discovery (read-only) -------------------------------------------------

# Query a single stack resource's physical id by CloudFormation resource type.
# Fails if zero or more than one match is found, matching the Python helper.
discover_single() {
    local resource_type="$1"
    local human_name="$2"
    local matches
    # --output text prints tab/newline-separated values; capture into an array.
    matches=$(aws cloudformation list-stack-resources \
        ${REGION_ARGS[@]+"${REGION_ARGS[@]}"} \
        --stack-name "$MAIN_STACK_NAME" \
        --query "StackResourceSummaries[?ResourceType=='${resource_type}'].PhysicalResourceId" \
        --output text 2>/dev/null || true)

    # Normalize whitespace to newlines and drop empties.
    local -a ids=()
    local id
    while IFS= read -r id; do
        [[ -n "$id" ]] && ids+=("$id")
    done < <(echo "$matches" | tr '\t' '\n')

    if [[ ${#ids[@]} -eq 0 ]]; then
        err "No ${human_name} (${resource_type}) found in stack '${MAIN_STACK_NAME}'."
        exit 2
    fi
    if [[ ${#ids[@]} -gt 1 ]]; then
        err "Expected exactly one ${human_name} (${resource_type}) in stack '${MAIN_STACK_NAME}', found ${#ids[@]}: ${ids[*]}. Disambiguate before deploying the dashboard."
        exit 2
    fi
    printf '%s' "${ids[0]}"
}

# Resolve the PCA ARN, preferring the exported stack output, falling back to
# the resource physical id.
discover_pca_arn() {
    local pca_arn
    pca_arn=$(aws cloudformation describe-stacks \
        ${REGION_ARGS[@]+"${REGION_ARGS[@]}"} \
        --stack-name "$MAIN_STACK_NAME" \
        --query "Stacks[0].Outputs[?OutputKey=='${PCA_OUTPUT_KEY}'].OutputValue" \
        --output text 2>/dev/null || true)
    if [[ -n "$pca_arn" && "$pca_arn" != "None" ]]; then
        printf '%s' "$pca_arn"
        return 0
    fi
    discover_single "AWS::ACMPCA::CertificateAuthority" "ACM Private CA"
}

# Verify the main stack is readable up front for a clean error message.
if ! aws cloudformation describe-stacks \
        ${REGION_ARGS[@]+"${REGION_ARGS[@]}"} \
        --stack-name "$MAIN_STACK_NAME" >/dev/null 2>&1; then
    err "Could not read stack '${MAIN_STACK_NAME}'${REGION:+ in ${REGION}}. Check the name, region, and credentials."
    exit 2
fi

STATE_MACHINE_ARN="$(discover_single "AWS::StepFunctions::StateMachine" "Step Functions state machine")"
DYNAMODB_TABLE_NAME="$(discover_single "AWS::DynamoDB::Table" "DynamoDB table")"
SNS_TOPIC_ARN="$(discover_single "AWS::SNS::Topic" "SNS topic")"
# Physical id of an SNS topic is its ARN; topic name is the last colon segment.
SNS_TOPIC_NAME="${SNS_TOPIC_ARN##*:}"
PCA_ARN="$(discover_pca_arn)"

# --- Report ----------------------------------------------------------------

echo -e "${BLUE}Discovered parameters from main stack '${MAIN_STACK_NAME}':${NC}"
echo ""
echo "  MainStackName     = ${MAIN_STACK_NAME}"
echo "  StateMachineArn   = ${STATE_MACHINE_ARN}"
echo "  DynamoDBTableName = ${DYNAMODB_TABLE_NAME}"
echo "  SNSTopicName      = ${SNS_TOPIC_NAME}"
echo "  PCAArn            = ${PCA_ARN}"
echo ""

# Assemble the deploy command as an array (safe quoting).
DEPLOY_CMD=(aws cloudformation deploy
    --template-file "$TEMPLATE_PATH"
    --stack-name "$DASHBOARD_STACK_NAME"
    --parameter-overrides
        "MainStackName=${MAIN_STACK_NAME}"
        "StateMachineArn=${STATE_MACHINE_ARN}"
        "DynamoDBTableName=${DYNAMODB_TABLE_NAME}"
        "SNSTopicName=${SNS_TOPIC_NAME}"
        "PCAArn=${PCA_ARN}")
if [[ -n "$REGION" ]]; then
    DEPLOY_CMD+=(--region "$REGION")
fi

# --- Dry run vs deploy -----------------------------------------------------

if [[ "$DO_DEPLOY" -eq 0 ]]; then
    echo "Dry run (no --deploy). To deploy the dashboard stack, re-run with --deploy or run:"
    echo ""
    # Render a readable, copy-pasteable command.
    printf '    aws cloudformation deploy \\\n'
    printf '      --template-file %q \\\n' "$TEMPLATE_PATH"
    printf '      --stack-name %q \\\n' "$DASHBOARD_STACK_NAME"
    printf '      --parameter-overrides \\\n'
    printf '        MainStackName=%q \\\n' "$MAIN_STACK_NAME"
    printf '        StateMachineArn=%q \\\n' "$STATE_MACHINE_ARN"
    printf '        DynamoDBTableName=%q \\\n' "$DYNAMODB_TABLE_NAME"
    printf '        SNSTopicName=%q \\\n' "$SNS_TOPIC_NAME"
    if [[ -n "$REGION" ]]; then
        printf '        PCAArn=%q \\\n' "$PCA_ARN"
        printf '      --region %q\n' "$REGION"
    else
        printf '        PCAArn=%q\n' "$PCA_ARN"
    fi
    echo ""
    exit 0
fi

echo -e "${BLUE}Deploying dashboard stack '${DASHBOARD_STACK_NAME}'...${NC}"
echo ""
if "${DEPLOY_CMD[@]}"; then
    echo -e "\n${GREEN}[SUCCESS] Dashboard stack '${DASHBOARD_STACK_NAME}' deployed.${NC}"
    exit 0
else
    rc=$?
    err "Dashboard deployment failed (exit code ${rc})."
    exit "$rc"
fi
