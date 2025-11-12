#!/bin/bash

# Exit on error
set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

# Configuration
# This contains the AWS related information - these variables can be abstracted out
AWS_REGION="${AWS_REGION:-us-west-2}"
LAMBDA_FUNCTION_NAME="ambient-agent-scheduled-monitor"
LAMBDA_ROLE_NAME="ambient-agent-lambda-role"
EVENTBRIDGE_RULE_NAME="ambient-agent-15min-check"

echo "🚀 Deploying Ambient Agent Lambda Integration"
echo "=============================================="
echo ""

# Check if .env file exists
if [ ! -f "$PARENT_DIR/.env" ]; then
    echo "❌ Error: .env file not found!"
    echo "Please create a .env file with required configuration."
    echo "See .env.example for reference."
    exit 1
fi

# Load environment variables from .env file
echo "📋 Loading environment variables from .env..."
export $(cat "$PARENT_DIR/.env" | grep -v '^#' | xargs)

# Validate required environment variables
# These are required variables that are fetched from the configuration file
REQUIRED_VARS=(
    "AGENTCORE_RUNTIME_URL"
    "SLACK_WEBHOOK_URL"
    "SLACK_SIGNING_SECRET"
)

# These are the M2M variables that are used to generate a bearer token to invoke the
# agent that runs on AgentCore runtime
OPTIONAL_M2M_VARS=(
    "COGNITO_DOMAIN_URL"
    "M2M_CLIENT_ID"
    "M2M_CLIENT_SECRET"
    "RESOURCE_SERVER_ID"
)

for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        echo "❌ Error: Required environment variable $var is not set"
        exit 1
    fi
done

M2M_CONFIGURED=true

for var in "${OPTIONAL_M2M_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        M2M_CONFIGURED=false
        break
    fi
done

if [ "$M2M_CONFIGURED" = false ]; then
    echo "❌ Error: No valid authentication method configured"
    echo "Please configure either:"
    echo "  1. M2M credentials (recommended): COGNITO_DOMAIN_URL, M2M_CLIENT_ID, M2M_CLIENT_SECRET, RESOURCE_SERVER_ID"
    echo "  2. Username/password: COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET, COGNITO_USERNAME, COGNITO_PASSWORD"
    exit 1
fi

if [ "$M2M_CONFIGURED" = true ]; then
    echo "✅ Using M2M client credentials authentication (recommended)"
else
    echo "⚠️  Using username/password authentication (fallback)"
    echo "    Note: Requires USER_PASSWORD_AUTH flow enabled in Cognito app client"
fi

echo "✅ All required environment variables are set"
echo ""

# Get AWS Account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "📌 AWS Account ID: $AWS_ACCOUNT_ID"
echo "📌 AWS Region: $AWS_REGION"
echo ""

# Step 1: Create IAM role for Lambda
echo "🔐 Step 1: Creating IAM role for Lambda..."

# Check if role already exists
if aws iam get-role --role-name "$LAMBDA_ROLE_NAME" 2>/dev/null; then
    echo "✅ IAM role $LAMBDA_ROLE_NAME already exists"
else
    # Create trust policy for Lambda
    cat > /tmp/lambda-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

    # Create the IAM role
    aws iam create-role \
        --role-name "$LAMBDA_ROLE_NAME" \
        --assume-role-policy-document file:///tmp/lambda-trust-policy.json \
        --description "Role for Ambient Agent Lambda function"

    echo "✅ IAM role created: $LAMBDA_ROLE_NAME"
fi

# Step 2: Attach policies to the role
echo "🔐 Step 2: Attaching policies to IAM role..."

# Attach basic Lambda execution policy
aws iam attach-role-policy \
    --role-name "$LAMBDA_ROLE_NAME" \
    --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole" || true

# Create and attach custom policy for CloudWatch and Cognito
cat > /tmp/lambda-custom-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:DescribeAlarms",
        "cloudwatch:GetMetricData",
        "cloudwatch:ListDashboards",
        "logs:DescribeLogGroups",
        "logs:FilterLogEvents",
        "logs:GetLogEvents"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "cognito-idp:InitiateAuth"
      ],
      "Resource": "arn:aws:cognito-idp:${AWS_REGION}:${AWS_ACCOUNT_ID}:userpool/${COGNITO_USER_POOL_ID}"
    }
  ]
}
EOF

# Create or update the policy
POLICY_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:policy/AmbientAgentLambdaPolicy"

if aws iam get-policy --policy-arn "$POLICY_ARN" 2>/dev/null; then
    echo "✅ Policy already exists, creating new version..."
    aws iam create-policy-version \
        --policy-arn "$POLICY_ARN" \
        --policy-document file:///tmp/lambda-custom-policy.json \
        --set-as-default || true
else
    aws iam create-policy \
        --policy-name "AmbientAgentLambdaPolicy" \
        --policy-document file:///tmp/lambda-custom-policy.json \
        --description "Custom policy for Ambient Agent Lambda"
    echo "✅ Policy created: $POLICY_ARN"
fi

# Attach custom policy to role
aws iam attach-role-policy \
    --role-name "$LAMBDA_ROLE_NAME" \
    --policy-arn "$POLICY_ARN" || true

echo "✅ Policies attached"
echo "⏳ Waiting 10 seconds for IAM role to propagate..."
sleep 10
echo ""

# Step 3: Package Lambda function
echo "📦 Step 3: Packaging Lambda function..."

cd "$PARENT_DIR/lambda"
# package the lambda function
zip -r /tmp/scheduled_monitor.zip scheduled_monitor.py

echo "✅ Lambda function packaged"
echo ""

# Step 4: Create or update Lambda function
echo "🚀 Step 4: Deploying Lambda function..."

LAMBDA_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${LAMBDA_ROLE_NAME}"

if aws lambda get-function --function-name "$LAMBDA_FUNCTION_NAME" 2>/dev/null; then
    echo "📝 Updating existing Lambda function..."
    aws lambda update-function-code \
        --function-name "$LAMBDA_FUNCTION_NAME" \
        --zip-file fileb:///tmp/scheduled_monitor.zip

    # Wait for update to complete
    aws lambda wait function-updated --function-name "$LAMBDA_FUNCTION_NAME"

    # Build environment variables based on what's configured
    ENV_VARS="AGENTCORE_RUNTIME_URL=${AGENTCORE_RUNTIME_URL},SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL},SLACK_SIGNING_SECRET=${SLACK_SIGNING_SECRET}"

    # Add M2M credentials if configured
    if [ "$M2M_CONFIGURED" = true ]; then
        ENV_VARS="${ENV_VARS},COGNITO_DOMAIN_URL=${COGNITO_DOMAIN_URL},M2M_CLIENT_ID=${M2M_CLIENT_ID},M2M_CLIENT_SECRET=${M2M_CLIENT_SECRET}"
        if [ -n "$RESOURCE_SERVER_ID" ]; then
            ENV_VARS="${ENV_VARS},RESOURCE_SERVER_ID=${RESOURCE_SERVER_ID}"
        fi
    fi

    # Add username/password credentials if configured
    if [ "$USER_CONFIGURED" = true ]; then
        ENV_VARS="${ENV_VARS},COGNITO_USER_POOL_ID=${COGNITO_USER_POOL_ID},COGNITO_CLIENT_ID=${COGNITO_CLIENT_ID},COGNITO_CLIENT_SECRET=${COGNITO_CLIENT_SECRET},COGNITO_USERNAME=${COGNITO_USERNAME},COGNITO_PASSWORD=${COGNITO_PASSWORD}"
    fi

    # Update environment variables
    aws lambda update-function-configuration \
        --function-name "$LAMBDA_FUNCTION_NAME" \
        --environment "Variables={${ENV_VARS}}" \
        --timeout 900 \
        --memory-size 10240

    echo "✅ Lambda function updated"
else
    echo "🆕 Creating new Lambda function..."

    # Build environment variables based on what's configured
    ENV_VARS="AGENTCORE_RUNTIME_URL=${AGENTCORE_RUNTIME_URL},SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL},SLACK_SIGNING_SECRET=${SLACK_SIGNING_SECRET}"

    # Add M2M credentials if configured
    if [ "$M2M_CONFIGURED" = true ]; then
        ENV_VARS="${ENV_VARS},COGNITO_DOMAIN_URL=${COGNITO_DOMAIN_URL},M2M_CLIENT_ID=${M2M_CLIENT_ID},M2M_CLIENT_SECRET=${M2M_CLIENT_SECRET}"
        if [ -n "$RESOURCE_SERVER_ID" ]; then
            ENV_VARS="${ENV_VARS},RESOURCE_SERVER_ID=${RESOURCE_SERVER_ID}"
        fi
    fi

    # Add username/password credentials if configured
    if [ "$USER_CONFIGURED" = true ]; then
        ENV_VARS="${ENV_VARS},COGNITO_USER_POOL_ID=${COGNITO_USER_POOL_ID},COGNITO_CLIENT_ID=${COGNITO_CLIENT_ID},COGNITO_CLIENT_SECRET=${COGNITO_CLIENT_SECRET},COGNITO_USERNAME=${COGNITO_USERNAME},COGNITO_PASSWORD=${COGNITO_PASSWORD}"
    fi

    aws lambda create-function \
        --function-name "$LAMBDA_FUNCTION_NAME" \
        --runtime python3.11 \
        --role "$LAMBDA_ROLE_ARN" \
        --handler scheduled_monitor.lambda_handler \
        --zip-file fileb:///tmp/scheduled_monitor.zip \
        --timeout 900 \
        --memory-size 10240 \
        --environment "Variables={${ENV_VARS}}"

    echo "✅ Lambda function created"
fi

echo ""

# Step 5: Create EventBridge rule
# this is for when the agent needs to be invoked once every 15 minutes to provide updates on logs,
# errors, and other metrics within the AWS accounts.
echo "⏰ Step 5: Creating EventBridge rule (every 15 minutes)..."

# Create or update EventBridge rule
aws events put-rule \
    --name "$EVENTBRIDGE_RULE_NAME" \
    --schedule-expression "rate(15 minutes)" \
    --state ENABLED \
    --description "Triggers ambient agent monitoring check every 15 minutes"
echo "✅ EventBridge rule created"

# Step 6: Add Lambda permission for EventBridge
echo "🔐 Step 6: Adding EventBridge trigger permission..."

aws lambda add-permission \
    --function-name "$LAMBDA_FUNCTION_NAME" \
    --statement-id "AllowEventBridgeInvoke" \
    --action "lambda:InvokeFunction" \
    --principal events.amazonaws.com \
    --source-arn "arn:aws:events:${AWS_REGION}:${AWS_ACCOUNT_ID}:rule/${EVENTBRIDGE_RULE_NAME}" 2>/dev/null || echo "✅ Permission already exists"

echo "✅ Permission added"
echo ""

# Step 7: Add Lambda as target for EventBridge rule
echo "🎯 Step 7: Adding Lambda as EventBridge target..."
LAMBDA_ARN="arn:aws:lambda:${AWS_REGION}:${AWS_ACCOUNT_ID}:function:${LAMBDA_FUNCTION_NAME}"
aws events put-targets \
    --rule "$EVENTBRIDGE_RULE_NAME" \
    --targets "Id"="1","Arn"="$LAMBDA_ARN"
echo "✅ Lambda added as target"
echo ""

# Step 8: Create API Gateway for Slack slash commands
echo "🌐 Step 8: Creating API Gateway for Slack slash commands..."

API_NAME="ambient-agent-slack-api"

# Check if API already exists
EXISTING_API_ID=$(aws apigateway get-rest-apis --query "items[?name=='${API_NAME}'].id" --output text)

if [ -n "$EXISTING_API_ID" ]; then
    echo "✅ API Gateway already exists: $EXISTING_API_ID"
    API_ID="$EXISTING_API_ID"
else
    echo "🆕 Creating new API Gateway..."
    API_ID=$(aws apigateway create-rest-api \
        --name "$API_NAME" \
        --description "API Gateway for Ambient Agent Slack slash commands" \
        --endpoint-configuration types=REGIONAL \
        --query 'id' --output text)
    echo "✅ API Gateway created: $API_ID"
fi

# Get root resource ID
ROOT_RESOURCE_ID=$(aws apigateway get-resources \
    --rest-api-id "$API_ID" \
    --query 'items[?path==`/`].id' --output text)

# Check if /slack-command resource exists
EXISTING_RESOURCE_ID=$(aws apigateway get-resources \
    --rest-api-id "$API_ID" \
    --query "items[?pathPart=='slack-command'].id" --output text)

if [ -n "$EXISTING_RESOURCE_ID" ]; then
    echo "✅ Resource /slack-command already exists"
    RESOURCE_ID="$EXISTING_RESOURCE_ID"
else
    echo "🆕 Creating /slack-command resource..."
    RESOURCE_ID=$(aws apigateway create-resource \
        --rest-api-id "$API_ID" \
        --parent-id "$ROOT_RESOURCE_ID" \
        --path-part "slack-command" \
        --query 'id' --output text)
    echo "✅ Resource created: $RESOURCE_ID"
fi

# Create or update POST method
echo "📝 Configuring POST method..."
aws apigateway put-method \
    --rest-api-id "$API_ID" \
    --resource-id "$RESOURCE_ID" \
    --http-method POST \
    --authorization-type NONE \
    --no-api-key-required 2>/dev/null || echo "✅ Method already exists"

# Create method response
aws apigateway put-method-response \
    --rest-api-id "$API_ID" \
    --resource-id "$RESOURCE_ID" \
    --http-method POST \
    --status-code 200 2>/dev/null || echo "✅ Method response already exists"

# Configure Lambda integration
echo "🔗 Configuring Lambda integration..."
LAMBDA_ARN="arn:aws:lambda:${AWS_REGION}:${AWS_ACCOUNT_ID}:function:${LAMBDA_FUNCTION_NAME}"

aws apigateway put-integration \
    --rest-api-id "$API_ID" \
    --resource-id "$RESOURCE_ID" \
    --http-method POST \
    --type AWS_PROXY \
    --integration-http-method POST \
    --uri "arn:aws:apigateway:${AWS_REGION}:lambda:path/2015-03-31/functions/${LAMBDA_ARN}/invocations" 2>/dev/null || echo "✅ Integration already configured"

# Create integration response
aws apigateway put-integration-response \
    --rest-api-id "$API_ID" \
    --resource-id "$RESOURCE_ID" \
    --http-method POST \
    --status-code 200 \
    --selection-pattern "" 2>/dev/null || echo "✅ Integration response already exists"

echo "✅ API Gateway configured"
echo ""

# Step 9: Deploy API to production stage
echo "🚀 Step 9: Deploying API to production stage..."

DEPLOYMENT_ID=$(aws apigateway create-deployment \
    --rest-api-id "$API_ID" \
    --stage-name prod \
    --stage-description "Production stage" \
    --description "Deployment for Slack slash commands" \
    --query 'id' --output text)

echo "✅ API deployed to prod stage"
echo ""

# Step 10: Add Lambda permission for API Gateway
echo "🔐 Step 10: Adding API Gateway invoke permission..."

aws lambda add-permission \
    --function-name "$LAMBDA_FUNCTION_NAME" \
    --statement-id "AllowAPIGatewayInvoke" \
    --action "lambda:InvokeFunction" \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:${AWS_REGION}:${AWS_ACCOUNT_ID}:${API_ID}/*/*" 2>/dev/null || echo "✅ Permission already exists"

echo "✅ Permission added"
echo ""

# Generate API Gateway URL
API_URL="https://${API_ID}.execute-api.${AWS_REGION}.amazonaws.com/prod/slack-command"

# Cleanup temporary files
rm -f /tmp/lambda-trust-policy.json /tmp/lambda-custom-policy.json /tmp/scheduled_monitor.zip

echo "=============================================="
echo "✅ Deployment completed successfully!"
echo "=============================================="
echo ""
echo "📋 Deployment Summary:"
echo "   • Lambda Function: $LAMBDA_FUNCTION_NAME"
echo "   • EventBridge Rule: $EVENTBRIDGE_RULE_NAME"
echo "   • Schedule: Every 15 minutes"
echo "   • IAM Role: $LAMBDA_ROLE_NAME"
echo "   • API Gateway: $API_ID"
echo "   • API Endpoint: $API_URL"
echo ""
echo "🔍 To view logs:"
echo "   aws logs tail /aws/lambda/$LAMBDA_FUNCTION_NAME --follow"
echo ""
echo "🧪 To test manually:"
echo "   # Test scheduled monitoring:"
echo "   aws lambda invoke --function-name $LAMBDA_FUNCTION_NAME /tmp/response.json && cat /tmp/response.json"
echo ""
echo "   # Test Slack slash command (simulate):"
echo "   curl -X POST $API_URL \\"
echo "     -H \"Content-Type: application/x-www-form-urlencoded\" \\"
echo "     -d \"text=What is the status of my CloudWatch alarms?&user_name=testuser&channel_name=general&response_url=https://hooks.slack.com/commands/...\""
echo ""
echo "🔧 Slack Slash Command Configuration:"
echo "   1. Go to https://api.slack.com/apps"
echo "   2. Select your app"
echo "   3. Go to 'Slash Commands'"
echo "   4. Create or edit your command (e.g., /ask)"
echo "   5. Set Request URL to: $API_URL"
echo "   6. Save changes"
echo ""
echo "🎉 Your agent will now:"
echo "   • Post scheduled updates to Slack every 15 minutes"
echo "   • Respond to Slack slash commands at $API_URL"
