"""
Lambda function for monitoring checks.
Handles both:
1. Scheduled monitoring via EventBridge
2. On-demand user questions via Slack slash commands

Invokes AgentCore runtime via HTTP and posts results to Slack.
"""
import os
import hmac
import json
import hashlib
import urllib3
from datetime import datetime
from urllib.parse import parse_qs


http = urllib3.PoolManager()


def verify_slack_request(
    event: dict,
    signing_secret: str
) -> None:
    """
    Verify that the request came from Slack using signature validation.

    Args:
        event: Lambda event containing headers and body
        signing_secret: Slack signing secret

    Raises:
        Exception: If signature verification fails
    """
    # Get required headers - try both lowercase and capitalized versions
    # API Gateway may normalize headers differently
    headers = event['headers']
    timestamp = (
        headers.get('x-slack-request-timestamp') or
        headers.get('X-Slack-Request-Timestamp', '')
    )
    signature = (
        headers.get('x-slack-signature') or
        headers.get('X-Slack-Signature', '')
    )

    if not timestamp or not signature:
        raise Exception("Missing Slack signature headers")

    # Compute signature
    sig_basestring = f"v0:{timestamp}:{event['body']}"
    computed_signature = 'v0=' + hmac.new(
        signing_secret.encode('utf-8'),
        sig_basestring.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    # Compare signatures
    if not hmac.compare_digest(computed_signature, signature):
        raise Exception("Invalid Slack signature")


def lambda_handler(event, context):
    """
    Lambda handler for monitoring checks.

    Supports two trigger types:
    1. EventBridge (scheduled): Uses default monitoring prompt
    2. Slack slash command: Accepts user questions via API Gateway
    """
    print(f"Monitoring check started at {datetime.now()}")
    print(f"Event received: {json.dumps(event)}")

    # Get configuration from environment variables
    agentcore_url: str = os.environ.get('AGENTCORE_RUNTIME_URL')
    slack_webhook_url: str = os.environ.get('SLACK_WEBHOOK_URL')
    slack_signing_secret: str = os.environ.get('SLACK_SIGNING_SECRET')

    # Client credentials (M2M) authentication - preferred method
    cognito_domain_url = os.environ.get('COGNITO_DOMAIN_URL')
    m2m_client_id = os.environ.get('M2M_CLIENT_ID')
    m2m_client_secret = os.environ.get('M2M_CLIENT_SECRET')
    resource_server_id = os.environ.get('RESOURCE_SERVER_ID')

    if not agentcore_url:
        print("ERROR: AGENTCORE_RUNTIME_URL not set")
        return {'statusCode': 500, 'body': 'Missing AgentCore URL'}

    # Determine trigger source and extract parameters
    is_slack_request = 'body' in event and 'headers' in event

    if is_slack_request:
        print("Processing Slack slash command request")

        # Verify Slack request signature for security
        if slack_signing_secret:
            try:
                verify_slack_request(event, slack_signing_secret)
            except Exception as e:
                print(f"Slack verification failed: {str(e)}")
                return {
                    'statusCode': 401,
                    'body': json.dumps({'error': 'Unauthorized'})
                }

        # Parse Slack payload
        body = parse_qs(event['body'])
        user_question = body.get('text', [''])[0].strip()
        response_url = body.get('response_url', [''])[0]
        user_name = body.get('user_name', ['unknown'])[0]
        channel_name = body.get('channel_name', ['unknown'])[0]

        if not user_question:
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'response_type': 'ephemeral',
                    'text': 'Please provide a question. Usage: `/ask <your question>`'
                })
            }
        print(f"User '{user_name}' from #{channel_name} asked: {user_question}")
        # Immediately acknowledge Slack (must respond within 3 seconds)
        initial_response = {
            'statusCode': 200,
            'body': json.dumps({
                'response_type': 'in_channel',
                'text': f'🤔 Processing your question: "{user_question}"...'
            })
        }
        # Set parameters for user question
        prompt = user_question
        session_id = f"user-{user_name}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        target_url = response_url
        is_scheduled = False

    else:
        print("Processing scheduled EventBridge monitoring check")
        if not slack_webhook_url:
            print("ERROR: SLACK_WEBHOOK_URL not set")
            return {'statusCode': 500, 'body': 'Missing Slack webhook URL'}

        # Set parameters for scheduled monitoring
        prompt = "Provide a summary of CloudWatch alarms, any critical issues, and resource health across AWS services. Focus on actionable insights. List all log groups, and give details about all services."
        session_id = f"scheduled-{datetime.now().strftime('%Y%m%d-%H%M')}"
        target_url = slack_webhook_url
        is_scheduled = True
        initial_response = None

    try:
        # For Slack requests, return immediate acknowledgment
        if is_slack_request and initial_response:
            # Process the request asynchronously after acknowledging
            # Note: Lambda will continue processing after return
            pass

        # Step 1: Get Cognito token
        print("Retrieving Cognito token...")

        # Try client credentials first (preferred M2M method)
        if m2m_client_id and m2m_client_secret and cognito_domain_url:
            print("Using client credentials authentication (M2M)")
            bearer_token = get_token_using_client_credentials(
                domain_url=cognito_domain_url,
                client_id=m2m_client_id,
                client_secret=m2m_client_secret,
                resource_server_id=resource_server_id
            )
        else:
            raise Exception("No valid authentication credentials provided. Need either M2M credentials or username/password")

        # Step 2: Invoke AgentCore runtime via HTTP
        print(f"Invoking AgentCore runtime with prompt: {prompt[:100]}...")

        agent_payload = {
            "prompt": prompt,
            "session_id": session_id
        }

        response = http.request(
            'POST',
            agentcore_url,
            body=json.dumps(agent_payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {bearer_token}'
            }
        )

        if response.status != 200:
            raise Exception(f"AgentCore request failed: {response.status} - {response.data.decode('utf-8')}")

        agent_response = response.data.decode('utf-8')
        print(f"Agent response received: {len(agent_response)} characters")

        # Step 3: Format response for Slack
        if is_scheduled:
            slack_message = format_slack_message(agent_response, is_scheduled=True)
        else:
            slack_message = format_slack_message(
                agent_response,
                is_scheduled=False,
                user_name=user_name,
                user_question=user_question
            )
        # Step 4: Post to Slack
        print(f"Posting to Slack at {target_url}...")
        slack_response = http.request(
            'POST',
            target_url,
            body=json.dumps(slack_message).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )

        if slack_response.status == 200:
            print("Successfully posted to Slack")
            if is_slack_request:
                # For Slack slash commands, we already returned acknowledgment
                # This is the delayed response sent to response_url
                return {
                    'statusCode': 200,
                    'body': json.dumps({'message': 'User question processed'})
                }
            else:
                return {
                    'statusCode': 200,
                    'body': json.dumps({'message': 'Monitoring check completed'})
                }
        else:
            print(f"Slack post failed: {slack_response.status}")
            return {
                'statusCode': 500,
                'body': json.dumps({'error': f'Slack error: {slack_response.status}'})
            }

    except Exception as e:
        print(f"Error in monitoring check: {str(e)}")

        # Try to send error notification to Slack
        try:
            error_message = {
                "text": f"🚨 *Monitoring Agent Error*\n```{str(e)}```",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🚨 Monitoring Agent Error"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n*Error:*\n```{str(e)}```"
                        }
                    }
                ]
            }

            # Send error to appropriate target
            error_target = target_url if 'target_url' in locals() else slack_webhook_url
            if error_target:
                http.request(
                    'POST',
                    error_target,
                    body=json.dumps(error_message).encode('utf-8'),
                    headers={'Content-Type': 'application/json'}
                )
        except Exception as slack_error:
            print(f"Failed to send error to Slack: {str(slack_error)}")

        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def get_token_using_client_credentials(
    domain_url: str,
    client_id: str,
    client_secret: str,
    resource_server_id: str = None
) -> str:
    """
    Retrieve bearer token using OAuth2 Client Credentials flow.

    Args:
        domain_url: Cognito domain URL
        client_id: M2M client ID
        client_secret: M2M client secret
        resource_server_id: Optional resource server ID for scopes

    Returns:
        Access token string

    Raises:
        Exception: If token request fails
    """
    token_url = f"{domain_url}/oauth2/token"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # Build form data
    data_parts = [
        "grant_type=client_credentials",
        f"client_id={client_id}",
        f"client_secret={client_secret}"
    ]

    # Add scope if resource server is specified
    if resource_server_id:
        scope = f"{resource_server_id}/gateway:read"
        data_parts.append(f"scope={scope}")

    data = "&".join(data_parts)

    print(f"Requesting token from {token_url}")

    response = http.request(
        'POST',
        token_url,
        body=data.encode('utf-8'),
        headers=headers
    )

    if response.status != 200:
        error_msg = f"Failed to retrieve token: {response.status} - {response.data.decode('utf-8')}"
        print(f"ERROR: {error_msg}")
        raise Exception(error_msg)

    token_data = json.loads(response.data.decode('utf-8'))
    print("Successfully retrieved bearer token")
    print(f"Token expires in {token_data.get('expires_in')} seconds")

    return token_data["access_token"]


def format_slack_message(
    agent_response: str,
    is_scheduled: bool = True,
    user_name: str = None,
    user_question: str = None
) -> dict:
    """
    Format agent response into Slack message with blocks.

    Args:
        agent_response: Raw response from agent
        is_scheduled: Whether this is a scheduled monitoring check
        user_name: Username for user-initiated questions
        user_question: The user's question (for user-initiated flow)

    Returns:
        Slack message payload
    """
    timestamp = datetime.now().strftime("%b %d, %Y at %I:%M %p UTC")

    # Clean up the agent response - handle escaped characters and formatting
    # If the response is a JSON string with escaped newlines, decode it
    try:
        # Try to parse as JSON in case it's a quoted string
        cleaned_response = json.loads(f'"{agent_response}"') if agent_response.startswith('\\n') else agent_response
    except (json.JSONDecodeError, ValueError):
        cleaned_response = agent_response

    # Replace markdown bold syntax to work better with Slack
    cleaned_response = cleaned_response.replace('**', '*')

    # Ensure newlines are actual newlines, not escaped
    cleaned_response = cleaned_response.replace('\\n', '\n')

    # Limit length to avoid Slack block limits (3000 chars per block)
    if len(cleaned_response) > 2900:
        cleaned_response = cleaned_response[:2900] + "\n\n_[Response truncated]_"

    # Create different messages based on flow type
    if is_scheduled:
        # Scheduled monitoring flow
        message = {
            "text": f"AWS Monitoring Report - {timestamp}",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "📊 AWS Monitoring Report",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{timestamp}*"
                    }
                },
                {
                    "type": "divider"
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": cleaned_response
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "_Next check in 15 minutes_"
                        }
                    ]
                }
            ]
        }
    else:
        # User-initiated question flow
        message = {
            "text": f"Answer to {user_name}'s question",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "💬 Question Answer",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Question from @{user_name}:*\n>{user_question}"
                    }
                },
                {
                    "type": "divider"
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": cleaned_response
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"_Answered at {timestamp}_"
                        }
                    ]
                }
            ]
        }

    return message
