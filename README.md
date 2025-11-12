# AgentWatch - An Ambient AWS Resource Monitoring Agent

When using ChatGPT, Claude Code or any other chatbot type of interface, they rely on end users to invoke the chatbot to then accomplish a task. For example, if a user wants to perform deep research on "best ways of evaluating AI agents", they will have to type out their prompt on the user interface, and then engage in a multi-turn conversation with the chatbot until the chatbot (which is an agent under the hood usually), has all the context to kick off the job. Once the agent underlying the chatbot has all the required information, it either synchronously or asynchronously calls tools, refers to memory and engages with other external sources to perform the task (in this case, deep research). This has two disadvantages:

1. **User management**: In this case, the user is responsible to craft a prompt and supply that prompt to an agent. This requires the user to do most of the work and there is usually some prerequisites a user would have to follow to get the agent to start in the first place. For use cases that are more event driven in nature that are dynamic and not under the control of the user, this problem compounds because the AI agent would have to dynamically work with the changing environment but under the guidance and control of the user, which may fall out of rhythm.

2. **Lack of parallel processing**: In today's Agentic world, organizations don't want agents to accomplish one but several tasks in parallel. If a user provides a task upfront, then this makes it hard for us humans to scale ourselves. An agent can be only doing one task for us at a time.

If we think about the UI/UX experience, there should be two characteristics that should help us mitigate the pain points above:

1. **Triggered dynamically, in an event driven way**: It should not be triggered necessarily only by a human and should be more event driven. There should be some tracking mechanism that spins off an agent and the agent can complete or resume a task based on continuously provided memory and context.

2. **Parallel processing**: It should allow for multiple agents running in parallel to accomplish a task, with a human in the loop capability.

The characteristics above are what defines an **ambient agent** (as referred by LangChain [here](https://blog.langchain.com/introducing-ambient-agents/#:~:text=Ambient%20agents%20listen%20to%20an%20event%20stream%20and%20act%20on%20it%20accordingly%2C%20potentially%20acting%20on%20multiple%20events%20at%20a%20time)):

```
Ambient agents listen to an event stream and act on it accordingly, potentially acting on multiple events at a time.
```

Ambient agents are also not the solution to everything. Thinking about bringing them involves a thoughtful consideration of when and how these agents can interact with humans and the control that the humans would have over the workflow of these agents as they execute and notify the end-user.

### AgentWatch

AgentWatch is a sample implementation of an ambient agent that is a hybrid ambient agent. There are some tasks that it performs that are fully autonomous (that are low on risk, for example referring to the AWS accounts and doing monitoring of resource utilization and providing the user with some information) and then there are some user actions that the user can configure and provide to the agent - for example analyzing the causes of alarms in the AWS account and fixing for it.

Several organizations use different platforms for communication. I recently attended an Anthropic event where someone mentioned: "AI is going to catch up to pace faster than we think it is", which means that organizations are going to be structured differently and you are going to be working with autonomous workers (or agents) over Slack that will be able to accomplish tasks faster, more efficiently and have a much tighter loop with the end users. For the purpose of this solution, we use **Slack** as the end user interface where the ambient agent will be posting messages to and from where end users will then interact with the agent on demand as well.

## Human in the Loop in Ambient Agents

Human-in-the-loop (HITL) is a fundamental component for building trustworthy ambient agents. While ambient agents operate autonomously and respond to event streams, they must know when to involve humans in their decision-making process. AgentWatch implements three core HITL patterns that balance autonomy with appropriate human oversight.

### The Three HITL Patterns

**1. Notify Pattern**

The notify pattern alerts users about important events without taking any action. This is useful for flagging events that users should be aware of but where the agent is not empowered to act on them. In AgentWatch, this pattern is implemented through scheduled monitoring reports. Every 15 minutes, the agent generates a comprehensive monitoring report covering CloudWatch alarms, critical issues, and resource health across AWS services. The agent posts these reports to a Slack channel, keeping the team informed without requiring immediate action or approval. This allows users to maintain situational awareness while the agent handles the routine work of aggregating and summarizing monitoring data.

**2. Question Pattern**

The question pattern enables the agent to ask users for clarification when it encounters uncertainty about how to proceed. This prevents the agent from making incorrect assumptions or taking inappropriate actions when faced with ambiguous situations. For example, if AgentWatch detects a critical alarm but is unclear whether to proceed with automated remediation or escalate to an on-call engineer, it can post a question to Slack asking for guidance. Similarly, when attempting to modify AWS resources or perform sensitive operations, the agent can ask for clarification on the specific approach to take, similar to how an SRE would consult with a senior administrator before making significant changes to production systems.

**3. Review Pattern**

The review pattern allows users to approve, reject, or edit actions before the agent executes them. This is particularly important for sensitive operations where human judgment is required. In AgentWatch, this pattern can be applied when the agent wants to perform potentially impactful actions such as modifying AWS resources, adjusting scaling policies, or changing alarm thresholds. The agent presents its proposed action to the user via Slack, along with relevant context and reasoning. The user can then approve the action to proceed, reject it entirely, or edit the parameters before execution. This ensures that critical decisions remain under human control while still benefiting from the agent's ability to identify issues and propose solutions.

These HITL patterns lower implementation risks by ensuring appropriate human oversight, mimic natural human communication patterns found in engineering teams, and enable the agent to learn from user feedback over time to better align with organizational preferences and policies.

## How AgentWatch Works

AgentWatch is built as a LangChain agent with access to seven specialized monitoring tools for AWS infrastructure. The agent uses Amazon Bedrock's Claude model for natural language understanding and can analyze CloudWatch dashboards, fetch logs, examine alarms, and perform cross-account monitoring. The architecture follows a hybrid ambient model with both scheduled monitoring and on-demand interaction capabilities.

The agent is deployed on AgentCore Runtime, which provides a secure, serverless, and purpose-built hosting environment for running AI agents at scale regardless of the agent framework or model provider. Once deployed, the agent is available as an HTTP endpoint that can be invoked programmatically. Authentication is handled through AgentCore Identity using OAuth 2.0 with Cognito as the identity provider, though any OIDC-compliant IdP can be used.

The deployment infrastructure consists of three main components working together. First, an AWS Lambda function serves as the orchestration layer, responsible for authenticating with Cognito to obtain bearer tokens, invoking the AgentCore Runtime endpoint with appropriate prompts, and formatting responses for Slack. Second, Amazon EventBridge provides scheduled invocation capability through a rule configured to trigger every 15 minutes. When triggered, the Lambda function uses a pre-configured monitoring prompt that asks the agent to provide summaries of CloudWatch alarms, critical issues, and resource health. Third, an API Gateway exposes the Lambda function as an HTTP endpoint that integrates with a Slack app through slash commands. When users type a question in Slack using the configured slash command, the request routes to API Gateway, which invokes the Lambda function with the user's question as the prompt.

This dual-trigger architecture enables AgentWatch to operate in two modes. In scheduled mode, the agent runs autonomously every 15 minutes, proactively monitoring AWS infrastructure and posting reports to keep teams informed without manual intervention. In on-demand mode, users can ask specific questions through Slack and receive immediate responses, allowing for interactive troubleshooting and investigation when needed. Both modes leverage the same underlying agent and tools, providing consistent monitoring capabilities whether operating autonomously or responding to user queries.

## AgentWatch in Action

The following screenshots demonstrate both operational modes of AgentWatch.

### Scheduled Monitoring Reports

![Scheduled Monitoring](img/scheduled_based.png)

Every 15 minutes, AgentWatch automatically generates and posts comprehensive monitoring reports to Slack, providing the team with continuous visibility into AWS infrastructure health.

### On-Demand Interaction

![User Question](img/on_demand_question_example_1.png)

Users can ask specific questions through Slack slash commands to investigate issues or get real-time information.

![Agent Response](img/on_demand_answer_example_2.png)

The agent processes the question and provides detailed, context-aware responses based on current AWS infrastructure state.

## Getting Started

This section walks you through deploying AgentWatch from initial setup to production deployment.

### Prerequisites

Before deploying AgentWatch, ensure you have the following:

- **AWS Account** with appropriate permissions to create Lambda functions, IAM roles, EventBridge rules, and API Gateway resources
- **AWS CLI** installed and configured with credentials
- **Python 3.11+** for local development and testing
- **Cognito User Pool** configured with OAuth 2.0 client credentials (M2M authentication recommended) or username/password authentication
- **Slack Workspace** with permissions to create and configure apps

### Step 1: Create and Configure Slack App

AgentWatch integrates with Slack to deliver monitoring reports and respond to user questions. You need to create a Slack app and configure it with the necessary permissions.

1. Go to https://api.slack.com/apps and click **Create New App**
2. Choose **From scratch** and provide an app name (e.g., "AgentWatch") and select your workspace
3. Navigate to **Incoming Webhooks** in the left sidebar
4. Toggle **Activate Incoming Webhooks** to On
5. Click **Add New Webhook to Workspace** and select the channel where monitoring reports should be posted
6. Copy the webhook URL (format: `https://hooks.slack.com/services/T.../B.../xxx`)
7. Navigate to **Slash Commands** in the left sidebar
8. Click **Create New Command** and configure:
   - Command: `/ask` (or your preferred command name)
   - Request URL: Leave this blank for now - you'll update it after deployment
   - Short Description: "Ask the AgentWatch monitoring agent a question"
   - Usage Hint: "What is the status of my CloudWatch alarms?"
9. Navigate to **Basic Information** in the left sidebar
10. Under **App Credentials**, copy the **Signing Secret** - you'll need this for request verification

![Create Slack App](img/slack_app_create_new_app.png)

### Step 2: Configure Identity Provider for Authentication

AgentWatch uses AgentCore Identity with OAuth 2.0 for secure authentication. You need to configure a Cognito User Pool with appropriate app clients.

For detailed instructions on setting up Cognito for AgentCore Identity, refer to the AgentCore documentation. You will need to configure either:

- **M2M Authentication (Recommended)**: OAuth 2.0 Client Credentials flow for service-to-service authentication
- **Username/Password Authentication (Fallback)**: USER_PASSWORD_AUTH flow with user credentials

Save the following values from your Cognito configuration:
- Cognito Domain URL
- M2M Client ID and Client Secret (for M2M auth)
- Resource Server ID (if using custom scopes)
- User Pool ID, Client ID, and user credentials (for username/password auth)

In this example, we use the following:

```
python idp_setup/setup_cognito.py
```

The results will be stored in a `cognito_config.json` file. 

### Step 3: Test Agent Locally

Before deploying to AgentCore Runtime, test the agent locally to ensure it works correctly with your AWS environment.

1. Clone this repository and navigate to the project directory
2. Install dependencies using `uv`:
   ```bash
   uv sync
   ```
3. Configure your AWS credentials and ensure you have access to CloudWatch, Lambda, and other services the agent will monitor
4. Run the agent locally:
   ```bash
   uv run python ambient_agent.py
   ```
5. Test the agent by sending sample prompts and verifying it can access your AWS resources

### Step 4: Deploy Agent to AgentCore Runtime

Deploy the agent to AgentCore Runtime to make it available as a secure HTTP endpoint.

1. Ensure you have the AgentCore CLI installed and configured

2. Update the `config.yaml` file with your model preferences and tool configurations

3. configure the agent:
   ```bash
   # Follow AgentCore deployment documentation
   agentcore configure -e ambient_agent.py
   ```
   When you run the command above, provide the values for the arn, code/container deployment, name of the agent, enter the credentials information from Step 2 above (use the `cognito_config.json` file for this) and view the `bedrock_agentcore.yaml` file created.

4. Launch the agent on AgentCore Runtime:

```
agentcore launch
```

5. After deployment, save the AgentCore Runtime URL - you'll need this for the Lambda configuration

### Step 5: Configure Environment Variables

Create a `.env` file with all the configuration values you've collected:

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Edit the `.env` file with your actual values:
   ```bash
   # AWS Configuration
   AWS_REGION=us-west-2

   # AgentCore Runtime URL (from Step 4)
   AGENTCORE_RUNTIME_URL=https://bedrock-agentcore...

   # Cognito Configuration - M2M (Recommended)
   COGNITO_DOMAIN_URL=https://your-domain.auth.us-west-2.amazoncognito.com
   M2M_CLIENT_ID=your_m2m_client_id
   M2M_CLIENT_SECRET=your_m2m_client_secret
   RESOURCE_SERVER_ID=your_resource_server_id

   # Slack Configuration (from Step 1)
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx
   SLACK_SIGNING_SECRET=your_slack_signing_secret
   ```

All values specified in `.env.example` should be configured. The deployment script will validate that required variables are present.

### Step 6: Deploy Lambda Function and Infrastructure

Run the deployment script to create the Lambda function, EventBridge rule, and API Gateway:

```bash
cd deployment
chmod +x deploy.sh
./deploy.sh
```

The script will:
1. Create an IAM role for Lambda with necessary permissions
2. Package and deploy the Lambda function code
3. Configure environment variables from your `.env` file
4. Create an EventBridge rule to trigger the agent every 15 minutes
5. Create an API Gateway endpoint for Slack slash commands
6. Set up all necessary permissions and integrations

At the end of deployment, the script will output an API Gateway URL. Copy this URL - you'll need it for the next step.

### Step 7: Update Slack App with API Gateway URL

Now that you have the API Gateway endpoint, update your Slack app configuration:

1. Go back to https://api.slack.com/apps and select your app
2. Navigate to **Slash Commands**
3. Click on the `/ask` command (or whatever you named it)
4. Update the **Request URL** with the API Gateway URL from Step 6
5. Click **Save**

### Step 8: Test the Deployment

**Test On-Demand Questions:**
Go to your Slack workspace and try the slash command:

```
/ask What is the status of my CloudWatch alarms?
```

The agent should respond with current information from your AWS environment.

## Conclusion

AgentWatch demonstrates how ambient agents can provide continuous, proactive monitoring of infrastructure while maintaining appropriate human oversight through well-designed HITL patterns. By combining scheduled autonomous operation with on-demand interaction capabilities, the system achieves a balance between automation and control that aligns with operational best practices.

The architecture leverages AWS managed services and AgentCore Runtime to provide a scalable, secure foundation for ambient agent deployment. The notify, question, and review patterns ensure that humans remain informed and in control while reducing the operational burden of routine monitoring tasks. This approach can be extended to other domains beyond AWS monitoring, applying the same principles to any scenario where continuous observation and selective human involvement are required.

Organizations implementing ambient agents should carefully consider which tasks are appropriate for full autonomy versus those requiring human approval, design clear communication channels between agents and humans, and establish feedback mechanisms that allow agents to learn from human decisions over time. AgentWatch serves as a practical reference implementation for these concepts.