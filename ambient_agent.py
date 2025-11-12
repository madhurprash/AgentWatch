import os
import json
import yaml
import boto3
import logging
from utils import *
from tools import *
from constants import *
from langsmith import traceable
from botocore.config import Config
from typing import Dict, List, Any
from langchain_aws import ChatBedrock
from langchain.agents import create_agent
from langgraph.checkpoint.memory import MemorySaver
from bedrock_agentcore.runtime import BedrockAgentCoreApp

# Initialize the bedrock agentcore app that will be used to launch the agent on bedrock agentcore runtime
app = BedrockAgentCoreApp()

# set a logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

logger.info(f"Going to load the configuration file with values about the ambient agent...")
config_data: Dict = load_config(CONFIG_FILE_FNAME)
logger.info(f"Loaded the configuration file: {json.dumps(config_data, indent=4)}")

logger.info(f"Going to initialize the agent model and the tools that the agent will be using...")

agent_model_configuration: Dict = config_data['model_information']
agent_system_prompt_fpath: str = agent_model_configuration['system_prompt_fpath']
agent_system_prompt: str = load_system_prompt(agent_system_prompt_fpath)
logger.info(f"Loaded the agent system prompt: {agent_system_prompt}")

# initialize the bedrock config
bedrock_config = Config(
    read_timeout=12000,
    connect_timeout=60,
    retries={
        'max_attempts': 3,
        'mode': 'adaptive'
    }
)

# Create a boto3 client with custom timeout configuration
bedrock_runtime_client = boto3.client(
    service_name='bedrock-runtime',
    region_name=boto3.session.Session().region_name,
    config=bedrock_config
)

# Initialize the model
agent_model = ChatBedrock(
    client=bedrock_runtime_client,
    model=agent_model_configuration["model_id"],
    model_kwargs={
        "temperature": agent_model_configuration["inference_parameters"]["temperature"],
        "max_tokens": agent_model_configuration["inference_parameters"]["max_tokens"],
        "top_p": agent_model_configuration["inference_parameters"]["top_p"],
    }
)
logger.info(f"Initialized Amazon Bedrock model: {agent_model_configuration['model_id']}")

monitoring_tools: List = [
    list_cloudwatch_dashboards,
    get_dashboard_summary,
    list_log_groups,
    fetch_cloudwatch_logs_for_service,
    analyze_log_group,
    get_cloudwatch_alarms_for_service,
    setup_cross_account_access,
]

# Create checkpointer for conversation memory
checkpointer = MemorySaver()

# Create the agent with checkpointer
monitoring_agent = create_agent(
    model=agent_model,
    tools=monitoring_tools, 
    system_prompt=agent_system_prompt,
    checkpointer=checkpointer
)

logger.info("Ambient monitoring agent created successfully with checkpointing enabled")

@traceable
@app.entrypoint
def agent_handler(payload: Dict[str, Any]) -> str:
    """
    Handle incoming payload and return agent response.

    Args:
        payload: Dictionary containing the user prompt
                 Expected format: {"prompt": "user question or instruction"}

    Returns:
        String response from the monitoring agent
    """
    try:
        # Extract the prompt from the payload
        user_prompt = payload.get("prompt")
        if not user_prompt:
            error_msg = "No 'prompt' field found in payload"
            logger.error(error_msg)
            return json.dumps({"error": error_msg})

        logger.info(f"Received prompt: {user_prompt}")

        # Thread configuration for maintaining conversation state
        # You can make this dynamic based on session_id in payload if needed
        thread_id = payload.get("session_id", "default-session")
        thread_config = {"configurable": {"thread_id": thread_id}}

        # Invoke agent with the prompt
        result = monitoring_agent.invoke(
            {"messages": [{"role": "user", "content": user_prompt}]},
            thread_config
        )

        # Extract the final AI message content
        messages = result.get('messages', [])
        final_message = messages[-1] if messages else None

        if final_message and hasattr(final_message, 'content'):
            response_text = final_message.content
            logger.info("Agent response generated successfully")
            return response_text
        else:
            error_msg = "No valid response from agent"
            logger.error(error_msg)
            return json.dumps({"error": error_msg, "raw_result": str(result)})

    except Exception as e:
        error_msg = f"Error processing request: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return json.dumps({"error": error_msg})



if __name__ == "__main__":
    app.run()