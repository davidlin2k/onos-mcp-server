from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_all_intents(detail: bool = False) -> str:
    """Gets all intents in the system.

    Args:
        detail: Flag to return full details of intents in list

    Returns array containing all the intents in the system.
    """
    try:
        params = {"detail": str(detail).lower()}
        intents = await make_onos_request("get", "/intents", params=params)
        return str(intents)
    except Exception as e:
        return f"Error retrieving intents: {str(e)}"


async def get_intent(appId: str, key: str) -> str:
    """Gets intent by application ID and key.

    Args:
        appId: Application identifier
        key: Intent key

    Returns details of the specified intent.
    """
    try:
        intent = await make_onos_request("get", f"/intents/{appId}/{key}")
        return str(intent)
    except Exception as e:
        return f"Error retrieving intent {key} for app {appId}: {str(e)}"


async def get_intents_by_application(appId: str, detail: bool = False) -> str:
    """Gets intents by application.

    Args:
        appId: Application identifier
        detail: Flag to return full details of intents in list

    Returns the intents specified by the application ID.
    """
    try:
        params = {"detail": str(detail).lower()}
        intents = await make_onos_request(
            "get", f"/intents/application/{appId}", params=params
        )
        return str(intents)
    except Exception as e:
        return f"Error retrieving intents for app {appId}: {str(e)}"


async def get_intent_installables(appId: str, key: str) -> str:
    """Gets intent installables by application ID and key.

    Args:
        appId: Application identifier
        key: Intent key
    """
    try:
        installables = await make_onos_request(
            "get", f"/intents/installables/{appId}/{key}"
        )
        return str(installables)
    except Exception as e:
        return f"Error retrieving installables for intent {key}, app {appId}: {str(e)}"


async def get_intent_related_flows(appId: str, key: str) -> str:
    """Gets all related flow entries created by a particular intent.

    Args:
        appId: Application identifier
        key: Intent key

    Returns all flow entries of the specified intent.
    """
    try:
        flows = await make_onos_request("get", f"/intents/relatedflows/{appId}/{key}")
        return str(flows)
    except Exception as e:
        return f"Error retrieving flows for intent {key}, app {appId}: {str(e)}"


async def get_intents_summary() -> str:
    """Gets summary of all intents.

    Returns a summary of the intents in the system.
    """
    try:
        summary = await make_onos_request("get", "/intents/minisummary")
        return str(summary)
    except Exception as e:
        return f"Error retrieving intents summary: {str(e)}"


async def submit_intent(intent_data: Dict[str, Any]) -> str:
    """Submits a new intent.

    Args:
        intent_data: Intent configuration including type, priority, constraints, etc.

    Creates and submits intent from the supplied JSON data.
    """
    try:
        result = await make_onos_request("post", "/intents", json=intent_data)
        return f"Intent submitted successfully: {result}"
    except Exception as e:
        return f"Error submitting intent: {str(e)}"


async def withdraw_intent(appId: str, key: str) -> str:
    """Withdraws an intent.

    Args:
        appId: Application identifier
        key: Intent key

    Withdraws the specified intent from the system.
    """
    try:
        await make_onos_request("delete", f"/intents/{appId}/{key}")
        return f"Intent {key} for app {appId} withdrawn successfully"
    except Exception as e:
        return f"Error withdrawing intent {key} for app {appId}: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all intent management tools with the MCP server."""
    mcp_server.tool()(get_all_intents)
    mcp_server.tool()(get_intent)
    mcp_server.tool()(get_intents_by_application)
    mcp_server.tool()(get_intent_installables)
    mcp_server.tool()(get_intent_related_flows)
    mcp_server.tool()(get_intents_summary)
    mcp_server.tool()(submit_intent)
    mcp_server.tool()(withdraw_intent)
