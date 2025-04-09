from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_links() -> str:
    """Get infrastructure links.

    Returns array of all links.
    """
    try:
        links = await make_onos_request("get", "/links")
        return str(links)
    except Exception as e:
        return f"Error retrieving links: {str(e)}"


async def get_stale_link_status() -> str:
    """Get useStaleLinkAge active status.

    Returns current status of the VanishedStaleLink.
    """
    try:
        status = await make_onos_request("get", "/links/usestalelinkage")
        return str(status)
    except Exception as e:
        return f"Error retrieving stale link status: {str(e)}"


async def set_stale_link_status(use_stale_link_age: bool) -> str:
    """Set useStaleLinkAge status.

    Args:
        use_stale_link_age: Boolean indicating whether to use stale link age

    Sets the status of whether to use the stale link age feature.
    """
    try:
        status_data = {"useStaleLink": use_stale_link_age}

        result = await make_onos_request(
            "post", "/links/usestalelinkage", json=status_data
        )
        return f"Stale link status set successfully: {result}"
    except Exception as e:
        return f"Error setting stale link status: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all link management tools with the MCP server."""
    mcp_server.tool()(get_links)
    mcp_server.tool()(get_stale_link_status)
    mcp_server.tool()(set_stale_link_status)
