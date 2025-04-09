from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_system_info() -> str:
    """Get high-level system information.

    Returns version, basic summaries, memory usage, and other system details.
    """
    try:
        info = await make_onos_request("get", "/system")
        return str(info)
    except Exception as e:
        return f"Error retrieving system information: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all system tools with the MCP server."""
    mcp_server.tool()(get_system_info)
