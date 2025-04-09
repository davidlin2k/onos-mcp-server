from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_packet_processors() -> str:
    """Gets packet processors.

    Returns array of all packet processors.
    """
    try:
        processors = await make_onos_request("get", "/packet/processors")
        return str(processors)
    except Exception as e:
        return f"Error retrieving packet processors: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all packet processing tools with the MCP server."""
    mcp_server.tool()(get_packet_processors)
