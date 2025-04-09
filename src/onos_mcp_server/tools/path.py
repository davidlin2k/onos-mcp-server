from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_shortest_paths(src: str, dst: str) -> str:
    """Gets all shortest paths between any two hosts or devices.

    Args:
        src: Source identifier (can be a device ID or host ID)
        dst: Destination identifier (can be a device ID or host ID)

    Returns array of all shortest paths between any two elements.
    """
    try:
        paths = await make_onos_request("get", f"/paths/{src}/{dst}")
        return str(paths)
    except Exception as e:
        return f"Error retrieving shortest paths from {src} to {dst}: {str(e)}"


async def get_disjoint_paths(src: str, dst: str) -> str:
    """Gets all shortest disjoint path pairs between any two hosts or devices.

    Args:
        src: Source identifier (can be a device ID or host ID)
        dst: Destination identifier (can be a device ID or host ID)

    Returns array of all shortest disjoint path pairs between any two elements.
    """
    try:
        paths = await make_onos_request("get", f"/paths/{src}/{dst}/disjoint")
        return str(paths)
    except Exception as e:
        return f"Error retrieving disjoint paths from {src} to {dst}: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all path tools with the MCP server."""
    mcp_server.tool()(get_shortest_paths)
    mcp_server.tool()(get_disjoint_paths)
