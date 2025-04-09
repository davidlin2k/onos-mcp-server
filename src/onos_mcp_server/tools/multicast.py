from typing import Any, Dict, List
from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_multicast_routes() -> str:
    """Get all multicast routes.

    Returns array of all known multicast routes.
    """
    try:
        routes = await make_onos_request("get", "/mcast")
        return str(routes)
    except Exception as e:
        return f"Error retrieving multicast routes: {str(e)}"


async def add_multicast_route(
    group: str, source: str, sources: List[str], sinks: List[str]
) -> str:
    """Create a new multicast route.

    Args:
        group: Multicast group address
        source: Source IP address
        sources: List of source connection points
        sinks: List of sink connection points

    Creates a new route in the multicast RIB.
    """
    try:
        route_data = {
            "group": group,
            "source": source,
            "sources": sources,
            "sinks": sinks,
        }

        result = await make_onos_request("post", "/mcast", json=route_data)
        return f"Multicast route added successfully for group {group}"
    except Exception as e:
        return f"Error adding multicast route: {str(e)}"


async def remove_multicast_route(group: str, source: str) -> str:
    """Remove a multicast route.

    Args:
        group: Multicast group address
        source: Source IP address

    Removes a route from the multicast RIB.
    """
    try:
        route_data = {"group": group, "source": source}

        await make_onos_request("delete", "/mcast", json=route_data)
        return f"Multicast route from {source} to group {group} removed successfully"
    except Exception as e:
        return f"Error removing multicast route: {str(e)}"


async def add_multicast_sink(group: str, source: str, sink: str) -> str:
    """Create a sink for a multicast route.

    Args:
        group: Multicast group address
        source: Source IP address
        sink: Sink connection point

    Creates a new sink for an existing multicast route.
    """
    try:
        sink_data = {"sink": sink}

        result = await make_onos_request(
            "post", f"/mcast/sinks/{group}/{source}", json=sink_data
        )
        return (
            f"Sink added successfully to multicast route from {source} to group {group}"
        )
    except Exception as e:
        return f"Error adding sink to multicast route: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all multicast management tools with the MCP server."""
    mcp_server.tool()(get_multicast_routes)
    mcp_server.tool()(add_multicast_route)
    mcp_server.tool()(remove_multicast_route)
    mcp_server.tool()(add_multicast_sink)
