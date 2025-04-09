from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_topology() -> str:
    """Gets overview of current topology.

    Returns a summary of the current network topology.
    """
    try:
        topology = await make_onos_request("get", "/topology")
        return str(topology)
    except Exception as e:
        return f"Error retrieving topology: {str(e)}"


async def get_topology_clusters() -> str:
    """Gets overview of topology SCCs.

    Returns information about Strongly Connected Components (SCCs) in the topology.
    """
    try:
        clusters = await make_onos_request("get", "/topology/clusters")
        return str(clusters)
    except Exception as e:
        return f"Error retrieving topology clusters: {str(e)}"


async def get_topology_cluster(cluster_id: int) -> str:
    """Gets details of a specific SCC.

    Args:
        cluster_id: ID of the cluster to query

    Returns details of the specified Strongly Connected Component.
    """
    try:
        cluster = await make_onos_request("get", f"/topology/clusters/{cluster_id}")
        return str(cluster)
    except Exception as e:
        return f"Error retrieving cluster {cluster_id}: {str(e)}"


async def get_cluster_devices(cluster_id: int) -> str:
    """Gets devices in a specific SCC.

    Args:
        cluster_id: ID of the cluster to query

    Returns devices in the specified Strongly Connected Component.
    """
    try:
        devices = await make_onos_request(
            "get", f"/topology/clusters/{cluster_id}/devices"
        )
        return str(devices)
    except Exception as e:
        return f"Error retrieving devices for cluster {cluster_id}: {str(e)}"


async def get_cluster_links(cluster_id: int) -> str:
    """Gets links in specific SCC.

    Args:
        cluster_id: ID of the cluster to query

    Returns links in the specified Strongly Connected Component.
    """
    try:
        links = await make_onos_request("get", f"/topology/clusters/{cluster_id}/links")
        return str(links)
    except Exception as e:
        return f"Error retrieving links for cluster {cluster_id}: {str(e)}"


async def is_infrastructure(connect_point: str) -> str:
    """Tests if a connect point is infrastructure or edge.

    Args:
        connect_point: Device and port in format deviceid:portnumber

    Returns whether the specified connect point is infrastructure or edge.
    """
    try:
        result = await make_onos_request(
            "get", f"/topology/infrastructure/{connect_point}"
        )
        return str(result)
    except Exception as e:
        return f"Error checking if {connect_point} is infrastructure: {str(e)}"


async def is_broadcast(connect_point: str) -> str:
    """Tests if a connect point is in broadcast set.

    Args:
        connect_point: Device and port in format deviceid:portnumber

    Returns whether the specified connect point is in the broadcast set.
    """
    try:
        result = await make_onos_request("get", f"/topology/broadcast/{connect_point}")
        return str(result)
    except Exception as e:
        return f"Error checking if {connect_point} is in broadcast set: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all topology tools with the MCP server."""
    mcp_server.tool()(get_topology)
    mcp_server.tool()(get_topology_clusters)
    mcp_server.tool()(get_topology_cluster)
    mcp_server.tool()(get_cluster_devices)
    mcp_server.tool()(get_cluster_links)
    mcp_server.tool()(is_infrastructure)
    mcp_server.tool()(is_broadcast)
