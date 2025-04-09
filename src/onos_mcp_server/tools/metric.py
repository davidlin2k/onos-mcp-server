from typing import Any, Dict
from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_all_metrics() -> str:
    """Gets stats information of all metrics.

    Returns array of all information for all metrics.
    """
    try:
        metrics = await make_onos_request("get", "/metrics")
        return str(metrics)
    except Exception as e:
        return f"Error retrieving all metrics: {str(e)}"


async def get_specific_metric(metricName: str) -> str:
    """Gets stats information of a specific metric.

    Args:
        metricName: Name of the metric to query

    Returns array of all information for the specified metric.
    """
    try:
        metric = await make_onos_request("get", f"/metrics/{metricName}")
        return str(metric)
    except Exception as e:
        return f"Error retrieving metric {metricName}: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all metrics tools with the MCP server."""
    mcp_server.tool()(get_all_metrics)
    mcp_server.tool()(get_specific_metric)
