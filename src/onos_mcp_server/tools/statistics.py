from typing import Optional
from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request

# Port Statistics


async def get_all_ports_statistics() -> str:
    """Gets port statistics of all devices.

    Returns statistics for all ports across all devices.
    """
    try:
        statistics = await make_onos_request("get", "/statistics/ports")
        return str(statistics)
    except Exception as e:
        return f"Error retrieving port statistics: {str(e)}"


async def get_device_port_statistics(deviceId: str) -> str:
    """Gets port statistics of a specified device.

    Args:
        deviceId: Device identifier

    Returns port statistics for all ports on the specified device.
    """
    try:
        statistics = await make_onos_request("get", f"/statistics/ports/{deviceId}")
        return str(statistics)
    except Exception as e:
        return f"Error retrieving port statistics for device {deviceId}: {str(e)}"


async def get_port_statistics(deviceId: str, port: str) -> str:
    """Gets port statistics of a specified device and port.

    Args:
        deviceId: Device identifier
        port: Port number

    Returns statistics for the specified port on the specified device.
    """
    try:
        statistics = await make_onos_request(
            "get", f"/statistics/ports/{deviceId}/{port}"
        )
        return str(statistics)
    except Exception as e:
        return f"Error retrieving statistics for port {port} on device {deviceId}: {str(e)}"


# Delta Port Statistics


async def get_all_ports_delta_statistics() -> str:
    """Gets port delta statistics of all devices.

    Returns delta statistics for all ports across all devices.
    """
    try:
        statistics = await make_onos_request("get", "/statistics/delta/ports")
        return str(statistics)
    except Exception as e:
        return f"Error retrieving delta port statistics: {str(e)}"


async def get_device_delta_port_statistics(deviceId: str) -> str:
    """Gets port delta statistics of a specified device.

    Args:
        deviceId: Device identifier

    Returns delta statistics for all ports on the specified device.
    """
    try:
        statistics = await make_onos_request(
            "get", f"/statistics/delta/ports/{deviceId}"
        )
        return str(statistics)
    except Exception as e:
        return f"Error retrieving delta port statistics for device {deviceId}: {str(e)}"


async def get_port_delta_statistics(deviceId: str, port: str) -> str:
    """Gets port delta statistics of a specified device and port.

    Args:
        deviceId: Device identifier
        port: Port number

    Returns delta statistics for the specified port on the specified device.
    """
    try:
        statistics = await make_onos_request(
            "get", f"/statistics/delta/ports/{deviceId}/{port}"
        )
        return str(statistics)
    except Exception as e:
        return f"Error retrieving delta statistics for port {port} on device {deviceId}: {str(e)}"


# Flow Statistics


async def get_active_flow_entries() -> str:
    """Gets sum of active entries in all tables for all devices.

    Returns count of active flow entries across all devices.
    """
    try:
        statistics = await make_onos_request("get", "/statistics/flows/activeentries")
        return str(statistics)
    except Exception as e:
        return f"Error retrieving active flow entries: {str(e)}"


async def get_link_flow_statistics(
    device: Optional[str] = None, port: Optional[str] = None
) -> str:
    """Gets load statistics for all links or for a specific link.

    Args:
        device: (Optional) Device identifier for a specific link
        port: (Optional) Port number for a specified link

    Returns flow statistics for links, filtered by device and port if specified.
    """
    try:
        params = {}
        if device:
            params["device"] = device
        if port:
            params["port"] = port

        statistics = await make_onos_request(
            "get", "/statistics/flows/link", params=params
        )
        return str(statistics)
    except Exception as e:
        return f"Error retrieving link flow statistics: {str(e)}"


# Table Statistics


async def get_all_tables_statistics() -> str:
    """Gets table statistics for all tables of all devices.

    Returns statistics for all flow tables across all devices.
    """
    try:
        statistics = await make_onos_request("get", "/statistics/flows/tables")
        return str(statistics)
    except Exception as e:
        return f"Error retrieving table statistics: {str(e)}"


async def get_device_tables_statistics(deviceId: str) -> str:
    """Gets table statistics for all tables of a specified device.

    Args:
        deviceId: Device identifier

    Returns statistics for all flow tables on the specified device.
    """
    try:
        statistics = await make_onos_request(
            "get", f"/statistics/flows/tables/{deviceId}"
        )
        return str(statistics)
    except Exception as e:
        return f"Error retrieving table statistics for device {deviceId}: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all statistics tools with the MCP server."""
    # Port statistics
    mcp_server.tool()(get_all_ports_statistics)
    mcp_server.tool()(get_device_port_statistics)
    mcp_server.tool()(get_port_statistics)

    # Delta port statistics
    mcp_server.tool()(get_all_ports_delta_statistics)
    mcp_server.tool()(get_device_delta_port_statistics)
    mcp_server.tool()(get_port_delta_statistics)

    # Flow statistics
    mcp_server.tool()(get_active_flow_entries)
    mcp_server.tool()(get_link_flow_statistics)

    # Table statistics
    mcp_server.tool()(get_all_tables_statistics)
    mcp_server.tool()(get_device_tables_statistics)
