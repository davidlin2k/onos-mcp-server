from typing import Any, Dict, List, Optional
from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_all_meters() -> str:
    """Returns all meters of all devices.

    Gets comprehensive information about all meters across all devices.
    """
    try:
        meters = await make_onos_request("get", "/meters")
        return str(meters)
    except Exception as e:
        return f"Error retrieving all meters: {str(e)}"


async def get_device_meters(deviceId: str) -> str:
    """Returns a collection of meters by the device id.

    Args:
        deviceId: Device identifier

    Gets all meters for the specified device.
    """
    try:
        meters = await make_onos_request("get", f"/meters/{deviceId}")
        return str(meters)
    except Exception as e:
        return f"Error retrieving meters for device {deviceId}: {str(e)}"


async def get_meter(deviceId: str, meterId: str) -> str:
    """Returns a meter by the meter id.

    Args:
        deviceId: Device identifier
        meterId: Meter identifier

    Gets details for a specific meter on the specified device.
    """
    try:
        meter = await make_onos_request("get", f"/meters/{deviceId}/{meterId}")
        return str(meter)
    except Exception as e:
        return f"Error retrieving meter {meterId} for device {deviceId}: {str(e)}"


async def remove_meter(deviceId: str, meterId: str) -> str:
    """Removes the meter by device id and meter id.

    Args:
        deviceId: Device identifier
        meterId: Meter identifier

    Removes the specified meter from the device.
    """
    try:
        await make_onos_request("delete", f"/meters/{deviceId}/{meterId}")
        return f"Meter {meterId} removed successfully from device {deviceId}"
    except Exception as e:
        return f"Error removing meter {meterId} from device {deviceId}: {str(e)}"


async def add_meter(
    deviceId: str, appId: str, unit: str, burst: bool, bands: List[Dict[str, Any]]
) -> str:
    """Creates new meter rule.

    Args:
        deviceId: Device identifier
        appId: Application identifier
        unit: Unit type (KB_PER_SEC, PKTS_PER_SEC)
        burst: Whether to use burst semantics
        bands: List of bands (each with type, rate, burst-size, and optionally prec/drop)

    Creates and installs a new meter rule for the specified device.
    """
    try:
        meter_data = {
            "deviceId": deviceId,
            "appId": appId,
            "unit": unit,
            "burst": burst,
            "bands": bands,
        }

        result = await make_onos_request("post", f"/meters/{deviceId}", json=meter_data)
        return f"Meter added successfully to device {deviceId}: {result}"
    except Exception as e:
        return f"Error adding meter to device {deviceId}: {str(e)}"


async def get_meter_by_cell_id(deviceId: str, scope: str, index: str) -> str:
    """Returns a meter by the meter cell id.

    Args:
        deviceId: Device identifier
        scope: Scope identifier
        index: Index

    Gets details for a specific meter on the device by cell ID.
    """
    try:
        meter = await make_onos_request("get", f"/meters/{deviceId}/{scope}/{index}")
        return str(meter)
    except Exception as e:
        return f"Error retrieving meter with scope {scope} and index {index} for device {deviceId}: {str(e)}"


async def remove_meter_by_cell_id(deviceId: str, scope: str, index: str) -> str:
    """Removes the meter by the device id and meter cell id.

    Args:
        deviceId: Device identifier
        scope: Scope identifier
        index: Index

    Removes the specified meter from the device by cell ID.
    """
    try:
        await make_onos_request("delete", f"/meters/{deviceId}/{scope}/{index}")
        return f"Meter with scope {scope} and index {index} removed successfully from device {deviceId}"
    except Exception as e:
        return f"Error removing meter with scope {scope} and index {index} from device {deviceId}: {str(e)}"


async def get_meters_by_scope(deviceId: str, scope: str) -> str:
    """Returns a collection of meters by the device id and meter scope.

    Args:
        deviceId: Device identifier
        scope: Scope identifier

    Gets all meters for the specified device filtered by scope.
    """
    try:
        meters = await make_onos_request("get", f"/meters/scope/{deviceId}/{scope}")
        return str(meters)
    except Exception as e:
        return f"Error retrieving meters with scope {scope} for device {deviceId}: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all meter management tools with the MCP server."""
    mcp_server.tool()(get_all_meters)
    mcp_server.tool()(get_device_meters)
    mcp_server.tool()(get_meter)
    mcp_server.tool()(remove_meter)
    mcp_server.tool()(add_meter)
    mcp_server.tool()(get_meter_by_cell_id)
    mcp_server.tool()(remove_meter_by_cell_id)
    mcp_server.tool()(get_meters_by_scope)
