from typing import Any, Dict
from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_mastership_balance() -> str:
    """Balance mastership across all online instances.

    Balances the mastership to be shared as evenly as possible by all online instances.
    """
    try:
        result = await make_onos_request("get", "/mastership")
        return str(result)
    except Exception as e:
        return f"Error balancing mastership: {str(e)}"


async def apply_mastership_role(device_id: str, node_id: str, role: str) -> str:
    """Apply a specific mastership role for a device.

    Args:
        device_id: Device identifier
        node_id: Controller node identifier
        role: Role to apply (MASTER, STANDBY, NONE)

    Applies the specified mastership role for the device.
    """
    try:
        role_data = {"deviceId": device_id, "nodeId": node_id, "role": role}

        result = await make_onos_request("put", "/mastership", json=role_data)
        return f"Mastership role applied successfully: {result}"
    except Exception as e:
        return f"Error applying mastership role: {str(e)}"


async def get_device_controllers(deviceId: str) -> str:
    """Get controllers connected to a device, in order of preference.

    Args:
        deviceId: Device identifier

    The first entry in the list is the current master.
    """
    try:
        controllers = await make_onos_request("get", f"/mastership/{deviceId}/role")
        return str(controllers)
    except Exception as e:
        return f"Error retrieving controllers for device {deviceId}: {str(e)}"


async def request_device_mastership(deviceId: str) -> str:
    """Request mastership of a device for the local controller.

    Args:
        deviceId: Device identifier

    Returns the mastership status and forces master selection if necessary.
    """
    try:
        status = await make_onos_request("get", f"/mastership/{deviceId}/request")
        return str(status)
    except Exception as e:
        return f"Error requesting mastership for device {deviceId}: {str(e)}"


async def get_device_master(deviceId: str) -> str:
    """Get the current master controller for a device.

    Args:
        deviceId: Device identifier

    Returns the current master for the specified device.
    """
    try:
        master = await make_onos_request("get", f"/mastership/{deviceId}/master")
        return str(master)
    except Exception as e:
        return f"Error retrieving master for device {deviceId}: {str(e)}"


async def get_controller_devices(nodeId: str) -> str:
    """Get devices for which a controller is the master.

    Args:
        nodeId: Controller identifier

    Returns the devices for which the controller is master.
    """
    try:
        devices = await make_onos_request("get", f"/mastership/{nodeId}/device")
        return str(devices)
    except Exception as e:
        return f"Error retrieving devices for controller {nodeId}: {str(e)}"


async def relinquish_device_mastership(deviceId: str) -> str:
    """Abandon mastership of a device on the local node.

    Args:
        deviceId: Device identifier

    Forces selection of a new master. If the local node is not a master
    for this device, no master selection will occur.
    """
    try:
        result = await make_onos_request("get", f"/mastership/{deviceId}/relinquish")
        return f"Mastership of device {deviceId} relinquished: {result}"
    except Exception as e:
        return f"Error relinquishing mastership for device {deviceId}: {str(e)}"


async def get_local_device_role(deviceId: str) -> str:
    """Get the role of the local node for a device.

    Args:
        deviceId: Device identifier

    Returns the role of the local node for the specified device.
    """
    try:
        role = await make_onos_request("get", f"/mastership/{deviceId}/local")
        return str(role)
    except Exception as e:
        return f"Error retrieving local role for device {deviceId}: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all mastership management tools with the MCP server."""
    mcp_server.tool()(get_mastership_balance)
    mcp_server.tool()(apply_mastership_role)
    mcp_server.tool()(get_device_controllers)
    mcp_server.tool()(request_device_mastership)
    mcp_server.tool()(get_device_master)
    mcp_server.tool()(get_controller_devices)
    mcp_server.tool()(relinquish_device_mastership)
    mcp_server.tool()(get_local_device_role)
