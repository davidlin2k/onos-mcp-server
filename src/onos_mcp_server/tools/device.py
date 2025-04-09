from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_devices() -> str:
    """Get information about all network devices.

    Returns array of all discovered infrastructure devices.
    """
    try:
        devices = await make_onos_request("get", "/devices")
        return str(devices)
    except Exception as e:
        return f"Error retrieving devices: {str(e)}"


async def get_device(deviceId: str) -> str:
    """Get detailed information about a specific device.

    Args:
        deviceId: ID of the device to query

    Returns details of the specified infrastructure device.
    """
    try:
        device = await make_onos_request("get", f"/devices/{deviceId}")
        return str(device)
    except Exception as e:
        return f"Error retrieving device {deviceId}: {str(e)}"


async def remove_device(deviceId: str) -> str:
    """Administratively remove a device from the inventory.

    Args:
        deviceId: ID of the device to remove

    Administratively deletes the specified device from the inventory of known devices.
    """
    try:
        await make_onos_request("delete", f"/devices/{deviceId}")
        return f"Device {deviceId} removed successfully from the inventory"
    except Exception as e:
        return f"Error removing device {deviceId}: {str(e)}"


async def get_all_device_ports() -> str:
    """Get information about ports on all infrastructure devices.

    Returns port details of all infrastructure devices.
    """
    try:
        ports = await make_onos_request("get", "/devices/ports")
        return str(ports)
    except Exception as e:
        return f"Error retrieving all device ports: {str(e)}"


async def get_device_ports(deviceId: str) -> str:
    """Get information about all ports on a specific device.

    Args:
        deviceId: ID of the device to query ports for

    Returns details of ports for the specified infrastructure device.
    """
    try:
        ports = await make_onos_request("get", f"/devices/{deviceId}/ports")
        return str(ports)
    except Exception as e:
        return f"Error retrieving ports for device {deviceId}: {str(e)}"


async def change_device_port_state(device_id: str, port_id: str, enabled: bool) -> str:
    """Change the administrative state of a device port.

    Args:
        device_id: Device identifier
        port_id: Port number
        enabled: True to enable the port, False to disable it

    Changes the administrative state of the specified port on the device.
    """
    try:
        port_data = {"enabled": enabled}

        await make_onos_request(
            "post", f"/devices/{device_id}/portstate/{port_id}", json=port_data
        )
        state = "enabled" if enabled else "disabled"
        return f"Port {port_id} on device {device_id} {state} successfully"
    except Exception as e:
        return f"Error changing port state: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all device management tools with the MCP server."""
    mcp_server.tool()(get_devices)
    mcp_server.tool()(get_device)
    mcp_server.tool()(remove_device)
    mcp_server.tool()(get_all_device_ports)
    mcp_server.tool()(get_device_ports)
    mcp_server.tool()(change_device_port_state)
