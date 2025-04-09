from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_all_modulation_devices() -> str:
    """Gets all modulation config devices.

    Returns array of all discovered modulation config devices.
    """
    try:
        devices = await make_onos_request("get", "/modulation")
        return str(devices)
    except Exception as e:
        return f"Error retrieving modulation devices: {str(e)}"


async def get_modulation_device(device_id: str) -> str:
    """Gets the details of a modulation config device.

    Args:
        device_id: Device identifier

    Returns the details of the specified modulation config device.
    """
    try:
        device = await make_onos_request("get", f"/modulation/{device_id}")
        return str(device)
    except Exception as e:
        return f"Error retrieving modulation device {device_id}: {str(e)}"


async def get_device_port_modulation(device_id: str, port_id: str) -> str:
    """Returns the supported modulation scheme for specified port of device.

    Args:
        device_id: Line port identifier
        port_id: Line port identifier

    Returns the supported modulation scheme for the specified port.
    """
    try:
        params = {"port_id": port_id}
        modulation = await make_onos_request(
            "get", f"/modulation/{device_id}/port", params=params
        )
        return str(modulation)
    except Exception as e:
        return f"Error retrieving modulation scheme for device {device_id}, port {port_id}: {str(e)}"


async def apply_device_modulation(modulation_data: Dict[str, Any]) -> str:
    """Applies the target modulation for the specified device.

    Args:
        modulation_data: JSON representation of device, port, component and target bitrate info

    Sets the modulation parameters for a device.
    """
    try:
        result = await make_onos_request("put", "/modulation", json=modulation_data)
        return f"Modulation applied successfully: {result}"
    except Exception as e:
        return f"Error applying modulation: {str(e)}"


async def set_port_modulation(
    device_id: str, port_id: str, direction: str, bitrate: float
) -> str:
    """Sets the modulation for specified device and port.

    Args:
        device_id: Device identifier
        port_id: Port channel
        direction: Port direction (transmitter or receiver port)
        bitrate: Port bitrate

    Sets specific modulation parameters for a device port.
    """
    try:
        params = {"port_id": port_id, "direction": direction, "bitrate": bitrate}

        result = await make_onos_request(
            "put", f"/modulation/set-modulation/{device_id}", params=params
        )
        return f"Port modulation set successfully for device {device_id}, port {port_id}: {result}"
    except Exception as e:
        return f"Error setting port modulation for device {device_id}, port {port_id}: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all modulation management tools with the MCP server."""
    mcp_server.tool()(get_all_modulation_devices)
    mcp_server.tool()(get_modulation_device)
    mcp_server.tool()(get_device_port_modulation)
    mcp_server.tool()(apply_device_modulation)
    mcp_server.tool()(set_port_modulation)
