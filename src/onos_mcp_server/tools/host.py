from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request
from typing import Any, Dict, List


async def get_hosts() -> str:
    """Get all end-station hosts.

    Returns array of all known end-station hosts.
    """
    try:
        hosts = await make_onos_request("get", "/hosts")
        return str(hosts)
    except Exception as e:
        return f"Error retrieving hosts: {str(e)}"


async def get_host(host_id: str) -> str:
    """Get details of a specific end-station host.

    Args:
        host_id: Host identifier

    Returns detailed properties of the specified end-station host.
    """
    try:
        host = await make_onos_request("get", f"/hosts/{host_id}")
        return str(host)
    except Exception as e:
        return f"Error retrieving host {host_id}: {str(e)}"


async def get_host_by_mac_vlan(mac: str, vlan: str) -> str:
    """Get details of end-station host with MAC/VLAN.

    Args:
        mac: Host MAC address
        vlan: Host VLAN identifier

    Returns detailed properties of the specified end-station host.
    """
    try:
        host = await make_onos_request("get", f"/hosts/{mac}/{vlan}")
        return str(host)
    except Exception as e:
        return f"Error retrieving host with MAC {mac} and VLAN {vlan}: {str(e)}"


async def add_host(
    mac: str, vlan: str, ip_addresses: List[str], locations: List[Dict[str, Any]]
) -> str:
    """Create a new host and add it to the host inventory.

    Args:
        mac: MAC address of the host (format: xx:xx:xx:xx:xx:xx)
        vlan: VLAN ID (use "-1" for none)
        ip_addresses: List of IP addresses for the host
        locations: List of locations where the host is connected
                  Each location should have 'elementId' (device ID) and 'port' (port number)

    Creates a new host based on provided information and adds it to the current host inventory.
    """
    try:
        host_data = {
            "mac": mac,
            "vlan": vlan,
            "ipAddresses": ip_addresses,
            "locations": locations,
        }

        result = await make_onos_request("post", "/hosts", json=host_data)
        return f"Host added successfully: {result}"
    except Exception as e:
        return f"Error adding host: {str(e)}"


async def remove_host(mac: str, vlan: str) -> str:
    """Remove a host from the inventory.

    Args:
        mac: Host MAC address
        vlan: Host VLAN identifier

    Administratively deletes the specified host from the inventory of known hosts.
    """
    try:
        await make_onos_request("delete", f"/hosts/{mac}/{vlan}")
        return f"Host with MAC {mac} and VLAN {vlan} removed successfully"
    except Exception as e:
        return f"Error removing host with MAC {mac} and VLAN {vlan}: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all host management tools with the MCP server."""
    mcp_server.tool()(get_hosts)
    mcp_server.tool()(get_host)
    mcp_server.tool()(get_host_by_mac_vlan)
    mcp_server.tool()(add_host)
    mcp_server.tool()(remove_host)
