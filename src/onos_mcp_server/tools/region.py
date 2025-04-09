from typing import Any, Dict, List
from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_all_regions() -> str:
    """Returns set of all regions.

    Gets all network regions defined in the system.
    """
    try:
        regions = await make_onos_request("get", "/regions")
        return str(regions)
    except Exception as e:
        return f"Error retrieving regions: {str(e)}"


async def get_region(regionId: str) -> str:
    """Returns the region with the specified identifier.

    Args:
        regionId: Region identifier

    Gets detailed information about a specific region.
    """
    try:
        region = await make_onos_request("get", f"/regions/{regionId}")
        return str(region)
    except Exception as e:
        return f"Error retrieving region {regionId}: {str(e)}"


async def create_region(
    region_id: str, region_name: str, region_type: str, masters: List[str] = None
) -> str:
    """Creates a new region using the supplied JSON input stream.

    Args:
        region_id: Region identifier
        region_name: Human-readable name for the region
        region_type: Type of region (e.g., METRO, CAMPUS, DATA_CENTER)
        masters: Optional list of master node IDs

    Creates a new network region.
    """
    try:
        region_data = {"id": region_id, "name": region_name, "type": region_type}

        if masters:
            region_data["masters"] = masters

        result = await make_onos_request("post", "/regions", json=region_data)
        return f"Region '{region_name}' created successfully with ID {region_id}"
    except Exception as e:
        return f"Error creating region: {str(e)}"


async def update_region(regionId: str, region_data: Dict[str, Any]) -> str:
    """Updates the specified region using the supplied JSON input stream.

    Args:
        regionId: Region identifier
        region_data: Updated region data including name, type, etc.

    Updates an existing network region.
    """
    try:
        result = await make_onos_request(
            "put", f"/regions/{regionId}", json=region_data
        )
        return f"Region {regionId} updated successfully"
    except Exception as e:
        return f"Error updating region {regionId}: {str(e)}"


async def remove_region(regionId: str) -> str:
    """Removes the specified region using the given region identifier.

    Args:
        regionId: Region identifier

    Deletes a network region.
    """
    try:
        await make_onos_request("delete", f"/regions/{regionId}")
        return f"Region {regionId} removed successfully"
    except Exception as e:
        return f"Error removing region {regionId}: {str(e)}"


async def get_region_devices(regionId: str) -> str:
    """Returns the set of devices that belong to the specified region.

    Args:
        regionId: Region identifier

    Gets all devices assigned to a specific region.
    """
    try:
        devices = await make_onos_request("get", f"/regions/{regionId}/devices")
        return str(devices)
    except Exception as e:
        return f"Error retrieving devices for region {regionId}: {str(e)}"


async def add_devices_to_region(regionId: str, device_ids: List[str]) -> str:
    """Adds the specified collection of devices to the region.

    Args:
        regionId: Region identifier
        device_ids: List of device identifiers to add to the region

    Assigns devices to a network region.
    """
    try:
        device_data = {"deviceIds": device_ids}

        result = await make_onos_request(
            "post", f"/regions/{regionId}/devices", json=device_data
        )
        return f"Devices added successfully to region {regionId}"
    except Exception as e:
        return f"Error adding devices to region {regionId}: {str(e)}"


async def remove_devices_from_region(regionId: str, device_ids: List[str]) -> str:
    """Removes the specified collection of devices from the region.

    Args:
        regionId: Region identifier
        device_ids: List of device identifiers to remove from the region

    Removes devices from a network region.
    """
    try:
        device_data = {"deviceIds": device_ids}

        await make_onos_request(
            "delete", f"/regions/{regionId}/devices", json=device_data
        )
        return f"Devices removed successfully from region {regionId}"
    except Exception as e:
        return f"Error removing devices from region {regionId}: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all region management tools with the MCP server."""
    mcp_server.tool()(get_all_regions)
    mcp_server.tool()(get_region)
    mcp_server.tool()(create_region)
    mcp_server.tool()(update_region)
    mcp_server.tool()(remove_region)
    mcp_server.tool()(get_region_devices)
    mcp_server.tool()(add_devices_to_region)
    mcp_server.tool()(remove_devices_from_region)
