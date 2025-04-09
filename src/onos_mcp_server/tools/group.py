from typing import Any, Dict, List, Optional
from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_all_groups() -> str:
    """Returns all groups of all devices.

    Retrieves information about all group entries across all devices.
    """
    try:
        groups = await make_onos_request("get", "/groups")
        return str(groups)
    except Exception as e:
        return f"Error retrieving all groups: {str(e)}"


async def get_device_groups(deviceId: str) -> str:
    """Returns all groups associated with the given device.

    Args:
        deviceId: Device identifier
    """
    try:
        groups = await make_onos_request("get", f"/groups/{deviceId}")
        return str(groups)
    except Exception as e:
        return f"Error retrieving groups for device {deviceId}: {str(e)}"


async def add_group(
    deviceId: str,
    group_type: str,
    app_id: str,
    app_cookie: str,
    buckets: List[Dict[str, Any]],
) -> str:
    """Create a new group rule.

    Args:
        deviceId: Device identifier
        group_type: Type of group (ALL, SELECT, INDIRECT, FAILOVER)
        app_id: Application identifier
        app_cookie: Application-specific cookie for this group
        buckets: List of buckets with treatment instructions

    Creates and installs a new group rule for the specified device.
    """
    try:
        group_data = {
            "type": group_type,
            "appId": app_id,
            "appCookie": app_cookie,
            "buckets": buckets,
        }

        result = await make_onos_request("post", f"/groups/{deviceId}", json=group_data)
        return f"Group added successfully to device {deviceId}: {result}"
    except Exception as e:
        return f"Error adding group to device {deviceId}: {str(e)}"


async def get_group(deviceId: str, appCookie: str) -> str:
    """Returns a group with the given deviceId and appCookie.

    Args:
        deviceId: Device identifier
        appCookie: Application cookie/key that identifies the group
    """
    try:
        group = await make_onos_request("get", f"/groups/{deviceId}/{appCookie}")
        return str(group)
    except Exception as e:
        return f"Error retrieving group with cookie {appCookie} for device {deviceId}: {str(e)}"


async def remove_group(deviceId: str, appCookie: str) -> str:
    """Removes the specified group.

    Args:
        deviceId: Device identifier
        appCookie: Application cookie used for lookup
    """
    try:
        await make_onos_request("delete", f"/groups/{deviceId}/{appCookie}")
        return (
            f"Group with cookie {appCookie} removed successfully from device {deviceId}"
        )
    except Exception as e:
        return f"Error removing group with cookie {appCookie} from device {deviceId}: {str(e)}"


async def add_buckets_to_group(
    deviceId: str, appCookie: str, buckets: List[Dict[str, Any]]
) -> str:
    """Adds buckets to an existing group.

    Args:
        deviceId: Device identifier
        appCookie: Application cookie
        buckets: List of buckets to add to the group
    """
    try:
        buckets_data = {"buckets": buckets}

        result = await make_onos_request(
            "post", f"/groups/{deviceId}/{appCookie}/buckets", json=buckets_data
        )
        return f"Buckets added successfully to group with cookie {appCookie} on device {deviceId}: {result}"
    except Exception as e:
        return f"Error adding buckets to group with cookie {appCookie} on device {deviceId}: {str(e)}"


async def remove_buckets_from_group(
    deviceId: str, appCookie: str, bucketIds: str
) -> str:
    """Removes buckets from an existing group.

    Args:
        deviceId: Device identifier
        appCookie: Application cookie
        bucketIds: Comma separated list of bucket identifiers to remove
    """
    try:
        await make_onos_request(
            "delete", f"/groups/{deviceId}/{appCookie}/buckets/{bucketIds}"
        )
        return f"Buckets {bucketIds} removed successfully from group with cookie {appCookie} on device {deviceId}"
    except Exception as e:
        return f"Error removing buckets from group with cookie {appCookie} on device {deviceId}: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all group management tools with the MCP server."""
    mcp_server.tool()(get_all_groups)
    mcp_server.tool()(get_device_groups)
    mcp_server.tool()(add_group)
    mcp_server.tool()(get_group)
    mcp_server.tool()(remove_group)
    mcp_server.tool()(add_buckets_to_group)
    mcp_server.tool()(remove_buckets_from_group)
