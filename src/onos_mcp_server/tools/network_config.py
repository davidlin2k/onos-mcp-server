from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_network_configuration() -> str:
    """Gets entire network configuration base.

    Returns all network configuration information stored in the system.
    """
    try:
        config = await make_onos_request("get", "/network/configuration")
        return str(config)
    except Exception as e:
        return f"Error retrieving network configuration: {str(e)}"


async def upload_network_configuration(config_data: Dict[str, Any]) -> str:
    """Uploads bulk network configuration.

    Args:
        config_data: Network configuration JSON rooted at the top node

    Uploads a complete set of network configurations.
    """
    try:
        result = await make_onos_request(
            "post", "/network/configuration", json=config_data
        )
        return f"Network configuration uploaded successfully: {result}"
    except Exception as e:
        return f"Error uploading network configuration: {str(e)}"


async def clear_network_configuration() -> str:
    """Clear entire network configuration base.

    Removes all network configuration from the system.
    """
    try:
        await make_onos_request("delete", "/network/configuration")
        return "Network configuration cleared successfully"
    except Exception as e:
        return f"Error clearing network configuration: {str(e)}"


async def get_subject_class_configuration(subject_class_key: str) -> str:
    """Gets all network configuration for a subject class.

    Args:
        subject_class_key: Subject class key

    Returns all configuration for the specified subject class.
    """
    try:
        config = await make_onos_request(
            "get", f"/network/configuration/{subject_class_key}"
        )
        return str(config)
    except Exception as e:
        return f"Error retrieving configuration for subject class {subject_class_key}: {str(e)}"


async def upload_subject_class_configuration(
    subject_class_key: str, config_data: Dict[str, Any]
) -> str:
    """Upload multiple network configurations for a subject class.

    Args:
        subject_class_key: Subject class key
        config_data: Network configuration JSON rooted at the top node

    Uploads configurations for the specified subject class.
    """
    try:
        result = await make_onos_request(
            "post", f"/network/configuration/{subject_class_key}", json=config_data
        )
        return f"Configuration for subject class {subject_class_key} uploaded successfully: {result}"
    except Exception as e:
        return f"Error uploading configuration for subject class {subject_class_key}: {str(e)}"


async def clear_subject_class_configuration(subject_class_key: str) -> str:
    """Clear all network configurations for a subject class.

    Args:
        subject_class_key: Subject class key

    Removes all configuration for the specified subject class.
    """
    try:
        await make_onos_request("delete", f"/network/configuration/{subject_class_key}")
        return (
            f"Configuration for subject class {subject_class_key} cleared successfully"
        )
    except Exception as e:
        return f"Error clearing configuration for subject class {subject_class_key}: {str(e)}"


async def get_subject_configuration(subject_class_key: str, subject_key: str) -> str:
    """Gets all network configuration for a subject.

    Args:
        subject_class_key: Subject class key
        subject_key: Subject key

    Returns all configuration for the specified subject.
    """
    try:
        config = await make_onos_request(
            "get", f"/network/configuration/{subject_class_key}/{subject_key}"
        )
        return str(config)
    except Exception as e:
        return f"Error retrieving configuration for subject {subject_key}: {str(e)}"


async def upload_subject_configuration(
    subject_class_key: str, subject_key: str, config_data: Dict[str, Any]
) -> str:
    """Upload multiple network configurations for a subject.

    Args:
        subject_class_key: Subject class key
        subject_key: Subject key
        config_data: Network configuration JSON rooted at the top node

    Uploads configurations for the specified subject.
    """
    try:
        result = await make_onos_request(
            "post",
            f"/network/configuration/{subject_class_key}/{subject_key}",
            json=config_data,
        )
        return (
            f"Configuration for subject {subject_key} uploaded successfully: {result}"
        )
    except Exception as e:
        return f"Error uploading configuration for subject {subject_key}: {str(e)}"


async def clear_subject_configuration(subject_class_key: str, subject_key: str) -> str:
    """Clear all network configurations for a subject.

    Args:
        subject_class_key: Subject class key
        subject_key: Subject key

    Removes all configuration for the specified subject.
    """
    try:
        await make_onos_request(
            "delete", f"/network/configuration/{subject_class_key}/{subject_key}"
        )
        return f"Configuration for subject {subject_key} cleared successfully"
    except Exception as e:
        return f"Error clearing configuration for subject {subject_key}: {str(e)}"


async def get_specific_configuration(
    subject_class_key: str, subject_key: str, config_key: str
) -> str:
    """Gets specific network configuration for a subject.

    Args:
        subject_class_key: Subject class key
        subject_key: Subject key
        config_key: Configuration class key

    Returns specific configuration for the specified subject.
    """
    try:
        config = await make_onos_request(
            "get",
            f"/network/configuration/{subject_class_key}/{subject_key}/{config_key}",
        )
        return str(config)
    except Exception as e:
        return f"Error retrieving {config_key} configuration for subject {subject_key}: {str(e)}"


async def upload_specific_configuration(
    subject_class_key: str,
    subject_key: str,
    config_key: str,
    config_data: Dict[str, Any],
) -> str:
    """Upload specific network configuration for a subject.

    Args:
        subject_class_key: Subject class key
        subject_key: Subject key
        config_key: Configuration class key
        config_data: Network configuration JSON rooted at the top node

    Uploads specific configuration for the specified subject.
    """
    try:
        result = await make_onos_request(
            "post",
            f"/network/configuration/{subject_class_key}/{subject_key}/{config_key}",
            json=config_data,
        )
        return f"{config_key} configuration for subject {subject_key} uploaded successfully: {result}"
    except Exception as e:
        return f"Error uploading {config_key} configuration for subject {subject_key}: {str(e)}"


async def clear_specific_configuration(
    subject_class_key: str, subject_key: str, config_key: str
) -> str:
    """Clear specific network configuration for a subject.

    Args:
        subject_class_key: Subject class key
        subject_key: Subject key
        config_key: Configuration class key

    Removes specific configuration for the specified subject.
    """
    try:
        await make_onos_request(
            "delete",
            f"/network/configuration/{subject_class_key}/{subject_key}/{config_key}",
        )
        return (
            f"{config_key} configuration for subject {subject_key} cleared successfully"
        )
    except Exception as e:
        return f"Error clearing {config_key} configuration for subject {subject_key}: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all network configuration tools with the MCP server."""
    mcp_server.tool()(get_network_configuration)
    mcp_server.tool()(upload_network_configuration)
    mcp_server.tool()(clear_network_configuration)
    mcp_server.tool()(get_subject_class_configuration)
    mcp_server.tool()(upload_subject_class_configuration)
    mcp_server.tool()(clear_subject_class_configuration)
    mcp_server.tool()(get_subject_configuration)
    mcp_server.tool()(upload_subject_configuration)
    mcp_server.tool()(clear_subject_configuration)
    mcp_server.tool()(get_specific_configuration)
    mcp_server.tool()(upload_specific_configuration)
    mcp_server.tool()(clear_specific_configuration)
