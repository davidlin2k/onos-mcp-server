from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import (
    ONOS_API_BASE,
    ONOS_USERNAME,
    ONOS_PASSWORD,
    HTTP_TIMEOUT,
)
import os
import httpx
import tempfile


async def get_diagnostics(save_path: str = None) -> str:
    """Get diagnostic information as a tar.gz file.

    Args:
        save_path: Optional path to save the tar.gz file. If not provided,
                  a temporary file will be created.

    Returns a tar.gz stream of node diagnostic information.
    """
    try:
        # This endpoint returns binary data, so we need a direct httpx request
        url = f"{ONOS_API_BASE}/diagnostics"
        auth = (ONOS_USERNAME, ONOS_PASSWORD)

        async with httpx.AsyncClient() as client:
            response = await client.get(url, auth=auth, timeout=HTTP_TIMEOUT)
            response.raise_for_status()

            # Determine where to save the file
            if not save_path:
                # Create a temporary file with .tar.gz extension
                fd, save_path = tempfile.mkstemp(
                    suffix=".tar.gz", prefix="onos_diagnostics_"
                )
                os.close(fd)

            # Write the binary content to file
            with open(save_path, "wb") as f:
                f.write(response.content)

            return f"Diagnostics data saved to {save_path}"
    except Exception as e:
        return f"Error retrieving diagnostics data: {str(e)}"


async def run_diagnostics_command(command: str, timeout: int = 60) -> str:
    """Run a diagnostics command.

    Args:
        command: The diagnostic command to execute
        timeout: Command timeout in seconds (default: 60)

    Returns the result of the diagnostic command.
    """
    try:
        command_data = {"command": command, "timeout": timeout}

        from onos_mcp_server.api_client import make_onos_request

        result = await make_onos_request("post", "/diagnostics", json=command_data)
        return f"Diagnostics command executed successfully: {result}"
    except Exception as e:
        return f"Error running diagnostics command: {str(e)}"


def register_tools(mcp_server: FastMCP):
    """Register all diagnostics tools with the MCP server."""
    mcp_server.tool()(get_diagnostics)
    mcp_server.tool()(run_diagnostics_command)
