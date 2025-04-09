from mcp.server.fastmcp import FastMCP

from onos_mcp_server.prompts import register_prompts
from onos_mcp_server.tools import (
    device,
    diagnostics,
    flow,
    group,
    host,
    intent,
    link,
    mastership,
    meter,
    metric,
    modulation,
    multicast,
    network_config,
    packet,
    path,
    region,
    statistics,
    system,
    topology,
    custom_tools,
)


def create_server():
    mcp = FastMCP("ONOS Network Management", log_level="ERROR")

    # Register all tools
    device.register_tools(mcp)
    diagnostics.register_tools(mcp)
    flow.register_tools(mcp)
    group.register_tools(mcp)
    host.register_tools(mcp)
    intent.register_tools(mcp)
    link.register_tools(mcp)
    mastership.register_tools(mcp)
    meter.register_tools(mcp)
    metric.register_tools(mcp)
    modulation.register_tools(mcp)
    multicast.register_tools(mcp)
    network_config.register_tools(mcp)
    packet.register_tools(mcp)
    path.register_tools(mcp)
    region.register_tools(mcp)
    statistics.register_tools(mcp)
    system.register_tools(mcp)
    topology.register_tools(mcp)
    custom_tools.register_tools(mcp)

    register_prompts(mcp)

    return mcp


if __name__ == "__main__":
    mcp = create_server()
    mcp.run()
