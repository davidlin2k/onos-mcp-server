from mcp.server.fastmcp import FastMCP
from onos_mcp_server.api_client import make_onos_request


async def get_network_summary() -> str:
    """Get a high-level summary of the network including devices, links, and hosts."""
    try:
        # Fetch devices, links, hosts, and topology in parallel
        devices_data = await make_onos_request("get", "/devices")
        links_data = await make_onos_request("get", "/links")
        hosts_data = await make_onos_request("get", "/hosts")
        topology_data = await make_onos_request("get", "/topology")

        # Extract key information
        device_count = len(devices_data.get("devices", []))
        link_count = len(links_data.get("links", []))
        host_count = len(hosts_data.get("hosts", []))
        cluster_count = topology_data.get("clusters", 0)

        # Create summary text
        summary = [
            "# Network Summary",
            f"- Devices: {device_count}",
            f"- Links: {link_count}",
            f"- Hosts: {host_count}",
            f"- Clusters: {cluster_count}",
        ]

        # Add device details
        summary.append("\n## Device Details")
        for device in devices_data.get("devices", []):
            device_id = device.get("id")
            status = "Available" if device.get("available") else "Unavailable"
            manufacturer = device.get("mfr", "Unknown")
            hw_version = device.get("hw", "Unknown")
            sw_version = device.get("sw", "Unknown")

            summary.append(
                f"- {device_id}: {status}, Manufacturer: {manufacturer}, HW: {hw_version}, SW: {sw_version}"
            )

        return "\n".join(summary)
    except Exception as e:
        return f"Error retrieving network summary: {str(e)}"


async def get_network_analytics() -> str:
    """Get analytics about network performance, utilization and health."""
    try:
        # Gather various statistics in parallel
        stats = await make_onos_request("get", "/statistics/ports")
        flows = await make_onos_request("get", "/flows")
        devices = await make_onos_request("get", "/devices")

        # Calculate analytics
        device_count = len(devices.get("devices", []))
        active_devices = sum(
            1 for d in devices.get("devices", []) if d.get("available", False)
        )
        total_flows = sum(len(dev.get("flows", [])) for dev in flows.get("flows", []))

        # Port utilization
        port_stats = {}
        for stat in stats.get("statistics", []):
            device_id = stat.get("device", "")
            if device_id not in port_stats:
                port_stats[device_id] = []

            ports = []
            for port in stat.get("ports", []):
                port_number = port.get("port", "")
                bytes_received = port.get("bytesReceived", 0)
                bytes_sent = port.get("bytesSent", 0)
                packets_received = port.get("packetsReceived", 0)
                packets_sent = port.get("packetsSent", 0)

                ports.append(
                    {
                        "port": port_number,
                        "bytesReceived": bytes_received,
                        "bytesSent": bytes_sent,
                        "packetsReceived": packets_received,
                        "packetsSent": packets_sent,
                    }
                )

            port_stats[device_id] = ports

        # Format the output
        result = [
            "# Network Analytics",
            f"## Overview",
            f"- Total Devices: {device_count}",
            f"- Active Devices: {active_devices}",
        ]

        # Add device availability percentage
        availability_pct = "N/A"
        if device_count > 0:
            availability_pct = f"{active_devices / device_count * 100:.1f}%"
        result.append(f"- Device Availability: {availability_pct}")

        # Add flow statistics
        result.append(f"- Total Flow Rules: {total_flows}")

        # Add average flow rules per device
        avg_flows = "N/A"
        if active_devices > 0:
            avg_flows = f"{total_flows / active_devices:.1f}"
        result.append(f"- Avg. Flow Rules per Device: {avg_flows}")

        # Add port statistics for top devices
        result.append("\n## Port Statistics (Top 5 Devices)")

        # Sort devices by traffic volume
        device_traffic = {}
        for device_id, ports in port_stats.items():
            total_bytes = sum(
                p.get("bytesReceived", 0) + p.get("bytesSent", 0) for p in ports
            )
            device_traffic[device_id] = total_bytes

        # Show top 5 devices by traffic
        top_devices = sorted(device_traffic.items(), key=lambda x: x[1], reverse=True)[
            :5
        ]

        for device_id, traffic in top_devices:
            result.append(f"\n### Device {device_id}")
            result.append(f"- Total Traffic: {traffic} bytes")

            # Show top 3 busiest ports
            ports = sorted(
                port_stats.get(device_id, []),
                key=lambda p: p.get("bytesReceived", 0) + p.get("bytesSent", 0),
                reverse=True,
            )[:3]

            result.append("#### Busiest Ports:")
            for port in ports:
                port_id = port.get("port", "")
                bytes_in = port.get("bytesReceived", 0)
                bytes_out = port.get("bytesSent", 0)
                packets_in = port.get("packetsReceived", 0)
                packets_out = port.get("packetsSent", 0)

                result.append(
                    f"- Port {port_id}: {bytes_in + bytes_out} bytes, {packets_in + packets_out} packets"
                )

        return "\n".join(result)
    except Exception as e:
        return f"Error retrieving network analytics: {str(e)}"


def register_tools(mcp_server: FastMCP):
    mcp_server.tool()(get_network_summary)
    mcp_server.tool()(get_network_analytics)
