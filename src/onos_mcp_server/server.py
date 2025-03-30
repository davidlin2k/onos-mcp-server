from typing import Any, Dict, List, Optional
import asyncio
import os
import httpx
from mcp.server.fastmcp import FastMCP, Context, Image
from mcp.server.fastmcp.prompts import base

# Create an MCP server
mcp = FastMCP("ONOS Network Management", log_level="ERROR")

# Configuration
ONOS_API_BASE = os.environ.get("ONOS_API_BASE", "http://localhost:8181/onos/v1")
ONOS_USERNAME = os.environ.get("ONOS_USERNAME", "onos")
ONOS_PASSWORD = os.environ.get("ONOS_PASSWORD", "rocks")
HTTP_TIMEOUT = 30.0  # seconds

# Helper functions
async def make_onos_request(
    method: str, 
    path: str, 
    json: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Make a request to the ONOS REST API with proper authentication and error handling."""
    url = f"{ONOS_API_BASE}{path}"
    auth = (ONOS_USERNAME, ONOS_PASSWORD)
    
    async with httpx.AsyncClient() as client:
        try:
            if method.lower() == "get":
                response = await client.get(url, auth=auth, params=params, timeout=HTTP_TIMEOUT)
            elif method.lower() == "post":
                response = await client.post(url, auth=auth, json=json, timeout=HTTP_TIMEOUT)
            elif method.lower() == "put":
                response = await client.put(url, auth=auth, json=json, timeout=HTTP_TIMEOUT)
            elif method.lower() == "delete":
                response = await client.delete(url, auth=auth, timeout=HTTP_TIMEOUT)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response.json() if response.content else {}
        except httpx.HTTPStatusError as e:
            error_msg = f"ONOS API error: {e.response.status_code} - {e.response.text}"
            raise ValueError(error_msg)
        except Exception as e:
            raise ValueError(f"Error connecting to ONOS: {str(e)}")

# Resources
@mcp.tool()
async def get_devices() -> str:
    """Get information about all network devices."""
    devices = await make_onos_request("get", "/devices")
    return str(devices)

@mcp.tool()
async def get_device(deviceId: str) -> str:
    """Get detailed information about a specific device.
    
    Args:
        deviceId: ID of the device to query
    """
    device = await make_onos_request("get", f"/devices/{deviceId}")
    return str(device)

@mcp.tool()
async def get_links() -> str:
    """Get information about all network links."""
    links = await make_onos_request("get", "/links")
    return str(links)

@mcp.tool()
async def get_hosts() -> str:
    """Get information about all hosts connected to the network."""
    hosts = await make_onos_request("get", "/hosts")
    return str(hosts)

@mcp.tool()
async def get_topology() -> str:
    """Get overview of current network topology."""
    topology = await make_onos_request("get", "/topology")
    return str(topology)

@mcp.tool()
async def get_applications() -> str:
    """Get information about all installed applications."""
    applications = await make_onos_request("get", "/applications")
    return str(applications)

@mcp.tool()
async def get_device_flows(deviceId: str) -> str:
    """Get all flow entries for a specific device."""
    flows = await make_onos_request("get", f"/flows/{deviceId}")
    return str(flows)

@mcp.tool()
async def get_system_info() -> str:
    """Get high-level system information, version, and memory usage."""
    system_info = await make_onos_request("get", "/system")
    return str(system_info)

@mcp.tool()
async def get_metrics() -> str:
    """Get statistics information for all metrics."""
    metrics = await make_onos_request("get", "/metrics")
    return str(metrics)

@mcp.tool()
async def get_specific_metric(metricName: str) -> str:
    """Get statistics information for a specific metric."""
    metric = await make_onos_request("get", f"/metrics/{metricName}")
    return str(metric)

@mcp.tool()
async def get_device_meters(deviceId: str) -> str:
    """Get all meter entries for a specific device."""
    meters = await make_onos_request("get", f"/meters/{deviceId}")
    return str(meters)

@mcp.tool()
async def get_all_intents() -> str:
    """Get all intents in the system."""
    intents = await make_onos_request("get", "/intents")
    return str(intents)

@mcp.tool()
async def get_device_groups(deviceId: str) -> str:
    """Get all group entries for a specific device."""
    groups = await make_onos_request("get", f"/groups/{deviceId}")
    return str(groups)

@mcp.tool()
async def get_port_statistics() -> str:
    """Get statistics for all ports across all devices."""
    statistics = await make_onos_request("get", "/statistics/ports")
    return str(statistics)

@mcp.tool()
async def get_device_port_statistics(deviceId: str) -> str:
    """Get statistics for all ports on a specific device."""
    statistics = await make_onos_request("get", f"/statistics/ports/{deviceId}")
    return str(statistics)

@mcp.tool()
async def get_flow_rules() -> str:
    """Get all flow rules across all devices."""
    flows = await make_onos_request("get", "/flows")
    return str(flows)

@mcp.tool()
async def remove_flow_rule(deviceId: str, flowId: str) -> str:
    """Remove a specific flow rule from a device."""
    await make_onos_request("delete", f"/flows/{deviceId}/{flowId}")
    return f"Flow rule {flowId} removed from device {deviceId}"

@mcp.tool()
async def get_flow_statistics() -> str:
    """Get statistics for all flows across all devices."""
    statistics = await make_onos_request("get", "/statistics/flows")
    return str(statistics)

@mcp.tool()
async def get_device_flow_statistics(deviceId: str) -> str:
    """Get statistics for all flows on a specific device."""
    statistics = await make_onos_request("get", f"/statistics/flows/{deviceId}")
    return str(statistics)

@mcp.tool()
async def get_table_statistics() -> str:
    """Get statistics for all flow tables across all devices."""
    statistics = await make_onos_request("get", "/statistics/tables")
    return str(statistics)

@mcp.tool()
async def get_device_table_statistics(deviceId: str) -> str:
    """Get statistics for all flow tables on a specific device."""
    statistics = await make_onos_request("get", f"/statistics/tables/{deviceId}")
    return str(statistics)

@mcp.tool()
async def get_network_configuration() -> str:
    """Get the entire network configuration."""
    configuration = await make_onos_request("get", "/network/configuration")
    return str(configuration)

@mcp.tool()
async def get_component_configuration() -> str:
    """Get component configurations."""
    configuration = await make_onos_request("get", "/configuration")
    return str(configuration)

@mcp.tool()
async def get_specific_component_configuration(componentName: str) -> str:
    """Get configuration for a specific component."""
    configuration = await make_onos_request("get", f"/configuration/{componentName}")
    return str(configuration)

@mcp.tool()
async def get_packet_processors() -> str:
    """Get all packet processors."""
    processors = await make_onos_request("get", "/packet/processors")
    return str(processors)

@mcp.tool()
async def get_regions() -> str:
    """Get information about all regions."""
    regions = await make_onos_request("get", "/regions")
    return str(regions)

@mcp.tool()
async def get_region(regionId: str) -> str:
    """Get detailed information about a specific region."""
    region = await make_onos_request("get", f"/regions/{regionId}")
    return str(region)

@mcp.tool()
async def get_device_keys() -> str:
    """Get all device keys."""
    keys = await make_onos_request("get", "/keys")
    return str(keys)

@mcp.tool()
async def get_device_key(deviceId: str) -> str:
    """Get keys for a specific device."""
    key = await make_onos_request("get", f"/keys/{deviceId}")
    return str(key)

@mcp.tool()
async def get_diagnostics() -> str:
    """Get diagnostics information."""
    diagnostics = await make_onos_request("get", "/diagnostics")
    return str(diagnostics)

@mcp.tool()
async def get_filter_objectives(deviceId: str) -> str:
    """Get filter flow objectives for a device."""
    objectives = await make_onos_request("get", f"/flowobjectives/{deviceId}/filter")
    return str(objectives)

@mcp.tool()
async def get_forward_objectives(deviceId: str) -> str:
    """Get forwarding flow objectives for a device."""
    objectives = await make_onos_request("get", f"/flowobjectives/{deviceId}/forward")
    return str(objectives)

@mcp.tool()
async def get_next_objectives(deviceId: str) -> str:
    """Get next flow objectives for a device."""
    objectives = await make_onos_request("get", f"/flowobjectives/{deviceId}/next")
    return str(objectives)

@mcp.tool()
async def get_multicast_routes() -> str:
    """Get all multicast routes."""
    routes = await make_onos_request("get", "/mcast")
    return str(routes)

@mcp.tool()
async def get_multicast_route(routeId: str) -> str:
    """Get a specific multicast route."""
    route = await make_onos_request("get", f"/mcast/{routeId}")
    return str(route)

@mcp.tool()
async def get_mastership() -> str:
    """Get mastership information for all devices."""
    mastership = await make_onos_request("get", "/mastership")
    return str(mastership)

@mcp.tool()
async def get_device_mastership(deviceId: str) -> str:
    """Get mastership information for a specific device."""
    mastership = await make_onos_request("get", f"/mastership/{deviceId}")
    return str(mastership)

# Tools
@mcp.tool()
async def get_network_summary() -> str:
    """Get a high-level summary of the network including devices, links, and hosts."""
    try:
        # Fetch devices, links, hosts, and topology in parallel
        devices_task = asyncio.create_task(make_onos_request("get", "/devices"))
        links_task = asyncio.create_task(make_onos_request("get", "/links"))
        hosts_task = asyncio.create_task(make_onos_request("get", "/hosts"))
        topology_task = asyncio.create_task(make_onos_request("get", "/topology"))
        
        devices_data = await devices_task
        links_data = await links_task
        hosts_data = await hosts_task
        topology_data = await topology_task
        
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
            f"- Clusters: {cluster_count}"
        ]
        
        # Add device details
        summary.append("\n## Device Details")
        for device in devices_data.get("devices", []):
            device_id = device.get("id")
            status = "Available" if device.get("available") else "Unavailable"
            manufacturer = device.get("mfr", "Unknown")
            hw_version = device.get("hw", "Unknown")
            sw_version = device.get("sw", "Unknown")
            
            summary.append(f"- {device_id}: {status}, Manufacturer: {manufacturer}, HW: {hw_version}, SW: {sw_version}")
        
        return "\n".join(summary)
    except Exception as e:
        return f"Error retrieving network summary: {str(e)}"

@mcp.tool()
async def install_application(app_file_url: str) -> str:
    """
    Install a new ONOS application from the given OAR file URL.
    
    Args:
        app_file_url: URL to the application OAR file
    """
    try:
        async with httpx.AsyncClient() as client:
            # Download the OAR file
            app_response = await client.get(app_file_url, timeout=HTTP_TIMEOUT)
            app_response.raise_for_status()
            
            # Send to ONOS API for installation
            url = f"{ONOS_API_BASE}/applications"
            params = {"activate": "true"}
            auth = (ONOS_USERNAME, ONOS_PASSWORD)
            
            headers = {"Content-Type": "application/octet-stream"}
            upload_response = await client.post(
                url, 
                params=params,
                auth=auth, 
                content=app_response.content, 
                headers=headers,
                timeout=HTTP_TIMEOUT
            )
            upload_response.raise_for_status()
            
            result = upload_response.json()
            return f"Application installed successfully: {result}"
    except Exception as e:
        return f"Error installing application: {str(e)}"

@mcp.tool()
async def activate_application(app_name: str) -> str:
    """
    Activate an ONOS application.
    
    Args:
        app_name: Name of the application to activate
    """
    try:
        await make_onos_request("post", f"/applications/{app_name}/active")
        return f"Application '{app_name}' activated successfully"
    except Exception as e:
        return f"Error activating application: {str(e)}"

@mcp.tool()
async def deactivate_application(app_name: str) -> str:
    """
    Deactivate an ONOS application.
    
    Args:
        app_name: Name of the application to deactivate
    """
    try:
        await make_onos_request("delete", f"/applications/{app_name}/active")
        return f"Application '{app_name}' deactivated successfully"
    except Exception as e:
        return f"Error deactivating application: {str(e)}"

@mcp.tool()
async def remove_application(app_name: str) -> str:
    """
    Uninstall an ONOS application.
    
    Args:
        app_name: Name of the application to remove
    """
    try:
        await make_onos_request("delete", f"/applications/{app_name}")
        return f"Application '{app_name}' removed successfully"
    except Exception as e:
        return f"Error removing application: {str(e)}"

@mcp.tool()
async def add_host(mac: str, vlan: str, ip_addresses: List[str], location_device: str, location_port: str) -> str:
    """
    Add a new host to the network.
    
    Args:
        mac: MAC address of the host (format: xx:xx:xx:xx:xx:xx)
        vlan: VLAN ID (use "-1" for none)
        ip_addresses: List of IP addresses for the host
        location_device: Device ID where the host is connected
        location_port: Port number where the host is connected
    """
    try:
        host_data = {
            "mac": mac,
            "vlan": vlan,
            "ipAddresses": ip_addresses,
            "locations": [{"elementId": location_device, "port": location_port}]
        }
        
        result = await make_onos_request("post", "/hosts", json=host_data)
        return f"Host added successfully: {result}"
    except Exception as e:
        return f"Error adding host: {str(e)}"

@mcp.tool()
async def add_flow(
    device_id: str,
    priority: int,
    timeout: int,
    is_permanent: bool,
    criteria: List[Dict[str, Any]],
    instructions: List[Dict[str, Any]]
) -> str:
    """
    Add a flow rule to a device with comprehensive criteria and instruction support.
    
    Args:
        device_id: Device ID to add the flow to
        priority: Flow priority (higher values = higher priority)
        timeout: Flow timeout in seconds (0 for no timeout)
        is_permanent: Whether the flow is permanent
        criteria: List of criteria dictionaries. Each criterion must have 'type' and associated fields.
                For example: [{"type": "ETH_TYPE", "ethType": "0x88cc"},
                            {"type": "IN_PORT", "port": "1"}]
        instructions: List of instruction dictionaries. Each instruction must have 'type' and associated fields.
                    For example: [{"type": "OUTPUT", "port": "2"},
                                {"type": "GROUP", "groupId": 1}]
    """
    try:
        # Create flow rule with full criteria and instruction support
        flow_data = {
            "priority": priority,
            "timeout": timeout,
            "isPermanent": is_permanent,
            "deviceId": device_id,
            "treatment": {
                "instructions": instructions
            },
            "selector": {
                "criteria": criteria
            }
        }
        
        params = {"appId": "org.onosproject.mcp"}
        result = await make_onos_request("post", f"/flows/{device_id}", json=flow_data, params=params)
        return f"Flow added successfully: {result}"
    except Exception as e:
        return f"Error adding flow: {str(e)}"

@mcp.tool()
async def remove_flow(device_id: str, flow_id: str) -> str:
    """
    Remove a flow rule from a device.
    
    Args:
        device_id: Device ID
        flow_id: Flow rule ID to remove
    """
    try:
        await make_onos_request("delete", f"/flows/{device_id}/{flow_id}")
        return f"Flow {flow_id} removed successfully from device {device_id}"
    except Exception as e:
        return f"Error removing flow: {str(e)}"

@mcp.tool()
async def add_intent(app_id: str, priority: int, source_host: str, destination_host: str) -> str:
    """
    Add a host-to-host intent.
    
    Args:
        app_id: Application ID
        priority: Intent priority
        source_host: Source host ID
        destination_host: Destination host ID
    """
    try:
        intent_data = {
            "type": "HostToHostIntent",
            "appId": app_id,
            "priority": priority,
            "one": source_host,
            "two": destination_host
        }
        
        result = await make_onos_request("post", "/intents", json=intent_data)
        return f"Intent added successfully: {result}"
    except Exception as e:
        return f"Error adding intent: {str(e)}"

@mcp.tool()
async def remove_intent(app_id: str, intent_key: str) -> str:
    """
    Remove an intent.
    
    Args:
        app_id: Application ID
        intent_key: Intent key
    """
    try:
        await make_onos_request("delete", f"/intents/{app_id}/{intent_key}")
        return f"Intent {intent_key} removed successfully"
    except Exception as e:
        return f"Error removing intent: {str(e)}"

@mcp.tool()
async def change_device_port_state(device_id: str, port_id: str, enabled: bool) -> str:
    """
    Change the administrative state of a device port.
    
    Args:
        device_id: Device ID
        port_id: Port ID
        enabled: True to enable the port, False to disable it
    """
    try:
        port_data = {
            "enabled": enabled
        }
        
        await make_onos_request("post", f"/devices/{device_id}/portstate/{port_id}", json=port_data)
        state = "enabled" if enabled else "disabled"
        return f"Port {port_id} on device {device_id} {state} successfully"
    except Exception as e:
        return f"Error changing port state: {str(e)}"

@mcp.tool()
async def get_shortest_path(source: str, destination: str) -> str:
    """
    Find the shortest path between two devices or hosts.
    
    Args:
        source: Source device/host ID
        destination: Destination device/host ID
    """
    try:
        paths = await make_onos_request("get", f"/paths/{source}/{destination}")
        
        result_lines = ["# Shortest Paths"]
        for i, path in enumerate(paths.get("paths", [])):
            result_lines.append(f"\n## Path {i+1} (Cost: {path.get('cost', 'N/A')})")
            for j, link in enumerate(path.get("links", [])):
                src = link.get("src", {})
                dst = link.get("dst", {})
                result_lines.append(f"{j+1}. {src.get('device', 'Unknown')}:{src.get('port', 'Unknown')} → {dst.get('device', 'Unknown')}:{dst.get('port', 'Unknown')}")
        
        return "\n".join(result_lines)
    except Exception as e:
        return f"Error finding shortest path: {str(e)}"

@mcp.tool()
async def get_topology_clusters() -> str:
    """Get information about strongly connected components in the network topology."""
    try:
        clusters = await make_onos_request("get", "/topology/clusters")
        
        result_lines = ["# Network Topology Clusters"]
        for cluster in clusters.get("clusters", []):
            cluster_id = cluster.get("id", "Unknown")
            device_count = cluster.get("deviceCount", 0)
            link_count = cluster.get("linkCount", 0)
            root = cluster.get("root", "Unknown")
            
            result_lines.append(f"\n## Cluster {cluster_id}")
            result_lines.append(f"- Devices: {device_count}")
            result_lines.append(f"- Links: {link_count}")
            result_lines.append(f"- Root: {root}")
            
            # Add devices in this cluster if available
            devices = cluster.get("deviceIds", [])
            if devices:
                result_lines.append("\n### Devices in this cluster:")
                for device in devices:
                    result_lines.append(f"- {device}")
        
        return "\n".join(result_lines)
    except Exception as e:
        return f"Error retrieving topology clusters: {str(e)}"

@mcp.tool()
async def get_network_analytics() -> str:
    """Get analytics about network performance, utilization and health."""
    try:
        # Gather various statistics in parallel
        stats_task = asyncio.create_task(make_onos_request("get", "/statistics/ports"))
        flows_task = asyncio.create_task(make_onos_request("get", "/flows"))
        devices_task = asyncio.create_task(make_onos_request("get", "/devices"))
        
        stats = await stats_task
        flows = await flows_task
        devices = await devices_task
        
        # Calculate analytics
        device_count = len(devices.get("devices", []))
        active_devices = sum(1 for d in devices.get("devices", []) if d.get("available", False))
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
                
                ports.append({
                    "port": port_number,
                    "bytesReceived": bytes_received,
                    "bytesSent": bytes_sent,
                    "packetsReceived": packets_received,
                    "packetsSent": packets_sent
                })
            
            port_stats[device_id] = ports
        
        # Format the output
        result = [
            "# Network Analytics",
            f"## Overview",
            f"- Total Devices: {device_count}",
            f"- Active Devices: {active_devices}"
        ]
        
        # Add device availability percentage
        availability_pct = "N/A"
        if device_count > 0:
            availability_pct = f"{active_devices/device_count*100:.1f}%"
        result.append(f"- Device Availability: {availability_pct}")
        
        # Add flow statistics
        result.append(f"- Total Flow Rules: {total_flows}")
        
        # Add average flow rules per device
        avg_flows = "N/A"
        if active_devices > 0:
            avg_flows = f"{total_flows/active_devices:.1f}"
        result.append(f"- Avg. Flow Rules per Device: {avg_flows}")
        
        # Add port statistics for top devices
        result.append("\n## Port Statistics (Top 5 Devices)")
        
        # Sort devices by traffic volume
        device_traffic = {}
        for device_id, ports in port_stats.items():
            total_bytes = sum(p.get("bytesReceived", 0) + p.get("bytesSent", 0) for p in ports)
            device_traffic[device_id] = total_bytes
        
        # Show top 5 devices by traffic
        top_devices = sorted(device_traffic.items(), key=lambda x: x[1], reverse=True)[:5]
        
        for device_id, traffic in top_devices:
            result.append(f"\n### Device {device_id}")
            result.append(f"- Total Traffic: {traffic} bytes")
            
            # Show top 3 busiest ports
            ports = sorted(port_stats.get(device_id, []), 
                          key=lambda p: p.get("bytesReceived", 0) + p.get("bytesSent", 0),
                          reverse=True)[:3]
            
            result.append("#### Busiest Ports:")
            for port in ports:
                port_id = port.get("port", "")
                bytes_in = port.get("bytesReceived", 0)
                bytes_out = port.get("bytesSent", 0)
                packets_in = port.get("packetsReceived", 0)
                packets_out = port.get("packetsSent", 0)
                
                result.append(f"- Port {port_id}: {bytes_in + bytes_out} bytes, {packets_in + packets_out} packets")
        
        return "\n".join(result)
    except Exception as e:
        return f"Error retrieving network analytics: {str(e)}"

@mcp.tool()
async def get_system_health() -> str:
    """Get comprehensive system health information including memory usage and cluster status."""
    try:
        # Fetch system info and cluster details in parallel
        system_task = asyncio.create_task(make_onos_request("get", "/system"))
        cluster_task = asyncio.create_task(make_onos_request("get", "/cluster"))
        
        system_data = await system_task
        cluster_data = await cluster_task
        
        # Format system health report
        report = ["# ONOS System Health Report"]
        
        # System version and uptime
        version = system_data.get("version", "Unknown")
        uptime = system_data.get("uptime", "Unknown")
        report.append(f"\n## System Information")
        report.append(f"- Version: {version}")
        report.append(f"- Uptime: {uptime}")
        
        # Memory usage
        memory = system_data.get("memory", {})
        total_mem = memory.get("total", 0) / (1024 * 1024)  # Convert to MB
        used_mem = memory.get("used", 0) / (1024 * 1024)    # Convert to MB
        free_mem = memory.get("free", 0) / (1024 * 1024)    # Convert to MB
        
        report.append(f"\n## Memory Usage")
        report.append(f"- Total Memory: {total_mem:.2f} MB")
        report.append(f"- Used Memory: {used_mem:.2f} MB")
        report.append(f"- Free Memory: {free_mem:.2f} MB")
        report.append(f"- Memory Utilization: {(used_mem/total_mem*100) if total_mem > 0 else 0:.2f}%")
        
        # Cluster information
        report.append(f"\n## Cluster Status")
        nodes = cluster_data.get("nodes", [])
        for node in nodes:
            node_id = node.get("id")
            node_ip = node.get("ip")
            node_status = node.get("status", "Unknown")
            report.append(f"- Node {node_id} ({node_ip}): {node_status}")
        
        return "\n".join(report)
    except Exception as e:
        return f"Error retrieving system health: {str(e)}"

@mcp.tool()
async def add_meter(device_id: str, app_id: str, unit: str, burst: bool, bands: List[Dict[str, Any]]) -> str:
    """
    Add a meter to a device.
    
    Args:
        device_id: Device ID to add the meter to
        app_id: Application ID
        unit: Unit type (KB_PER_SEC or PKTS_PER_SEC)
        burst: Whether to use burst semantics
        bands: List of bands (each with type, rate, burst-size, and optionally prec/drop)
    """
    try:
        # Create meter data
        meter_data = {
            "deviceId": device_id,
            "appId": app_id,
            "unit": unit,
            "burst": burst,
            "bands": bands
        }
        
        # Add the meter
        result = await make_onos_request("post", f"/meters/{device_id}", json=meter_data)
        return f"Meter added successfully to device {device_id}"
    except Exception as e:
        return f"Error adding meter: {str(e)}"

@mcp.tool()
async def remove_meter(device_id: str, meter_id: str) -> str:
    """
    Remove a meter from a device.
    
    Args:
        device_id: Device ID
        meter_id: Meter ID to remove
    """
    try:
        await make_onos_request("delete", f"/meters/{device_id}/{meter_id}")
        return f"Meter {meter_id} removed successfully from device {device_id}"
    except Exception as e:
        return f"Error removing meter: {str(e)}"

@mcp.tool()
async def get_system_metrics() -> str:
    """Get summary of critical system and network metrics."""
    try:
        # Fetch metrics data
        metrics_data = await make_onos_request("get", "/metrics")
        
        # Extract key metrics
        report = ["# System Metrics Summary"]
        
        # Process metrics
        metrics = metrics_data.get("metrics", {})
        
        # Group metrics by category
        categories = {}
        for name, metric in metrics.items():
            category = name.split('.')[0] if '.' in name else 'Other'
            if category not in categories:
                categories[category] = []
            categories[category].append((name, metric))
        
        # Add metrics by category
        for category, metrics_list in sorted(categories.items()):
            report.append(f"\n## {category} Metrics")
            for name, metric in metrics_list[:10]:  # Limit to first 10 per category
                # Extract metric value based on type
                value = "N/A"
                if "counter" in metric:
                    value = f"Count: {metric['counter']['count']}"
                elif "gauge" in metric:
                    value = f"Value: {metric['gauge']['value']}"
                elif "histogram" in metric:
                    value = f"Mean: {metric['histogram']['mean']:.2f}, Max: {metric['histogram']['max']}"
                elif "meter" in metric:
                    value = f"Rate: {metric['meter']['meanRate']:.2f}/sec"
                elif "timer" in metric:
                    value = f"Mean: {metric['timer']['mean']:.2f}ms, Max: {metric['timer']['max']}ms"
                
                # Add to report
                report.append(f"- {name}: {value}")
        
        return "\n".join(report)
    except Exception as e:
        return f"Error retrieving system metrics: {str(e)}"

@mcp.tool()
async def send_packet(device_id: str, port: str, packet_data: str, packet_type: str = "ARP") -> str:
    """
    Send a packet out from a device port.
    
    Args:
        device_id: Device ID to send the packet from
        port: Port number to send the packet out of
        packet_data: Packet data in hex format
        packet_type: Type of packet (default: ARP)
    """
    try:
        packet_out_data = {
            "deviceId": device_id,
            "port": port,
            "type": packet_type,
            "data": packet_data
        }
        
        result = await make_onos_request("post", "/packet/sendout", json=packet_out_data)
        return f"Packet sent successfully from device {device_id}, port {port}"
    except Exception as e:
        return f"Error sending packet: {str(e)}"

@mcp.tool()
async def add_packet_processor(priority: int, app_id: str, processor_type: str, processor_name: str) -> str:
    """
    Add a packet processor.
    
    Args:
        priority: Priority of the processor (higher number = higher priority)
        app_id: Application ID that owns this processor
        processor_type: Type of processor (e.g., 'intercept', 'observe')
        processor_name: Name for the processor
    """
    try:
        processor_data = {
            "priority": priority,
            "appId": app_id,
            "type": processor_type,
            "name": processor_name
        }
        
        result = await make_onos_request("post", "/packet/processors", json=processor_data)
        return f"Packet processor '{processor_name}' added successfully with priority {priority}"
    except Exception as e:
        return f"Error adding packet processor: {str(e)}"

@mcp.tool()
async def add_group(device_id: str, app_id: str, group_type: str, buckets: List[Dict[str, Any]]) -> str:
    """
    Add a group to a device.
    
    Args:
        device_id: Device ID to add the group to
        app_id: Application ID
        group_type: Type of group (ALL, SELECT, INDIRECT, FAILOVER)
        buckets: List of buckets with actions
    """
    try:
        # Create group data
        group_data = {
            "deviceId": device_id,
            "appId": app_id,
            "type": group_type,
            "buckets": buckets
        }
        
        # Add the group
        result = await make_onos_request("post", f"/groups/{device_id}", json=group_data)
        return f"Group added successfully to device {device_id}"
    except Exception as e:
        return f"Error adding group: {str(e)}"

@mcp.tool()
async def remove_group(device_id: str, group_id: str) -> str:
    """
    Remove a group from a device.
    
    Args:
        device_id: Device ID
        group_id: Group ID to remove
    """
    try:
        await make_onos_request("delete", f"/groups/{device_id}/{group_id}")
        return f"Group {group_id} removed successfully from device {device_id}"
    except Exception as e:
        return f"Error removing group: {str(e)}"

@mcp.tool()
async def add_region(region_id: str, region_name: str, region_type: str) -> str:
    """
    Add a new region.
    
    Args:
        region_id: Region identifier
        region_name: Human-readable name for the region
        region_type: Type of region (e.g., METRO, CAMPUS, DATA_CENTER)
    """
    try:
        region_data = {
            "id": region_id,
            "name": region_name,
            "type": region_type
        }
        
        result = await make_onos_request("post", "/regions", json=region_data)
        return f"Region '{region_name}' added successfully with ID {region_id}"
    except Exception as e:
        return f"Error adding region: {str(e)}"

@mcp.tool()
async def add_device_key(device_id: str, device_key_type: str, key_value: str) -> str:
    """
    Add a device key.
    
    Args:
        device_id: Device identifier
        device_key_type: Type of key (e.g., COMMUNITY_NAME, USERNAME_PASSWORD)
        key_value: Value of the key
    """
    try:
        key_data = {
            "deviceKeyId": device_id,
            "type": device_key_type,
            "key": key_value
        }
        
        result = await make_onos_request("post", "/keys", json=key_data)
        return f"Key added successfully for device {device_id}"
    except Exception as e:
        return f"Error adding device key: {str(e)}"

@mcp.tool()
async def remove_device_key(device_id: str) -> str:
    """
    Remove a device key.
    
    Args:
        device_id: Device identifier
    """
    try:
        await make_onos_request("delete", f"/keys/{device_id}")
        return f"Key removed successfully for device {device_id}"
    except Exception as e:
        return f"Error removing device key: {str(e)}"

@mcp.tool()
async def run_diagnostics(diagnostics_command: str, timeout: int = 60) -> str:
    """
    Run a diagnostics command.
    
    Args:
        diagnostics_command: Command to run
        timeout: Command timeout in seconds
    """
    try:
        command_data = {
            "command": diagnostics_command,
            "timeout": timeout
        }
        
        result = await make_onos_request("post", "/diagnostics", json=command_data)
        return f"Diagnostics command executed successfully: {result}"
    except Exception as e:
        return f"Error running diagnostics: {str(e)}"

@mcp.tool()
async def add_flow_objective(device_id: str, objective_type: str, priority: int, timeout: int, permanent: bool, selector: Dict[str, Any], treatment: Dict[str, Any]) -> str:
    """
    Add a flow objective to a device.
    
    Args:
        device_id: Device ID to add the flow objective to
        objective_type: Type of objective (filter, forward, next)
        priority: Flow priority
        timeout: Flow timeout in seconds
        permanent: Whether the flow is permanent
        selector: Traffic selector criteria
        treatment: Traffic treatment instructions
    """
    try:
        objective_data = {
            "priority": priority,
            "timeout": timeout,
            "permanent": permanent,
            "selector": selector,
            "treatment": treatment
        }
        
        result = await make_onos_request("post", f"/flowobjectives/{device_id}/{objective_type}", json=objective_data)
        return f"{objective_type.capitalize()} objective added successfully to device {device_id}"
    except Exception as e:
        return f"Error adding flow objective: {str(e)}"

@mcp.tool()
async def add_multicast_route(source: str, group: str, sources: List[str], sinks: List[str]) -> str:
    """
    Add a multicast route.
    
    Args:
        source: Source address
        group: Multicast group address
        sources: List of source connection points
        sinks: List of sink connection points
    """
    try:
        route_data = {
            "source": source,
            "group": group,
            "sources": sources,
            "sinks": sinks
        }
        
        result = await make_onos_request("post", "/mcast", json=route_data)
        return f"Multicast route added successfully for group {group}"
    except Exception as e:
        return f"Error adding multicast route: {str(e)}"

@mcp.tool()
async def remove_multicast_route(route_id: str) -> str:
    """
    Remove a multicast route.
    
    Args:
        route_id: Route identifier
    """
    try:
        await make_onos_request("delete", f"/mcast/{route_id}")
        return f"Multicast route {route_id} removed successfully"
    except Exception as e:
        return f"Error removing multicast route: {str(e)}"

@mcp.tool()
async def set_device_mastership(device_id: str, node_id: str) -> str:
    """
    Set the master node for a device.
    
    Args:
        device_id: Device identifier
        node_id: Node identifier to set as master
    """
    try:
        mastership_data = {
            "nodeId": node_id
        }
        
        result = await make_onos_request("post", f"/mastership/{device_id}", json=mastership_data)
        return f"Device {device_id} mastership set to node {node_id}"
    except Exception as e:
        return f"Error setting device mastership: {str(e)}"

# Add prompts for common use cases
@mcp.prompt("diagnose-network-issue")
def diagnose_network_issue_prompt() -> str:
    """Prompt for diagnosing network issues in ONOS-managed networks."""
    return """
    # Network Issue Diagnosis
    
    I'll help you diagnose issues in your ONOS-managed network. To provide the most accurate diagnosis, please share:
    
    1. What symptoms are you experiencing? (e.g., connectivity loss, performance degradation)
    2. When did the issue start?
    3. Any recent changes to the network configuration or topology?
    4. Are there specific devices, hosts, or connections affected?
    
    I'll analyze your network and identify the likely causes and potential solutions.
    """

@mcp.prompt("design-network-flow")
def design_network_flow_prompt() -> str:
    """Prompt for designing and implementing network flows in ONOS."""
    return """
    # Network Flow Design
    
    I'll help you design and implement network flows using ONOS. Please provide:
    
    1. Your network goal (e.g., traffic isolation, load balancing, security)
    2. Source and destination details
    3. Traffic characteristics (protocol, port, etc.)
    4. Any specific routing requirements or constraints
    
    I'll create a flow design and help you implement it using ONOS flow rules.
    """

@mcp.prompt("configure-intent-based-networking")
def configure_intent_based_networking_prompt() -> str:
    """Prompt for setting up intent-based networking in ONOS."""
    return """
    # Intent-Based Networking Configuration
    
    I'll help you implement intent-based networking in ONOS. Please describe:
    
    1. Your connectivity objectives (e.g., host-to-host, point-to-multipoint)
    2. Traffic prioritization needs
    3. Any required traffic constraints or policies
    4. Resilience and failover requirements
    
    I'll guide you through setting up appropriate network intents to achieve your goals.
    """

@mcp.prompt("network-health-report")
def network_health_report_prompt() -> str:
    """Prompt for generating a comprehensive network health report."""
    return """
    # Network Health Report
    
    I'll generate a comprehensive health report for your ONOS-managed network, including:
    
    1. Overall network status
    2. Device availability and health
    3. Flow and intent statistics
    4. Traffic patterns and bottlenecks
    5. Potential issues and recommendations
    
    Would you like to focus on a specific aspect of the network, or would you prefer a complete overview?
    """

@mcp.prompt("sdn-migration-planning")
def sdn_migration_planning_prompt() -> str:
    """Prompt for planning migration to SDN with ONOS."""
    return """
    # SDN Migration Planning
    
    I'll help you plan your migration to Software-Defined Networking using ONOS. Let's discuss:
    
    1. Your current network architecture
    2. Migration goals and priorities
    3. Timeline and phasing considerations
    4. Critical applications and services
    5. Risk mitigation strategies
    
    I'll provide a structured migration plan tailored to your requirements.
    """

@mcp.prompt("system-health-check")
def system_health_check_prompt() -> str:
    """Prompt for comprehensive system health check of ONOS."""
    return """
    # ONOS System Health Check
    
    I'll perform a comprehensive health check of your ONOS system, including:
    
    1. System resource utilization (CPU, memory, etc.)
    2. Cluster node status
    3. Application health
    4. Performance metrics
    5. Potential bottlenecks or issues
    
    Would you like me to focus on any particular subsystem or component, or would you prefer a complete system overview?
    """

@mcp.prompt("metrics-analysis")
def metrics_analysis_prompt() -> str:
    """Prompt for analyzing ONOS metrics and performance."""
    return """
    # ONOS Metrics Analysis
    
    I'll analyze your ONOS system metrics to:
    
    1. Identify performance bottlenecks
    2. Highlight unusual patterns or anomalies
    3. Compare current metrics with historical baselines
    4. Recommend optimizations based on observed patterns
    
    Which specific metrics or parts of the system would you like me to focus on?
    """

@mcp.prompt("qos-configuration")
def qos_configuration_prompt() -> str:
    """Prompt for configuring Quality of Service using meters and flows."""
    return """
    # Quality of Service Configuration
    
    I'll help you implement QoS policies in your ONOS network using meters and flow rules:
    
    1. What type of traffic do you want to prioritize or limit?
    2. Are there specific applications, services, or hosts that need QoS guarantees?
    3. Do you need bandwidth guarantees, latency guarantees, or both?
    4. Are there different traffic classes with different requirements?
    
    I'll guide you through creating the appropriate meters and flow rules to implement your QoS requirements.
    """

@mcp.prompt("performance-tuning")
def performance_tuning_prompt() -> str:
    """Prompt for tuning ONOS for optimal performance."""
    return """
    # ONOS Performance Tuning
    
    I'll help you optimize your ONOS deployment for better performance:
    
    1. What performance issues are you currently experiencing?
    2. What's your current ONOS deployment architecture?
    3. Are you running a multi-node cluster?
    4. What network scale are you operating at (number of devices, flows, etc.)?
    
    Based on your situation, I'll recommend configuration changes, resource allocation adjustments, 
    and architectural improvements to enhance your ONOS performance.
    """

if __name__ == "__main__":
    mcp.run()
