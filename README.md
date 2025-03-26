# ONOS MCP Server

## Overview
A Model Context Protocol (MCP) server implementation that provides network control and management capabilities through the ONOS SDN controller. This server enables programmatic access to ONOS network management, OpenFlow device control, and comprehensive analytics through ONOS's REST API. Perfect for educational environments, network prototyping, and SDN research with ONOS.

## Components

### Resources
The server exposes over 30 dynamic resources, including:
- `onos://devices`: Information about all network devices
- `onos://device/{deviceId}`: Detailed information about a specific device
- `onos://links`: Information about all network links
- `onos://hosts`: Information about all hosts connected to the network
- `onos://topology`: Overview of current network topology
- `onos://applications`: Information about all installed applications
- `onos://flows/{deviceId}`: All flow entries for a specific device
- `onos://system`: High-level system information, version, and memory usage
- `onos://metrics`: Statistics information for all metrics
- `onos://meters/{deviceId}`: All meter entries for a specific device
- `onos://intents`: All intents in the system
- `onos://statistics/*`: Various statistics resources for ports, flows, and tables
- `onos://network/configuration`: The entire network configuration
- `onos://configuration`: Component configurations
- And many more for comprehensive ONOS system access

### Prompts
The server provides nine specialized prompts:
- `diagnose-network-issue`: Interactive prompt for diagnosing network issues
  - Helps identify connectivity problems and service degradation
  - Analyzes network symptoms and changes
  - Suggests targeted solutions

- `design-network-flow`: Assistance for designing and implementing network flows
  - Helps create traffic isolation, load balancing, and security policies
  - Guides source/destination flow creation
  - Supports specific routing requirements

- `configure-intent-based-networking`: Support for intent-based networking
  - Guides connectivity objectives implementation
  - Helps with traffic prioritization
  - Assists with resilience and failover configuration

- `network-health-report`: Comprehensive network status analysis
  - Provides device availability reporting
  - Delivers flow and intent statistics
  - Identifies bottlenecks and performance issues

- `sdn-migration-planning`: Planning for SDN migration with ONOS
  - Helps assess current architecture
  - Guides through migration goals and priorities
  - Develops phased implementation strategies

- `system-health-check`: System-level diagnostics for ONOS
  - Analyzes resource utilization
  - Reports cluster status
  - Evaluates component health

- `metrics-analysis`: Deep analysis of ONOS metrics
  - Identifies performance bottlenecks
  - Highlights anomalies
  - Recommends optimizations

- `qos-configuration`: Quality of Service implementation guidance
  - Helps prioritize traffic types
  - Assists with bandwidth and latency guarantees
  - Creates class-based service levels

- `performance-tuning`: Optimization for ONOS deployments
  - Resolves performance issues
  - Enhances resource allocation
  - Improves architecture for scale

### Tools
The server offers over 20 powerful tools, including:

#### Network Management Tools
- `get_network_summary`
   - Get a high-level summary of the network including devices, links, and hosts
   - No input required
   - Returns comprehensive network overview with device details

- `get_network_analytics`
   - Get analytics about network performance, utilization and health
   - No input required
   - Returns detailed performance metrics and utilization statistics

- `get_system_health`
   - Get comprehensive system health information including memory usage and cluster status
   - No input required
   - Returns detailed health report with memory utilization and node status

#### Application Management Tools
- `install_application`
   - Install a new ONOS application from an OAR file URL
   - Input: `app_file_url` (string)
   - Returns installation status

- `activate_application`
   - Activate an ONOS application
   - Input: `app_name` (string)
   - Returns activation status

- `deactivate_application`
   - Deactivate an ONOS application
   - Input: `app_name` (string)
   - Returns deactivation status

- `remove_application`
   - Uninstall an ONOS application
   - Input: `app_name` (string)
   - Returns removal status

#### Network Configuration Tools
- `add_flow`
   - Add a flow rule to a device
   - Input: device ID, priority, timeout, etc.
   - Returns flow addition status

- `remove_flow`
   - Remove a flow rule from a device
   - Input: device ID and flow ID
   - Returns removal status

- `add_intent`
   - Add a host-to-host intent
   - Input: app ID, priority, source and destination hosts
   - Returns intent creation status

- `get_shortest_path`
   - Find the shortest path between two devices or hosts
   - Input: source and destination IDs
   - Returns detailed path information

#### Other tools
Additional tools for device configuration, QoS management, diagnostics, and more.

## Usage with Claude Desktop

```json
# Add the server to your claude_desktop_config.json
{
  "mcpServers": {
    "onos": {
      "command": "python",
      "args": [
        "src/onos-mcp-server/server.py"
      ],
      "env": {
        "ONOS_API_BASE": "http://localhost:8181/onos/v1",
        "ONOS_USERNAME": "onos",
        "ONOS_PASSWORD": "rocks"
      }
    }
  }
}
```

## Requirements
- Python 3.7+
- ONOS controller (running and accessible)
- httpx library
- mcp library

## Configuration
The server uses the following environment variables:
- `ONOS_API_BASE`: Base URL for ONOS API (default: http://localhost:8181/onos/v1)
- `ONOS_USERNAME`: Username for ONOS API authentication (default: onos)
- `ONOS_PASSWORD`: Password for ONOS API authentication (default: rocks)

## License

This MCP server is licensed under the MIT License. This means you are free to use, modify, and distribute the software, subject to the terms and conditions of the MIT License. For more details, please see the LICENSE file in the project repository.

## Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.
