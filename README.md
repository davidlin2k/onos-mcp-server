# ONOS MCP Server

## Overview
A Model Context Protocol (MCP) server implementation that provides network control and management capabilities through the ONOS SDN controller. This server enables AI assistants to access ONOS network management, OpenFlow device control, and comprehensive analytics through a structured API interface. The server is ideal for educational environments, network operations, SDN research, and AI-assisted network management.

## Features

### Network Resources
The server provides access to ONOS REST API endpoints, including:

- Network devices, links, and hosts
- Topology information
- Flow rules and intents
- Applications and services
- Statistics and metrics
- System and cluster health

### Analytics Tools

- **Network Summary**: Get a comprehensive overview of devices, links, hosts, and clusters with detailed device information
- **Network Analytics**: Analyze performance metrics, traffic patterns, and utilization statistics
- **System Health**: Monitor memory usage, cluster status, and component health
- **Application Management**: Install, activate, deactivate, and uninstall ONOS applications
- **Flow Configuration**: Create and manage flow rules and intents
- **Path Computation**: Find optimal paths between network endpoints

### Specialized Prompts

- **Network Diagnostics**: Troubleshoot connectivity issues and service degradation
- **Intent-Based Configuration**: Implement connectivity objectives and policies
- **Network Health Analysis**: Generate comprehensive status reports
- **QoS Configuration**: Set up traffic prioritization and service levels
- **Performance Optimization**: Improve resource allocation and scalability

## Requirements

- Python 3.7+
- [uv](https://docs.astral.sh/uv/getting-started/installation/#standalone-installer) for dependency management
- Running ONOS controller
- httpx library
- mcp library

## Configuration

Configure the server using environment variables:

- `ONOS_API_BASE`: Base URL for ONOS API (default: http://localhost:8181/onos/v1)
- `ONOS_USERNAME`: Username for ONOS API authentication (default: onos)
- `ONOS_PASSWORD`: Password for ONOS API authentication (default: rocks)

## Usage with Claude Desktop

```json
{
  "mcpServers": {
    "onos": {
      "command": "uv",
      "args": [
        "--directory",
        "parent_of_servers_repo/servers/src/onos-mcp-server",
        "run",
        "server.py"
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

## Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.
