# POX MCP Server

## Overview
A Model Context Protocol (MCP) server implementation that provides network control and management capabilities through the POX SDN controller. This server enables Python-based network programming, OpenFlow device management, and automated network analysis through POX's modular architecture. Perfect for educational environments, network prototyping, and SDN research.

## Components

### Resources
The server exposes two dynamic resources:
- `pox://network-config`: A comprehensive POX controller configuration memo
  - Tracks active POX components and their configurations
  - Records network topology and flow rules
  - Maintains discovered network insights
- `pox://topology`: Real-time network topology view
  - Shows active OpenFlow datapaths (switches)
  - Maps host locations and connections
  - Displays link status and port mappings

### Prompts
The server provides three specialized prompts:
- `pox-network-manager`: Interactive prompt for POX controller management
  - Required argument: `topic` - The network control aspect to focus on
  - Helps configure POX components and modules
  - Guides through network policy implementation
  - Integrates with network configuration memo

- `simple-hub`: Basic L2 hub implementation using POX
  - Required argument: `dpid` - The datapath identifier
  - Demonstrates POX's event-driven programming
  - Shows basic packet handling and flooding
  - Explains POX's core mechanisms

- `learning-switch`: L2 learning switch implementation
  - Required argument: `dpid` - The datapath identifier
  - Showcases POX's table management
  - Implements MAC learning and forwarding
  - Demonstrates POX's packet handling capabilities

### Tools
The server offers five core tools:

#### Datapath Management Tools
- `get_switches`
   - List all connected OpenFlow datapaths
   - No input required
   - Returns: Array of active POX-controlled switches
   - Includes connection status and capabilities

- `get_switch_desc`
   - Get detailed datapath information
   - Input:
     - `dpid` (string): Datapath identifier
   - Returns: POX-managed switch details and features

#### Flow Management Tools
- `get_flow_stats`
   - Retrieve POX flow statistics
   - Input:
     - `dpid` (string): Datapath identifier
     - `match` (object, optional): POX match structure
     - `table_id` (string, optional): OpenFlow table ID
     - `out_port` (string, optional): Output port filter
   - Returns: POX flow statistics including packet counts

- `set_table`
   - Configure POX flow tables
   - Input:
     - `dpid` (string): Datapath identifier
     - `flows` (array): POX flow specifications
   - Returns: Flow table update confirmation

#### Analysis Tools
- `append_insight`
   - Add network insights to POX configuration memo
   - Input:
     - `insight` (string): Network observation or analysis
   - Returns: Insight addition confirmation
   - Updates pox://network-config resource

## Usage with Claude Desktop

### uv

```json
# Add the server to your claude_desktop_config.json
{
  "mcpServers": {
    "pox": {
      "command": "uv",
      "args": [
        "--directory",
        "parent_of_servers_repo/servers/src/mcp_server_pox",
        "run",
        "server.py"
      ],
      "env": {
        "POX_SERVER_URL": "http://localhost:8000"
      }
    }
  }
}
```

## License

This MCP server is licensed under the MIT License. This means you are free to use, modify, and distribute the software, subject to the terms and conditions of the MIT License. For more details, please see the LICENSE file in the project repository.

## Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.
