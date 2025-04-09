from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.prompts.base import Message, UserMessage, AssistantMessage


def register_prompts(mcp_server: FastMCP):
    @mcp_server.prompt("list-topology")
    def list_topology() -> str:
        """
        Retrieve the network topology from the ONOS controller and summarize devices and links.
        In a production environment, this tool will query the ONOS REST API (/onos/v1/topology)
        and then generate a summary of switches, hosts, and connectivity gaps.
        """
        return (
            "Fetch current topology from the ONOS controller. Provide a summary listing all devices "
            "and highlight any detected connectivity gaps or anomalies."
        )

    @mcp_server.prompt("deploy-flow")
    def deploy_flow(
        deviceId: str, flowId: str, match: str, actions: str, priority: str = "default"
    ) -> str:
        """
        Deploy a flow rule on an ONOS device.
        Arguments:
          - deviceId: Unique identifier of the target device.
          - flowId: Unique identifier for the flow rule.
          - match: Criteria to match incoming traffic.
          - actions: Actions to perform when traffic matches.
          - priority: (Optional) Priority for the flow rule.
        """
        return (
            f"Deploy flow '{flowId}' on device '{deviceId}' with match criteria '{match}', "
            f"actions '{actions}', and priority '{priority}'."
        )

    @mcp_server.prompt("remove-flow")
    def remove_flow(deviceId: str, flowId: str) -> str:
        """
        Remove an existing flow rule from an ONOS device.
        Arguments:
          - deviceId: Unique identifier of the target device.
          - flowId: Unique identifier of the flow rule to remove.
        """
        return f"Remove the flow rule '{flowId}' from device '{deviceId}'."

    @mcp_server.prompt("debug-network-issue")
    def debug_network_issue(issueDescription: str, deviceId: str = "") -> list[Message]:
        """
        A multi-step workflow prompt for debugging network issues on the ONOS controller.
        Optionally focus on a single device if a deviceId is provided.
        Arguments:
          - issueDescription: A description of the observed network issue.
          - deviceId: (Optional) The device to focus on.
        Returns a sequence of messages for a human-in-the-loop workflow.
        """
        messages = []
        if deviceId:
            messages.append(UserMessage(f"Starting debug for device '{deviceId}'."))
        else:
            messages.append(UserMessage("Starting network-wide debug."))

        messages.append(UserMessage(f"Issue reported: {issueDescription}"))
        messages.append(
            AssistantMessage(
                "I will help analyze the issue. "
                "Please provide any additional details (e.g., log excerpts or error codes)."
            )
        )
        return messages

    @mcp_server.prompt("configure-qos-policy")
    def configure_qos_policy(
        deviceId: str, policyType: str, trafficClass: str, parameters: str
    ) -> str:
        """
        Create or update QoS policies for network traffic on an ONOS device.

        This prompt configures Quality of Service policies on ONOS-managed OpenFlow devices.
        The configuration will be applied through the ONOS northbound REST API
        (/onos/v1/flows/ or /onos/v1/meters/ depending on the policy type).

        Arguments:
          - deviceId: Device ID to apply QoS policy (format: of:0000000000000001)
          - policyType: Type of QoS policy:
              * meter: OpenFlow meter-based rate limiting
              * queue: Maps traffic to specific hardware queues
              * dscp: Differentiates traffic using DSCP marking
              * pcp: 802.1p priority code point for L2 QoS
          - trafficClass: Traffic class definition (e.g., "tcp,dstport=80", "ip,src=10.0.0.1/24", "arp")
          - parameters: Policy-specific parameters (JSON string)

        Examples:
          - Rate limit HTTP traffic:
            policyType="meter", trafficClass="tcp,dstport=80",
            parameters='{"rate":"100Mbps","burst":"10MB"}'

          - Priority queue for VoIP:
            policyType="queue", trafficClass="udp,dstport=5060",
            parameters='{"queueId":3,"minRate":"5Mbps","maxRate":"50Mbps"}'

          - DSCP marking for video streaming:
            policyType="dscp", trafficClass="udp,dstport=554",
            parameters='{"dscpValue":46}'
        """
        # Map policy types to ONOS treatments
        policy_treatments = {
            "meter": "applying meter-based rate limiting",
            "queue": "mapping to hardware queue with QoS guarantees",
            "dscp": "marking DSCP field in IP header",
            "pcp": "setting 802.1p priority bits",
        }

        treatment = policy_treatments.get(
            policyType, "applying custom QoS configuration"
        )

        return (
            f"Configuring QoS policy on device '{deviceId}' (using ONOS REST API)\n\n"
            f"Policy Type: {policyType}\n"
            f"Traffic Selector: {trafficClass}\n"
            f"Treatment: {treatment}\n"
            f"Parameters: {parameters}\n\n"
            f"The configuration will be translated to appropriate OpenFlow instructions "
            f"and applied to the device's flow tables. Monitor the ONOS log for confirmation "
            f"of successful application or any errors in policy deployment."
        )

    @mcp_server.prompt("optimize-qos-settings")
    def optimize_qos_settings(
        optimizationGoal: str, deviceId: str = ""
    ) -> list[Message]:
        """
        Analyze network traffic patterns and recommend QoS optimizations for ONOS-managed devices.
        Arguments:
          - optimizationGoal: Primary optimization target (e.g., throughput, latency, fairness, security).
          - deviceId: (Optional) Target specific device. If omitted, analyzes all devices in the network.
        Returns a structured multi-step message sequence for a guided optimization workflow.
        """
        valid_goals = ["throughput", "latency", "fairness", "security"]
        if optimizationGoal not in valid_goals:
            return [
                UserMessage(f"Invalid optimization goal: {optimizationGoal}"),
                AssistantMessage(
                    f"The optimization goal must be one of: {', '.join(valid_goals)}. "
                    "Please try again with a valid goal."
                ),
            ]

        messages = []

        messages.append(
            UserMessage(
                f"Analyze network traffic patterns and optimize QoS settings for {deviceId or 'all devices'} with the primary goal of improving {optimizationGoal}."
            )
        )

        return messages

    @mcp_server.prompt("general-network-prompt")
    def general_network_prompt(topic: str) -> str:
        """
        A general-purpose prompt for network administration tasks using ONOS.

        This prompt creates a context for helping network administrators manage OpenFlow networks
        with the ONOS controller, customized to a specific topic or task.

        Arguments:
          - topic: The specific networking topic or task to focus on (e.g., "routing",
                   "security policies", "traffic engineering", "troubleshooting").
        """
        return f"""
        You are an expert in OpenFlow networks and ONOS (Open Network Operating System).
        
        You are assisting a network administrator in managing and configuring an OpenFlow-based network using ONOS.
        The topic provided is: {topic}

        <network-info> The network currently has several OpenFlow switches connected to a ONOS controller. Each switch has a unique ID that identifies it. You can view the switches, their connections, and configure flow tables through this interface. </network-info>
        Your goal is to help the user analyze their network, configure it effectively, and solve any potential issues.

        <objectives> 1. Explore the network topology by listing connected switches 2. Examine details about specific switches 3. Configure flow tables to implement the requested network behavior 4. Analyze flow statistics to understand network traffic patterns 5. Document and explain network configurations for reference </objectives>
        Use the provided tools to interact with the ONOS controller and help manage this OpenFlow network.
        """
