# Network Packet Analyzer

This Python script is a simple network packet sniffer built using the scapy library. It captures live network traffic, extracts information such as source and destination IP addresses, and identifies the protocol (TCP/UDP). Additionally, it inspects packet payloads and provides a snippet of the data where applicable.

# Features

1)Capture and analyze network traffic in real-time.

2)Display source and destination IP addresses for each captured packet.

3)Identify TCP and UDP protocols for easy analysis.

4)View packet payload snippets for deeper inspection of data.

5)Supports capturing on a specific network interface or default to all available interfaces.

# Requirements

1)Python 3.x

2)scapy library

# Code Overview

1)capture_packet: Extracts key information from each packet, including IP addresses, protocol type, and payload if available.

2)run_sniffer: Starts the sniffer on the specified network interface and captures packets in real-time.

3)Main Execution: Prompts the user to specify the network interface, starts the sniffer, and handles termination with CTRL + C.

# Notes

This script uses the scapy library to capture and process network packets. Ensure that you have appropriate permissions to sniff network traffic on your system.

Disclaimer: Unauthorized network sniffing may be illegal in some jurisdictions. Ensure that you have explicit permission to monitor network traffic in your environment.

# Disclaimer

This tool should only be used in environments where you have explicit permission to monitor keyboard activity. Unauthorized monitoring of personal or corporate systems may be illegal.
