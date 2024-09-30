import scapy.all as scapy

def capture_packet(packet):
    """
    Processes a captured packet and extracts relevant information such as IP addresses, protocol, and payload.
    
    Args:
        packet: The network packet captured.
    """
    # Check if packet has IP layer
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        dest_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        # Display source and destination IPs
        print(f"[{source_ip}] -> [{dest_ip}]", end=" ")

        # Check for TCP/UDP protocols
        if protocol == 6 and packet.haslayer(scapy.TCP):
            print("[TCP Protocol]", end=" ")
        elif protocol == 17 and packet.haslayer(scapy.UDP):
            print("[UDP Protocol]", end=" ")

        # Check for payload and print a snippet
        if packet.haslayer(scapy.Raw):
            payload_content = packet[scapy.Raw].load[:50]  # Show a portion of the payload
            print(f"Payload: {payload_content}")
        else:
            print("No Payload")

def run_sniffer(network_interface=None):
    """
    Initiates the packet sniffer, capturing packets on the specified network interface.
    
    Args:
        network_interface: The interface to listen on (e.g., 'eth0'). Defaults to None for all interfaces.
    """
    print(f"Listening on interface: {network_interface or 'default interface'}")
    scapy.sniff(iface=network_interface, prn=capture_packet, store=False)

if __name__ == "__main__":
    try:
        # Get interface from user, default if left blank
        network_interface = input("Enter the interface to sniff (or press Enter for default): ").strip()
        
        # Start the sniffer
        run_sniffer(network_interface if network_interface else None)

    except KeyboardInterrupt:
        print("\nSniffer terminated.")
    except Exception as error:
        print(f"Error: {error}")
