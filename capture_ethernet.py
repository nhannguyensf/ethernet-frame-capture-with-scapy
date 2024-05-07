from scapy.all import *

def capture_ethernet_frames(count=15):
    """
    Function to capture a specified number of Ethernet frames and analyze each frame for networking details.

    Args:
    - count (int): Number of Ethernet frames to capture, default is 15.

    Returns:
    - list: A list of captured packets, each item being a Scapy packet object with detailed network information extracted.

    This function uses Scapy's sniff() to capture packets and then analyzes each packet to extract MAC and IP details.
    It prints a summary along with the source and destination MAC addresses, and if available, IP version, source IP, and
    destination IP addresses.
    """
    
    print("Starting packet capture")  # Notify user that packet capture is starting

    # Capture 'count' Ethernet frames using Scapy's sniff function. The capture can be filtered using 'filter' parameter if necessary.
    packets = sniff(count=count)
    print("Packet capture done")  # Notify user that packet capture has finished

    # Process each packet to extract and print details
    i = 0
    for packet in packets:
        print(f"\n--- Packet Summary {i+1}: ---")
        print(packet.summary())  # Print a brief summary of each packet

        # Extract and display the source and destination MAC addresses from the Ethernet layer of the packet
        if packet.haslayer(Ether):
            src_mac = packet[Ether].src  # Source MAC address
            dst_mac = packet[Ether].dst  # Destination MAC address
            print(f"Source MAC: {src_mac}, Destination MAC: {dst_mac}")

        # Check if the packet contains an IP layer and extract details if present
        if packet.haslayer(IP):
            ip_layer = packet[IP]  # Access the IP layer of the packet
            print(f"IP Version: {ip_layer.version}")  # Print the IP version (IPv4 or IPv6)
            print(f"Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}")  # Print source and destination IP addresses
        i+=1
    print("\n------- Packet analyzing finished! -------\n")  # Notify user that packet analyzing has finished
    # Return the list of captured packets for possible further processing
    return packets

# Ensures that the capture function is only executed when the script is run directly
if __name__ == "__main__":
    captured_frames = capture_ethernet_frames(15)  # Capture and analyze 15 Ethernet frames
