# Import the sniff function from Scapy library.
from scapy.all import *

def capture_ethernet_frames(count=15):
    """
    Capture a specified number of Ethernet frames using the Scapy library.

    Args:
    - count (int): Number of Ethernet frames to capture, default is 15.

    Returns:
    - list: A list of captured packets, each item is a Scapy packet object.

    This function utilizes the sniff() function from Scapy to capture packets.
    It filters for Ethernet frames only ('ether' filter) and limits the capture
    to 'count' number of frames. Each captured frame is printed with a summary
    for quick inspection.
    """
    print("Starting packet capture") # Debug purpose

    # Sniff 'count' Ethernet frames. The filter 'ether' ensures only Ethernet frames are captured.
    packets = sniff(count=count)

    print("Packet capture done") # Debug purpose

    # Print a summary of each captured packet.
    for packet in packets:
        print(packet.summary())

    # Return the list of captured packets for further processing if needed.
    return packets


# The following code will only execute if this script is run directly (not imported as a module).
if __name__ == "__main__":
    # Call the capture function and store the returned list of packets
    captured_frames = capture_ethernet_frames(15)

