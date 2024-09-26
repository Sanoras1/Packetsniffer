from scapy.all import *

# Define the parameters for filtering
TARGET_IP = "192.168.1.100"  # Change this to the IP address you want to block
MAX_PACKET_LENGTH = 105  # Change this to the maximum packet length you want to allow

def packet_filter(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        # Check if the source IP matches the target IP
        if  packet[IP].src == TARGET_IP and  packet[IP].len == MAX_PACKET_LENGTH:
            print(f"Dropping packet from {TARGET_IP}: {packet.summary()}")
            return False  # Drop the packet
        

       
    return True  # Keep the packet

def main():
    # Start sniffing packets
    print("Starting packet capture... (Press Ctrl+C to stop)")
    try:
        sniff(prn=lambda x: packet_filter(x), filter="ip and src host 192.168.1.181", store=0)
    except KeyboardInterrupt:
        print("\nPacket capture stopped.")

if __name__ == "__main__":
    main()
