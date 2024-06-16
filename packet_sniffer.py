from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine protocol type
        if proto == 6:
            protocol = 'TCP'
        elif proto == 17:
            protocol = 'UDP'
        else:
            protocol = 'Other'

        # Extract payload data if present
        payload_data = ''
        if Raw in packet:
            payload_data = packet[Raw].load

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        if payload_data:
            print(f"Payload Data: {payload_data}")
        print("="*50)

# Sniff the network and use the callback function to process each packet
sniff(prn=packet_callback, filter="ip", store=0)
