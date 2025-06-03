from scapy.all import sniff

def process_packet(packet):
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        print("========================================")
        print(f"Packet Captured")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
        print(f"Packet Summary: {packet.summary()}")
        print("========================================")

# Start sniffing packets
print("Starting the Network Sniffer...")
sniff(prn=process_packet, count=10)
