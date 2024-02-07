# import json
# from datetime import datetime
# from scapy.all import sniff, IP, TCP

# # Define a list of signatures
# signatures = [
#     {"name": "Port Scan", "ports": [9999], "threshold": 5},
#     {"name": "SQL Injection", "pattern": "'; DROP TABLE", "case_sensitive": False},
# ]

# def match_signature(packet, signature):
#     if "ports" in signature:
#         # Check if the packet's source or destination port matches any in the signature
#         return packet[TCP].sport in signature["ports"] or packet[TCP].dport in signature["ports"]
#     elif "pattern" in signature:
#         # Check if the packet payload contains the signature pattern
#         payload = str(packet[TCP].payload)
#         if not signature.get("case_sensitive", True):
#             payload = payload.lower()
#         return signature["pattern"] in payload
#     return False

# def packet_handler(packet):
#     if packet.haslayer(IP) and packet.haslayer(TCP):
#         for signature in signatures:
#             if match_signature(packet, signature):
#                 alert = {
#                     "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#                     "alert": f"Suspicious activity detected - {signature['name']}",
#                     "source_ip": packet[IP].src,
#                     "source_port": packet[TCP].sport,
#                     "destination_ip": packet[IP].dst,
#                     "destination_port": packet[TCP].dport,
#                 }
#                 print(json.dumps(alert, indent=4))

# # Start sniffing on all interfaces
# sniff(prn=packet_handler, store=0, iface="lo", filter="tcp")


# import json
# from datetime import datetime
# from scapy.all import sniff, IP, TCP

# # Define the message to filter for
# filter_message = "testing123"

# def packet_handler(packet):
#     if packet.haslayer(IP) and packet.haslayer(TCP):
#         if packet[TCP].sport == 9999 or packet[TCP].dport == 9999:
#             payload = str(packet[TCP].payload)
#             if filter_message in payload:
#                 alert = {
#                     "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#                     "alert": f"Suspicious activity detected on port 9999 with message: {filter_message}",
#                     "source_ip": packet[IP].src,
#                     "source_port": packet[TCP].sport,
#                     "destination_ip": packet[IP].dst,
#                     "destination_port": packet[TCP].dport,
#                 }
#                 print(json.dumps(alert, indent=4))

# # Start sniffing on all interfaces
# sniff(prn=packet_handler, store=0, iface="lo", filter="tcp port 9999")

import json
from datetime import datetime
from scapy.all import sniff, IP, TCP

def process_packet(packet, filter_message, output_filename):
    alert = None  # Initialize alert to None
    if packet.haslayer(IP) and packet.haslayer(TCP):
        if filter_message in str(packet[TCP].payload):
            alert = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "alert": f"Suspicious activity detected with message: {filter_message}",
                "source_ip": packet[IP].src,
                "source_port": packet[TCP].sport,
                "destination_ip": packet[IP].dst,
                "destination_port": packet[TCP].dport,
            }
            with open(output_filename, "a") as file:
                file.write(json.dumps(alert, indent=4) + "\n")
    return alert

def start_ids(port, filter_message="testing123", output_filename="alerts.log"):
    print(f"IDS started on port {port}. It will stop automatically after 30 seconds.")
    sniff(prn=lambda packet: process_packet(packet, filter_message, output_filename), store=0, iface="lo", filter=f"tcp port {port}", timeout=30)
    print("IDS stopped after 30 seconds.")


