from scapy.all import IP, TCP, send

# Define the destination IP and port
destination_ip = "127.0.0.1"  # Replace with the IP address of the target
destination_port = 9999  # Replace with the port number of the target

# Message to send
message = "testing123"

# Create a custom TCP packet with the message as payload
packet = IP(dst=destination_ip) / TCP(dport=destination_port) / message

# Send the packet
send(packet)
