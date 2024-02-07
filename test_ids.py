import pytest
from scapy.all import send, IP, TCP

# Dynamically generate tests for different ports
ports = [10000 + i for i in range(100)]

@pytest.mark.parametrize("port", ports)
def test_ids_on_port(port):
    destination_ip = "127.0.0.1"
    message = "testing123"
    packet = IP(dst=destination_ip) / TCP(dport=port) / message
    send(packet)
    # Implement logic to verify that the IDS instance detected the packet
    # This might involve reading from the output file specific to the port and checking for an alert
