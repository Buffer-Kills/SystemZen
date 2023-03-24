from scapy.all import *

target_ip = "127.0.0.1"

start_port = 1
end_port = 1024

def scan_port(port):
    packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
    response = sr1(packet, timeout=1, verbose=0)
    if response is not None:
        if response.haslayer(TCP) and response[TCP].flags == 18:
            return True
    return False

open_ports = []
for port in range(start_port, end_port+1):
    if scan_port(port):
        open_ports.append(port)
        print("Port {} is open".format(port))

print("Open ports:", open_ports)