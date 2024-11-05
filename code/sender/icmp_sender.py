from scapy.all import *

def send_packet(ip):
    packet = IP(dst=ip, ttl=1) / ICMP()
    send(packet)

if __name__ == "__main__":
    send_packet("receiver")