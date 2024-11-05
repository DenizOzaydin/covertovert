from scapy.all import *

def check(packet):
    if packet.haslayer(ICMP) and packet[IP].ttl == 1:
        packet.show()
        return True

def receive():
    sniff(filter="icmp", prn=check, stop_filter=check)
    return True

if __name__ == "__main__":
    receive()