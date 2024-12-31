from CovertChannelBase import CovertChannelBase
from scapy.all import sniff, IP, UDP, DNS, DNSRR
import random

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        pass

    def send(self, log_file_name, receiver_ip):
        to_log = ""

        binary_message = self.generate_random_binary_message_with_logging(log_file_name, min_length=16, max_length=16)

        cnt = 8
        tmp = 0

        for bit in binary_message:
            if(str(bit) == '1'):
                tmp += cnt
            cnt //= 2
            if(cnt == 0):
                while(tmp > 0):
                    packet = IP(dst=receiver_ip) / UDP(dport=53) / DNS(an=DNSRR(type=1))
                    super().send(packet=packet)
                    tmp -= 1
                packet = IP(dst=receiver_ip) / UDP(dport=53) / DNS(an=DNSRR(type=5))
                super().send(packet=packet)
                cnt = 8
        
    def receive(self, log_file_name):
        buffer = ""
        decoded = ""
        flag = False

        def stop_filter(packet):
            return flag
        
        temp = 0
        def receive_packet(packet):
            nonlocal buffer, decoded, flag, temp
            def get_str(num):
                st = "{0:b}".format(num)
                while(len(st) < 4):
                    st = '0' + st
                return st
            if(packet.haslayer(DNS) and hasattr(packet[DNS], 'an')):
                atype = packet[DNS].an.type
                if(atype == 1):
                    temp += 1
                if(atype == 5):
                    st = get_str(temp)
                    buffer += st
                    temp = 0
                while(len(buffer) >= 8):
                    c = chr(int(buffer[:8], 2))
                    buffer = buffer[8:]
                    decoded += c
                    if(c == '.'):
                        flag = True
        
        sniff(prn=receive_packet, filter="udp port 53", stop_filter=stop_filter)

        self.log_message(decoded, log_file_name)
