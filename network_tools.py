import pyinputplus as pyip
from scapy.all import *
import pyfiglet 
import socket 
from datetime import datetime 
from tqdm import tqdm
from fuzzing.fuzzer import FuzzExecutor

class NetworkTools():
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

    def tcp_port_scanner(self):
        ascii_banner = pyfiglet.figlet_format("PORT SCANNER") 
        print(ascii_banner) 
        
        target = pyip.inputStr('host name: ')
        
        # Add Banner  
        print("-" * 50) 
        print("Scanning Target: " + target) 
        print("Scanning started at:" + str(datetime.now())) 
        print("-" * 50) 
        
        try: 
            
            # will scan ports between 1 to 65,535 
            for port in tqdm(range(1,65535)): 
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
                socket.setdefaulttimeout(1) 
                
                # returns an error indicator 
                result = s.connect_ex((target,port)) 
                if result ==0: 
                    print("\nPort {} is open".format(port)) 
                s.close() 
                
        except KeyboardInterrupt: 
            print("\n Exitting Program !!!!") 
        except socket.gaierror: 
            print("\n Hostname Could Not Be Resolved !!!!") 
        except socket.error: 
            print("\n Server not responding !!!!") 


        return

    @classmethod
    def writeLog(client, data=''):
        separator = '='*50
        fopen = open('./honey.mmh', 'a')
        fopen.write('Time: %s\nIP: %s\nPort: %d\nData: %s\n%s\n\n'%(str(datetime.now()), client[0], client[1], data, separator))
        print('Time: %s\nIP: %s\nPort: %d\nData: %s\n%s\n\n'%(str(datetime.now()), client[0], client[1], data, separator))
        fopen.close()

    def honeypot(self):
        ascii_banner = pyfiglet.figlet_format("HONEYPOT") 
        print(ascii_banner) 

        motd = input('MOTD: ')
        host = input('IP Address: ')
        while True:
            try:
                port = int(input('Port: '))
            except TypeError:
                print('Error: Invalid port number.')
                continue
            else:
                if (port < 1) or (port > 65535):
                    print('Error: Invalid port number.')
                    continue
                else:
                    print(host, port, motd)
                    break

        print('Starting honeypot!')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen(100)
        while True:
            (insock, address) = s.accept()
            print('Connection from: %s:%d' % (address[0], address[1]))
            try:
                insock.send('%s\n'%(motd))
                data = insock.recv(1024)
                insock.close()
            except(socket.error,e):
                NetworkTools.writeLog(address)
            else:
                NetworkTools.writeLog(address, data)


# net = NetworkTools()
# net.tcp_port_scanner()


# import fuzzing
# seed = "This could be the content of a huge text file."
# number_of_fuzzed_variants_to_generate = 10
# fuzz_factor = 7
# fuzzed_data = fuzzing.fuzz_string(seed, number_of_fuzzed_variants_to_generate, fuzz_factor)
# print(fuzzed_data)


# Files to use as initial input seed.
file_list = ["download.png", 'main.py']

# List of applications to test.
apps_under_test = ["Google Chrome.Ink", "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"]

number_of_runs = 13

def test():
    fuzz_executor = FuzzExecutor(apps_under_test, file_list)
    fuzz_executor.run_test(number_of_runs)
    return fuzz_executor.stats

# def main():
#     for i in file_list:
#         with open(i,'r+') as f:
#             print(f)

#     stats = test()
#     print(stats)

