import socket 
from scapy.all import *
import logging

namePCAPFile = 'file1.pcap'

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def show_and_select_interface():
    print("Hello!\nSelect the network's adapter please!")
    i = 0
    for s in socket.if_nameindex():
        print(f"{i+1} - {s[1]}")
        i+=1

    n_interf = int(input("Insert a number: "))

    while (n_interf>len(socket.if_nameindex()) or n_interf <= 0):
        logging.error("The interface doesn't exists")
        n_interf = int(input("Error! Please insert a valid number: "))  

    return  n_interf

    
def sniff_the_traffic(interface):
    capture = sniff(iface=interface, count=50) 
    print(type(capture))
    print(capture.summary())
    for p in capture:
        wrpcap(namePCAPFile, [p], append=True)

def analyse_capture():
    packets_dict = {}
    scapy_cap = PcapReader(namePCAPFile)
    for packet in scapy_cap:
        if IP in packet:
            #print(packet[IP].src)
            #Se e un pacchetto SYN e l'ip sorgente non e' presente lo metto nel dizionario
            if TCP in packet and packet[TCP].flags=='S':
                 
                if packet[IP].src not in packets_dict:
                    packets_dict[packet[IP].src] = {}
                if packet[TCP].dport not in packets_dict[packet[IP].src]:
                        packets_dict[packet[IP].src][packet[TCP].dport] = {}
                if packet[TCP].sport not in packets_dict[packet[IP].src][packet[TCP].dport]:
                        packets_dict[packet[IP].src][packet[TCP].dport][packet[TCP].sport] = {'SYN_ACK': 0, 'ACK':0, 'SYN':1, 'RST':0}
                else:
                    packets_dict[packet[IP].src][packet[TCP].dport][packet[TCP].sport]['SYN'] +=1

            if TCP in packet and packet[TCP].flags=='SA': 
                if packet[IP].dst in packets_dict:
                    if packet[TCP].sport in packets_dict[packet[IP].dst]:
                        if packet[TCP].dport in packets_dict[packet[IP].dst][packet[TCP].sport]:
                            packets_dict[packet[IP].dst][packet[TCP].sport][packet[TCP].dport]['SYN_ACK'] +=1

            if TCP in packet and packet[TCP].flags=='A': 
                if packet[IP].src in packets_dict:
                    if packet[TCP].dport in packets_dict[packet[IP].src]:
                        if packet[TCP].sport in packets_dict[packet[IP].src][packet[TCP].dport]:
                            packets_dict[packet[IP].src][packet[TCP].dport][packet[TCP].sport]['ACK'] +=1
            
            """if TCP in packet and packet[TCP].flags=='R': 
                if packet[IP].src in packets_dict:
                    if packet[TCP].dport in packets_dict[packet[IP].src]:
                        if packet[TCP].sport in packets_dict[packet[IP].src][packet[TCP].dport]:
                            packets_dict[packet[IP].src][packet[TCP].dport][packet[TCP].sport]['RST'] +=1"""

    
    return packets_dict  


def check_syn_flood_Attack(packets_dict):
    count = 0
    for ip in packets_dict:
        
        for dport in packets_dict[ip]:
            for sport in packets_dict[ip][dport]:
                if packets_dict[ip][dport][sport]['ACK']==0 and packets_dict[ip][dport][sport]['RST'] == packets_dict[ip][dport][sport]['ACK']:
                    count +=1

            if count == len(packets_dict[ip][dport]):
                print(f'Dall\'indirizzo {ip} sulla porta {dport} si e\' registrato un attacco SYN FLOOD')
            else:
                print("Nessun attacco e' stato registrato")

       


if __name__=="__main__":
    n_interf = show_and_select_interface()
    interface = socket.if_nameindex()[n_interf-1][1]
    print(f"The network adapter selected is: {interface}")
    sniff_the_traffic(interface)
    packets_dict = analyse_capture()
    check_syn_flood_Attack(packets_dict)
