import socket 
from scapy.all import *
import logging

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
    capture = sniff(iface=interface, count=5000) 
    print(type(capture))
    input()
    print(capture.summary())
    for p in capture:
        wrpcap('file1.pcap', [p], append=True)



if __name__=="__main__":
    n_interf = show_and_select_interface()
    interface = socket.if_nameindex()[n_interf-1][1]
    print(f"The network adapter selected is: {interface}")
    sniff_the_traffic(interface)