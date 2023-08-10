#! /usr/bin/env python
from multiprocessing import process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap)

import os, sys, time


#function to get the mac address of a target.
def get_mac(ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    else:
        return None
    
print(get_mac("10.0.4.1"))


'''
class Arper:
    def __init__(self, victim, gateway, interface="eth0"):
        pass

    def run(self):
        pass

    def poison(self):
        pass

    def sniff(self, count=200):
        pass

    def restore(self):
        pass

if __name__ == '__main__':
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arper(victim, gateway, interface)
    myarp.run()

'''