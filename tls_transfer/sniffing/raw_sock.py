#!/usr/bin/env python
import socket
from scapy.all import *

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.bind(('13.0.0.1',0))
while True:
    packet = s.recv(4096)
    pkt= IP(packet)
    pkt.show()
    chk1 = pkt['TCP'].chksum
    del pkt['TCP'].chksum
    del pkt[IP].chksum
    pkt2= Ether(dst='00:00:00:00:00:bb', src='00:00:00:00:bb:bb') / IP(str(pkt))
    pkt2.show()

    if chk1 != pkt2[TCP].chksum:
        print("NON MATCHING CHECKSUMS: %x %x" % (chk1,pkt2[TCP].chksum))
    else:
        print("MATCHING CHECKSUMS: %x %x" % (chk1, pkt2[TCP].chksum))
