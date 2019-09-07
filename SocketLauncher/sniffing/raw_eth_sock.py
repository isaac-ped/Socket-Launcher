#!/usr/bin/env python
import socket
from scapy.all import *

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind(('h3-eth0',0))
while True:
    packet = s.recv(4096)
    pkt= Ether(packet)
    pkt.show()
    if TCP in pkt:
        chk1 = pkt['TCP'].chksum
        del pkt['TCP'].chksum
        pkt2= Ether(str(pkt))

        if chk1 != pkt2[TCP].chksum:
            print("NON MATCHING CHECKSUMS: %x %x" % (chk1,pkt2[TCP].chksum))

