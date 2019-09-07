#!/usr/bin/env python
from scapy.all import *
import sys

def prn_fn(pkt):
    pkt.show()
    if IP not in pkt:
        return

    chk1 = pkt[IP].chksum
    del pkt[IP].chksum
    del pkt[IP].len
    if TCP in pkt:
        chk2 = pkt[TCP].chksum
        del pkt[TCP].chksum

    pkt2 = Ether(str(pkt))
    if chk1 != pkt2[IP].chksum:
        print("NONMATCH IP CHKSUM: %x %x" % (chk1, pkt2[IP].chksum))
    else:
        print("MATCH CHKSUM")

    if TCP in pkt and chk2 != pkt2[TCP].chksum:
        print("NONMATCH TCP CHKSUM: %x %x" % (chk2, pkt2[TCP].chksum))
    else:
        print("MATCH CHECKSUM")

if len(sys.argv) == 3:
    for pkt in rdpcap(sys.argv[2]):
        prn_fn(pkt)

sniff(iface=sys.argv[1], prn=prn_fn)
