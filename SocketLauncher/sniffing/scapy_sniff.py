#!/usr/bin/env python
from scapy.all import *
import sys

def prn_fn(pkt):
    if TCP not in pkt:
        return

    pkt.show()
    chk1 = pkt[TCP].chksum
    del pkt[TCP].chksum

    pkt2 = Ether(str(pkt))
    if chk1 != pkt2[TCP].chksum:
        print("NONMATCH CHKSUM: %x %x" % (chk1, pkt2[TCP].chksum))
    else:
        print("MATCH CHKSUM")


sniff(iface=sys.argv[1], prn=prn_fn)
