#!/usr/bin/env python
from scapy.all import *
import sys

def prn_fn(pkt):
    if TCP not in pkt:
        return

    print("Seq: 0x%x (%d)" % (pkt[TCP].seq, pkt[TCP].seq))
    print("Ack: 0x%x (%d)" % (pkt[TCP].ack, pkt[TCP].ack))


sniff(iface=sys.argv[1], prn=prn_fn)
