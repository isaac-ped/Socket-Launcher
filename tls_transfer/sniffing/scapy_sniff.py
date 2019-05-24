from scapy.all import *
import sys

sniff(iface=sys.argv[1], prn=lambda x: x.show())
