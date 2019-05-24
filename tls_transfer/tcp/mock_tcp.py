from scapy.all import *
from pyroute2 import IPRoute
import argparse
import getmac

def open_connection(iface, srcip, srcport, dstmac, dstip, dstport):

    srcmac = getmac.get_mac_address(iface)
    eth_hdr = Ether(dst=dstmac, src=srcmac)

    ip_hdr = eth_hdr/IP(src=srcip, dst=dstip)

    syn = TCP(dport=dstport, sport=srcport, ack=0, seq=1, flags="S")

    response = srp1(ip_hdr/syn, iface=iface)

    response.show2()

    ack = TCP(dport=dstport, sport=srcport, ack=response.seq+1, seq=2, flags="A")

    response = srp1(ip_hdr / ack, iface=iface)
    response.show2()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('iface')
    parser.add_argument('srcip')
    parser.add_argument('srcport', type=int)
    parser.add_argument('dstmac')
    parser.add_argument('dstip')
    parser.add_argument('dstport', type=int)
    args = parser.parse_args()

    open_connection(args.iface, args.srcip, args.srcport,
                    args.dstmac, args.dstip, args.dstport)
