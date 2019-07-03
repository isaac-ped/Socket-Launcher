#!/usr/bin/env python
import ctypes as ct
from bcc import BPF
import socket
import os
import struct
import argparse
from pyroute2 import IPRoute
import time

def ip2int(addr):
    return socket.htonl(struct.unpack('!I', socket.inet_aton(addr))[0])

class DstServer(ct.Structure):
    _pack_ = 1
    _fields_ = [
            ('h_dest', ct.c_char * 6),
            ('addr', ct.c_uint32)
    ]

class Switch(object):

    def __init__(self, src_file = os.path.join(os.path.dirname(__file__), 'switch.c')):
        self.b = BPF(src_file = src_file)
        self.ifaces = []

    def add_iface(self, ip, iface):
        self.ifaces.append(iface)
        ipr = IPRoute()
        ifindex = ipr.get_links(ifname = iface)[0]['index']

        self.b['devmap'][ct.c_uint32(len(self.ifaces))] = ct.c_int(ifindex)

        self.b['ip_map'][ct.c_uint32(ip2int(ip))] = ct.c_uint32(len(self.ifaces))

        self.ifaces.append(iface)

    def run(self):

        ing_fn= self.b.load_func('monitor_ingress', BPF.XDP)

        for iface in self.ifaces:
            ip = IPRoute()
            ifindex = ip.get_links(ifname = iface)[0]['index']

            self.b.remove_xdp(iface, 0)
            self.b.attach_xdp(iface, ing_fn, 0)

        try:
            time.sleep(1000)
        finally:
            for iface in self.ifaces:
                self.b.remove_xdp(iface, 0)

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('iface_ip', nargs="+")

    args = parser.parse_args()

    s = Switch()
    for ifip in args.iface_ip:
        s.add_iface(ifip.split(":")[1], ifip.split(":")[0])
    s.run()
