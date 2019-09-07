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

class DSRClient(object):

    def __init__(self, src_file = os.path.join(os.path.dirname(__file__), 'dsr_client.c')):
        self.b = BPF(src_file = src_file)
        self.n_servers = 0

    def run(self, iface):
        ing_fn= self.b.load_func('monitor_ingress', BPF.XDP)
        egr_fn= self.b.load_func('monitor_egress', BPF.SCHED_CLS)

        ip = IPRoute()
        ifindex = ip.get_links(ifname = iface)[0]['index']

        print("Ifindex of {} is {}".format(iface, ifindex))

        try:
            ip.tc('add', 'clsact', ifindex)
        except:
            print("Couldn't add clsact")

        self.b.remove_xdp(iface, 0)
        self.b.attach_xdp(iface, ing_fn, 0)

        ip.tc('add-filter', 'bpf', ifindex,
                fd = egr_fn.fd, name = egr_fn.name,
                parent ='ffff:fff3', class_id = 1,
                direct_action=True)
        try:
            time.sleep(1000)
        finally:
            self.b.remove_xdp(iface, 0)
            try:
                ip.tc('del', 'clsact', ifindex)
            except:
                print("Couldn't del clsact")

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('iface')

    args = parser.parse_args()

    p = DSRClient()
    p.run(args.iface)
