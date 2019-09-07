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
            ('addr', ct.c_uint32)
    ]

class DSRProxy(object):

    def __init__(self, src_file = os.path.join(os.path.dirname(__file__), 'dsr_proxy.c')):
        self.b = BPF(src_file = src_file)
        self.n_servers = 0

    def add_server(self, ip):
        structip = ip2int(ip)

        server = DstServer(structip)

        self.b['dst_servers'][self.n_servers] = server
        self.b['n_dst_servers'][0] = ct.c_uint(self.n_servers+1)
        self.n_servers += 1

    def add_port(self, port):
        ctport = ct.c_uint16(socket.htons(port))
        self.b['active_ports'][ctport] = ct.c_uint32(1)

    def run(self, iface):
        ing_fn= self.b.load_func('monitor_ingress', BPF.XDP)

        ip = IPRoute()
        ifindex = ip.get_links(ifname = iface)[0]['index']

        print("Ifindex of {} is {}".format(iface, ifindex))

        try:
            ip.tc('add', 'clsact', ifindex)
        except:
            print("Couldn't add clsact")

        self.b.attach_xdp(iface, ing_fn, 0)
        '''
        ip.tc('add-filter', 'bpf', ifindex,
                fd = ing_fn.fd, name = ing_fn.name,
                parent ='ffff:fff2', class_id = 1,
                direct_action=True)
                '''
        try:
            time.sleep(1000)
        finally:
            try:
                ip.tc('del', 'clsact', ifindex)
            except:
                print("Couldn't del clsact")

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('iface')
    parser.add_argument('port', type=int)
    parser.add_argument('ip', nargs='+')

    args = parser.parse_args()

    p = DSRProxy()
    p.add_port(args.port)
    for ip in args.ip:
        print(ip)
        p.add_server(ip)
    p.run(args.iface)
