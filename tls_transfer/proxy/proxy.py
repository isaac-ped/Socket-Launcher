#!/usr/bin/env python
import ctypes as ct
from bcc import BPF
import socket
import os
import struct
import argparse
from pyroute2 import IPRoute
import time
import zmq
import json


def ip2int(addr):
    return socket.htonl(struct.unpack('!I', socket.inet_aton(addr))[0])

class DstAddr(ct.Structure):
    _pack_ = 1
    _fields_ = [
            ('addr', ct.c_uint32),
            ('port', ct.c_uint16)
    ]

class OutFlow(ct.Structure):
    _pack_ = 1
    _fields_ = [
            ('srcport', ct.c_uint16),
            ('dstport', ct.c_uint16)
    ]

class Flow(ct.Structure):
    _pack_ = 1
    _fields_ = [
            ('srcaddr', ct.c_uint32),
            ('srcport', ct.c_uint16),
            ('dstport', ct.c_uint16)
    ]

class Proxy(object):

    def __init__(self, src_file = os.path.join(os.path.dirname(__file__), 'proxy.c')):
        try:
            os.mkdir('/tmp/tsproxy');
        except OSError:
            pass
        ctx = zmq.Context()
        self.sock_loc = 'ipc:///tmp/tsproxy/0'
        self.sock = ctx.socket(zmq.REP)
        self.sock.bind(self.sock_loc)
        print("Bound sock to %s" % self.sock_loc)

        self.b = BPF(src_file = src_file)
        self.n_servers = 0

    def add_server(self, ip, port, id=None):
        print("Adding server at %s:%d" % (ip, port))
        structip = ip2int(ip)
        server = DstAddr(structip, ct.c_uint16(socket.htons(port)))

        if id is None:
            id = self.n_servers

        self.n_servers = max(self.n_servers, id + 1)

        self.b['dst_servers'][id] = server
        self.b['n_dst_servers'][0] = ct.c_uint(self.n_servers)

    def redirect_flow(self, orig_id, next_id, n_sport):
        if orig_id >= self.n_servers or next_id >= self.n_servers:
            print("A BAD THING HAS HAPPENED")
            return

        orig = self.b['dst_servers'][orig_id]
        next = self.b['dst_servers'][next_id]

        outflow = OutFlow(orig.port, ct.c_uint16(n_sport))
        try:
            client = self.b['outflows'][outflow]
        except KeyError:
            print("Could not find outflow")
            return

        print("Attempting to replace %d:%d->%d %d=>%d" % (client.addr, socket.ntohs(client.port), socket.ntohs(orig.port), orig_id, next_id))

        inflow = Flow(client.addr, client.port, orig.port)

        if inflow not in self.b['inflows']:
            print("NOT REPLACING WHICH IS WEIRD")

        self.b['inflows'][inflow] = ct.c_int(next_id + 1)
        #self.b['outflows'][new_outflow] = client

    def add_port(self, port):
        ctport = ct.c_uint16(socket.htons(port))
        self.b['active_ports'][ctport] = ct.c_uint32(1)

    def handle_message(self, msg):
        print("Handling message: %s" % msg);
        jmsg = json.loads(msg)
        if jmsg['type'] == 'add':
            print("Handling ADD msg")
            self.add_server(jmsg['ip'], jmsg['port'], jmsg['id'])
        if jmsg['type'] == 'redirect':
            print("Handling REDIRECT msg")
            self.redirect_flow(jmsg['orig_id'], jmsg['next_id'], jmsg['n_sport'])

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
            while (True):
                print("Waiting on receive")
                message = self.sock.recv()
                self.handle_message(message)
                self.sock.send("done")
        finally:
            self.b.remove_xdp(iface)
            try:
                ip.tc('del', 'clsact', ifindex)
            except:
                print("Couldn't del clsact")

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('iface')
    parser.add_argument('port', type=int)
    parser.add_argument('ip', nargs='*')

    args = parser.parse_args()

    p = Proxy()
    p.add_port(args.port)
    for ip in args.ip:
        print(ip)
        p.add_server(ip)
    p.run(args.iface)
