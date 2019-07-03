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

class Flow(ct.Structure):
    _pack_ = 1
    _fields_ = [
            ('srcaddr', ct.c_uint32),
            ('srcport', ct.c_uint16),
            ('dstport', ct.c_uint16)
    ]

class DropClient(object):

    def __init__(self, client_id,
                 src_file = os.path.join(os.path.dirname(__file__), 'drop_client.c')):
        try:
            os.mkdir('/tmp/drop_client');
        except OSError:
            pass
        ctx = zmq.Context()
        self.sock_loc = 'ipc:///tmp/drop_client/%d' % client_id
        self.sock = ctx.socket(zmq.REP)
        self.sock.bind(self.sock_loc)
        print("Bound sock to %s" % self.sock_loc)

        self.b = BPF(src_file = src_file)
        self.n_servers = 0

    def block_flow(self, ip, src_port, dst_port):
        structip = ip2int(ip)
        flow = Flow(structip, socket.htons(src_port), socket.htons(dst_port))

        self.b['blocked_flows'][flow] = ct.c_int(1)

    def unblock_flow(self, ip, src_port, dst_port):
        flow = Flow(ip2int(ip), socket.htons(src_port), socket.htons(dst_port))

        try:
            del self.b['blocked_flows'][flow]
        except KeyError:
            print("Error unblocking flow")

    def handle_message(self, msg):
        print("Handling message: %s" % msg);
        jmsg = json.loads(msg)
        if jmsg['type'] == 'drop':
            print("Handling BLOCK msg")
            self.block_flow(jmsg['src_ip'], jmsg['src_port'], jmsg['dst_port'])
        elif jmsg['type'] == 'undrop':
            print("Handling UNBLOCK  msg")
            self.unblock_flow(jmsg['src_ip'], jmsg['src_port'], jmsg['dst_port'])
        else:
            print("Unknown message tpye: %s" % jmsg['type'])

    def run(self, iface):
        ing_fn= self.b.load_func('monitor_ingress', BPF.XDP)

        self.b.attach_xdp(iface, ing_fn, 0)

        try:
            while (True):
                print("Waiting on receive")
                message = self.sock.recv()
                self.handle_message(message)
                self.sock.send("done")
        finally:
            self.b.remove_xdp(iface)

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('iface')
    parser.add_argument('client_id', type=int)

    args = parser.parse_args()

    dc = DropClient(args.client_id)
    dc.run(args.iface)
