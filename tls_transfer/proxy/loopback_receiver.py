#!/usr/bin/env python
from __future__ import print_function
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
import arpreq

def log(*args, **kwargs):
    return
    args = [str(time.time())] + list(args)
    print(*args, **kwargs)

def ip2int(addr):
    return socket.htonl(struct.unpack('!I', socket.inet_aton(addr))[0])

class DstServer(ct.Structure):
    _pack_ = 1
    _fields_ = [
            ('h_dest', ct.c_char * 6),
            ('addr', ct.c_uint32)
    ]

class Flow(ct.Structure):
    _pack_ = 1
    _fields_ = [
            ('srcaddr', ct.c_uint32),
            ('srcport', ct.c_uint16),
            ('dstport', ct.c_uint16)
    ]

class LBRecv(object):

    def __init__(self, id, src_file = os.path.join(os.path.dirname(__file__), 'loopback_receiver.c')):
        try:
            os.mkdir('/tmp/tspeer');
        except OSError:
            pass
        ctx = zmq.Context()
        self.sock_loc = 'ipc:///tmp/tspeer/%d' % id
        self.sock = ctx.socket(zmq.REP)
        self.sock.bind(self.sock_loc)
        print("Bound sock to %s" % self.sock_loc)

        self.b = BPF(src_file = src_file)
        self.n_servers = 0

    def set_block(self, ip, src, dst, x):
        ctsrc = ct.c_uint16(socket.htons(src))
        ctdst = ct.c_uint16(socket.htons(dst))
        ctip = ip2int(ip)

        ds = Flow(ctip, ctsrc, ctdst)

        self.b['blocked_flows'][ds] = ct.c_int32(x)

    def add_server(self, ip, port, id=None):
        print("Adding server at %s:%d" % (ip, port))
        structip = ip2int(ip)
        print("Made int")
        mac = arpreq.arpreq(ip)
        print("MAC", mac)
        if mac is None:
            print("COULD NOT FIND MAC ADDRESS FOR IP %s"% ip)
            raise

        log("Found mac address: {}".format(mac))
        macstr = mac.replace(':', '').decode('hex')
        server = DstServer(macstr, structip)

        if id is None:
            id = self.n_servers

        self.n_servers = max(self.n_servers, id + 1)

        self.b['dst_servers'][id] = server
        self.b['n_dst_servers'][0] = ct.c_uint(self.n_servers)

    def redirect_flow(self, next_id, srcaddr, srcport, dstport):
        if next_id >= self.n_servers:
            print("A BAD THING HAS HAPPENED");
            return

        structip = ip2int(srcaddr)
        flow = Flow(structip, ct.c_uint16(socket.htons(srcport)),
                    ct.c_uint16(socket.htons(dstport)))

        self.b['redirect_flows'][flow] = ct.c_uint(next_id)

    def stop_redirect(self, srcaddr, srcport, dstport):
        flow = Flow(
                ip2int(srcaddr),
                ct.c_uint16(socket.htons(srcport)),
                ct.c_uint16(socket.htons(dstport)))

        try:
            del self.b['redirect_flows'][flow]
        except:
            print("Couldn't del flow")

    def add_ack(self, dstaddr, dstport, srcport, ack):
        flow = Flow(
                ip2int(dstaddr),
                ct.c_uint16(socket.htons(dstport)),
                ct.c_uint16(socket.htons(srcport)))

        self.b['ack_flows'][flow] = ct.c_uint32(ack)

    def handle_message(self, msg):
        log("Handling message: %s" % msg)
        jmsg = json.loads(msg)

        if jmsg['type'] == 'block':
            self.set_block(jmsg['ip'], jmsg['src_port'], jmsg['dst_port'], 1)
        elif jmsg['type'] == 'unblock':
            self.set_block(jmsg['ip'], jmsg['src_port'], jmsg['dst_port'], 0)
        elif jmsg['type'] == 'add_peer':
            self.add_server(jmsg['ip'], jmsg['port'], jmsg['id'])
        elif jmsg['type'] == 'redirect':
            self.redirect_flow(jmsg['next_id'], jmsg['src_addr'], jmsg['src_port'], jmsg['dst_port'])
        elif jmsg['type'] == 'stop_redirect':
            self.stop_redirect(jmsg['src_addr'], jmsg['src_port'], jmsg['dst_port'])
        elif jmsg['type'] == 'ack':
            self.add_ack(jmsg['dst_addr'], jmsg['dst_port'], jmsg['src_port'], jmsg['ack'])
        else:
            log("UNKNOWN TYPE: %s" % jmsg['type'])

    def run(self, iface):
        ip = IPRoute()
        ifindex = ip.get_links(ifname = iface)[0]['index']
        self.b['ifindex'][0] = ct.c_int(ifindex);

        print(iface + " index is " + str(ifindex))

        ing_iface_fn = self.b.load_func('monitor_iface_ingress', BPF.XDP)
        egr_iface_fn = self.b.load_func('monitor_iface_egress', BPF.SCHED_CLS)
        ing_iface_tc_fn = self.b.load_func('check_redirect', BPF.SCHED_CLS)
        lo_iface_fn = self.b.load_func('monitor_lo_ingress', BPF.SCHED_CLS)

        lo_idx = ip.link_lookup(ifname = 'lo')[0]

        self.b['loopback'][ct.c_uint32(0)] = ct.c_int(lo_idx)

        try:
            ip.tc('add', 'clsact', lo_idx)
        except:
            print("Couldn't add clsact")

        try:
            ip.tc('add', 'clsact', ifindex)
        except:
            print("Couldn't add iface clsact")

        self.b.remove_xdp(iface, 0)
        self.b.attach_xdp(iface, ing_iface_fn, 0)

        ip.tc('add-filter', 'bpf', lo_idx,
                fd = lo_iface_fn.fd, name = lo_iface_fn.name,
                parent ='ffff:fff2', class_id = 1,
                direct_action=True)


        ip.tc('add-filter', 'bpf', ifindex,
              fd = ing_iface_tc_fn.fd, name = ing_iface_tc_fn.name,
              parent = 'ffff:fff2', class_id = 1,
              direct_action=True)
        ip.tc('add-filter', 'bpf', ifindex,
              fd = egr_iface_fn.fd, name = egr_iface_fn.name,
              parent = 'ffff:fff3', class_id = 1,
              direct_action=True)
        try:
            while True:
                log("Waiting on receive")
                message = self.sock.recv()
                self.handle_message(message)
                self.sock.send("done")
        except Exception as e:
            print(e)
            pass
        finally:
            self.b.remove_xdp(iface, 0)
            try:
                ip.tc('del', 'clsact', ifindex)
            except:
                print("Couldn't del clsact")
            try:
                ip.tc('del', 'clsact', lo_idx)
            except:
                print("Couldn't del clsact")

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('iface')
    parser.add_argument('id', type=int)

    args = parser.parse_args()

    p = LBRecv(args.id)
    p.run(args.iface)
