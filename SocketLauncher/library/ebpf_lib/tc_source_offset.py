#!/usr/bin/env python
import sys
import ctypes as ct
from pyroute2 import IPRoute
from bcc import BPF
from time import sleep
from threading import Thread
import logging
import argparse
import socket
import os
import struct

def ip2int(addr):
    return socket.htonl(struct.unpack('!I', socket.inet_aton(addr))[0])

class ProposedKey(ct.Structure):
    _pack_ = 1
    _fields_ = [('saddr_orig', ct.c_uint32),
                ('sport_orig', ct.c_uint16)]

class ProposedRewrite(ct.Structure):
    _pack_ = 1
    _fields_ = [("saddr_new", ct.c_uint32),
                ("sport_new", ct.c_uint16),
                ('seq_new', ct.c_uint32),
                ('ack_new', ct.c_uint32)]

def show_active(type, cpu, data, size):
    event = ct.cast(data, ct.POINTER(SeqTuple)).contents
    print("%s:\n\tseq:%lu\n\tseq_start:%lu\n\tack:%lu\n\tack_start:%lu\n" %
            (type, event.seq_start, event.seq_offset, event.ack_start, event.ack_offset))

class SourceRewriter(object):

    def __init__(self, src_file=os.path.join(os.path.dirname(__file__), 'tc_source_offset.c')):
        self.b = BPF(src_file=src_file)
        self.running = False
        #self.b['ingress_events'].open_perf_buffer(lambda *x: show_active('ingress', *x))
        #self.b['egress_events'].open_perf_buffer(lambda *x: show_active('egress', *x))

    def set_rewrite(self, saddr, sport, saddr_new, sport_new, seq, ack_seq):
        key = ProposedKey(ip2int(saddr),
                         socket.htons(sport))
        print("Seq: %d, %d" % ( seq, socket.htonl(seq)))
        val = ProposedRewrite(ip2int(saddr_new),
                              socket.htons(sport_new),
                              socket.htonl(seq),
                              socket.htonl(ack_seq))

        print("Seq: %d"% val.seq_new);

        self.b['proposed_in'][key] = val

    def run(self, iface):
        ing_fn = self.b.load_func('rewrite_ingress', BPF.SCHED_CLS)
        egr_fn = self.b.load_func('rewrite_egress', BPF.SCHED_CLS)


        ip = IPRoute()

        ifindex = ip.get_links(ifname=iface)[0]['index']

        try:
            ip.tc('add', 'clsact', ifindex)
        except:
            print("Couldn't add clsact")

        ip.tc('add-filter', 'bpf', ifindex,
                fd=ing_fn.fd, name=ing_fn.name, parent='ffff:fff2', class_id=1, direct_action=True)

        ip.tc('add-filter', 'bpf', ifindex,
                fd=egr_fn.fd, name=egr_fn.name, parent='ffff:fff3', direct_action=True, class_id=1)

        try:
            self.running = True
            while self.running:
                self.b.perf_buffer_poll(timeout=1000)
        finally:
            try:
                ip.tc('del', 'clsact', ifindex)
            except:
                print("Could not del clsact")

    def start(self, iface):
        self.thread = Thread(target = self.run, args=(iface,))
        self.thread.start()

    def stop(self):
        self.running = False
        self.thread.join()
        logging.debug("Source rewriter joined")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('iface')
    parser.add_argument('saddr', type=str,  nargs='?')
    parser.add_argument('sport', type=int, nargs='?')
    parser.add_argument('saddr_new', type=str, nargs='?')
    parser.add_argument('sport_new', type=int, nargs='?')
    parser.add_argument('seq', type=int, nargs='?')
    parser.add_argument('ack_seq', type=int, nargs='?')

    args = parser.parse_args()
    sc = SourceRewriter('tc_source_offset.c')
    if args.saddr:
        sc.set_rewrite(args.saddr, args.sport, args.saddr_new, args.sport_new, args.seq, args.ack_seq)
    sc.run(args.iface)
