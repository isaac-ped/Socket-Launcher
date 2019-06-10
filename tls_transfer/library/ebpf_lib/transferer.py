#!/usr/bin/env python
import logging
logging.basicConfig(level = logging.DEBUG)
import ctypes as ct
from pyroute2 import IPRoute
from bcc import BPF
import time
import signal
import argparse
import os
import socket
import struct
import random
from collections import defaultdict
from collections import namedtuple
from threading import Thread

def ip2int(addr):
    return socket.htonl(struct.unpack('!I', socket.inet_aton(addr))[0])

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

class PortRange(ct.Structure):
    _fields_ = [('start', ct.c_uint16),
                ('stop', ct.c_uint16)]

class MonitoredSocket(ct.Structure):
    _pack_ = 1

    _fields_ = [
            ('addr', ct.c_uint32),
            ('port', ct.c_uint16),
            ('seq', ct.c_uint32),
            ('ack', ct.c_uint32)
    ]

class MonitoredAddr(ct.Structure):
    _pack_ = 1

    _fields_ = [
            ('addr', ct.c_uint32),
            ('dest_port', ct.c_uint16)
    ]


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

class Transferer(object):

    Connection = namedtuple('Connection', ['addr', 'port', 'seq', 'ack'])

    def __init__(self, src_file=os.path.join(os.path.dirname(__file__), 'transferer.c')):
        self.b = BPF(src_file = src_file)
        self.pools = defaultdict(lambda: defaultdict(lambda: True))
        self.running = False
        self.thread = None

        self.b['clear_pool'].open_perf_buffer(self.clear_pool)
        self.b['add_to_pool'].open_perf_buffer(self.add_to_pool)
        self.b['rm_from_pool'].open_perf_buffer(self.rm_from_pool)

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

    def pop_connection(self, addr):
        logging.info("Getting connections for addr {}".format(addr))
        if len(self.pools[addr]) == 0:
            raise Exception("No connection pool available to addr {}".format(addr))
        port = random.choice(list(self.pools[addr].keys()))
        while self.pools[addr][port] is False:
            del self.pools[addr][port]
            if len(self.pools[addr]) == 0:
                raise Exception("No connection pool available to addr {}".format(addr))
            port = random.choice(list(self.pools[addr].keys()))

        seq, ack = self.pools[addr][port]

        del self.pools[addr][port]

        return self.Connection(addr, port, seq, ack)


    def clear_pool(self, cpu, data, size):
        ms = ct.cast(data, ct.POINTER(MonitoredSocket)).contents
        try:
            del self.pools[int2ip(ms.addr)][ms.port]
            logging.debug("Removed %s:%d from pool", int2ip(ms.addr), ms.port)
        except:
            pass

    def add_to_pool(self, cpu, data, size):
        ms = ct.cast(data, ct.POINTER(MonitoredSocket)).contents
        if self.pools[int2ip(ms.addr)][ms.port]:
            logging.debug("Adding {}:{} to pool".format(int2ip(ms.addr),
                                                        ms.port))
            self.pools[int2ip(ms.addr)][ms.port] = (ms.seq, ms.ack)
        else:
            print("Already Closed: {}:{}".format(int2ip(ms.addr), ms.port))

    def rm_from_pool(self, cpu, data, size):
        ms = ct.cast(data, ct.POINTER(MonitoredSocket)).contents
        print("RM: {}:{}".format(int2ip(ms.addr), ms.port))
        self.pools[int2ip(ms.addr)][ms.port] = False

    def set_port_range(self, addr, dport, port_start, port_stop):
        key = MonitoredAddr(ip2int(addr), socket.htons(dport))
        rng = PortRange(port_start, port_stop)

        self.b['port_ranges'][key] = rng

        logging.info("Added port range {}:{}-{}".format(addr, port_start, port_stop))


    def attach(self, iface):
        ing_fn = self.b.load_func('rewrite_ingress', BPF.SCHED_CLS)
        egr_fn = self.b.load_func('rewrite_egress', BPF.SCHED_CLS)

        ip = IPRoute()

        ifindex = ip.get_links(ifname = iface)[0]['index']

        try:
            ip.tc('add', 'clsact', ifindex)
        except:
            print("Couldn't add clsact")


        ip.tc('add-filter', 'bpf', ifindex,
                fd=ing_fn.fd, name=ing_fn.name, parent='ffff:fff2', class_id=1, direct_action=True)

        ip.tc('add-filter', 'bpf', ifindex,
                fd=egr_fn.fd, name=egr_fn.name, parent='ffff:fff3', direct_action=True, class_id=1)

        logging.info("Added transferer ebpf filters")

    def loop(self):
        logging.debug("Looping pool monitor...")
        try:
            while self.running:
                self.b.perf_buffer_poll(timeout=1000)
        finally:
            try:
                ip.tc('del', 'clsact', ifindex)
            except:
                print("Could not del clsact")

    def start(self, iface):
        self.attach(iface)
        self.running=True
        self.thread = Thread(target = self.loop)
        self.thread.start()

    def stop(self):
        logging.debug("Stopping pool monitor")
        self.running = False
        self.thread.join()

    def signal_handler(self, signum, frame):
        print("Signaled!")
        self.running = False
