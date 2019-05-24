import sys
import ctypes as ct
from pyroute2 import IPRoute
from bcc import BPF
from time import sleep
import argparse
import socket
import struct

def ip2int(addr):
    return socket.htonl(struct.unpack('!I', socket.inet_aton(addr))[0])

class AddrTuple(ct.Structure):
    _fields_ = [("saddr", ct.c_uint32),
                ("sport", ct.c_uint16)]

class SeqTuple(ct.Structure):
    _fields_ = [('seq_start', ct.c_uint32),
                ('seq_offset', ct.c_uint32),
                ('ack_start', ct.c_uint32),
                ('ack_offset', ct.c_uint32),
                ('offset_set', ct.c_bool)]

def show_active(type, cpu, data, size):
    event = ct.cast(data, ct.POINTER(SeqTuple)).contents
    print("%s:\n\tseq:%lu\n\tseq_start:%lu\n\tack:%lu\n\tack_start:%lu\n" %
            (type, event.seq_start, event.seq_offset, event.ack_start, event.ack_offset))

class SeqChanger(object):

    def __init__(self, src_file):
        self.b = BPF(src_file=src_file)
        self.b['ingress_events'].open_perf_buffer(lambda *x: show_active('ingress', *x))
        self.b['egress_events'].open_perf_buffer(lambda *x: show_active('egress', *x))

    def set_rewrite(self, saddr, sport, seq, ack_seq):
        print(ip2int(saddr), socket.htons(sport))
        addr = AddrTuple(ip2int(saddr), socket.htons(sport))
        seq = SeqTuple(socket.htonl(seq), 0, socket.htonl(ack_seq), 0, False)

        self.b['seq_table'][addr] = seq

    def run(self, iface):
        ing_fn = self.b.load_func('change_ingress', BPF.SCHED_CLS)
        egr_fn = self.b.load_func('change_egress', BPF.SCHED_CLS)


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
            while 1:
                self.b.perf_buffer_poll()
        finally:
            try:
                ip.tc('del', 'clsact', ifindex)
            except:
                print("Could not del clsact")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('iface')
    parser.add_argument('dport', type=int,  nargs='?')
    parser.add_argument('saddr', nargs='?')
    parser.add_argument('sport', type=int, nargs='?')
    parser.add_argument('seq', type=int, nargs='?')
    parser.add_argument('ack_seq', type=int, nargs='?')

    args = parser.parse_args()
    sc = SeqChanger('tc_seq_change.c')
    if args.saddr:
        sc.set_rewrite(args.saddr, args.sport, args.seq, args.ack_seq)
    sc.run(args.iface)
