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
    print("%s:\n\tseq:%d\n\tseq_start:%d\n\tack:%d\n\tack_start:%d\n" %
            (type, event.seq_start, event.seq_offset, event.ack_start, event.ack_offset))

class SeqMonitor(object):

    def __init__(self, src_file):
        self.b = BPF(src_file=src_file)

    def show_active(self):
        for k, v in self.b['seqs'].items():
            print("Port {}:\n\t Seq: {}\n\t Ack: {}".format(k.source, v.seq, v.ack))


    def run(self, iface):
        ing_fn = self.b.load_func('monitor_ingress', BPF.SCHED_CLS)


        ip = IPRoute()

        ifindex = ip.get_links(ifname=iface)[0]['index']

        try:
            ip.tc('add', 'clsact', ifindex)
        except:
            print("Couldn't add clsact")

        ip.tc('add-filter', 'bpf', ifindex,
                fd=ing_fn.fd, name=ing_fn.name, parent='ffff:fff2', class_id=1, direct_action=True)

        try:
            while 1:
                sleep(1)
                self.show_active()
        finally:
            try:
                ip.tc('del', 'clsact', ifindex)
            except:
                print("Could not del clsact")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('iface')

    args = parser.parse_args()
    sc = SeqMonitor('tc_monitor_seq.c')
    sc.run(args.iface)

