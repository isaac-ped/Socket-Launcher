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

class MacAddr(ct.Structure):
    _fields_ = [('h_dest', ct.c_byte * 6),
                ('ifindex', ct.c_int)]

class Msg(ct.Structure):
    _fields_ = [("size", ct.c_size_t),
                ("msg", ct.c_char * 100)];

def print_notification(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Msg)).contents
    print("Notification:")
    print(event.msg)

class MacChanger(object):

    def __init__(self, src_file, iface, macs):
        self.b = BPF(src_file=src_file)
        self.n_macs = 0

        ip = IPRoute()
        ifindex = ip.get_links(ifname=iface)[0]['index']

        for mac in macs:
            self.add_macaddr(mac, ifindex)

    def add_macaddr(self, macaddr, ifindex):
        addr_ints = [int(x, 16) for x in macaddr.split(':')]
        print(addr_ints)
        addr = MacAddr()
        addr.h_dest = (ct.c_byte*6)(*addr_ints) # struct.pack("!BBBBBB", *addr_ints)
        addr.ifindex = ifindex
        #print(type(addr_struct))
        #for i,x in enumerate(addr_struct):
        #    print type(x)
        #    addr.h_dest[i] = x
        #addr = MacAddr(addr_struct, ifindex)

        print(addr)

        self.b['mac_array'][self.n_macs] = addr
        self.n_macs += 1
        self.b['mac_size'][0] = ct.c_int(self.n_macs)

    def run(self, iface):
        ing_fn = self.b.load_func('handle_ingress', BPF.SCHED_CLS)

        ip = IPRoute()

        ifindex = ip.get_links(ifname=iface)[0]['index']

        try:
            ip.tc('add', 'clsact', ifindex)
        except:
            print("Couldn't add clsact")

        ip.tc('add-filter', 'bpf', ifindex,
                fd=ing_fn.fd, name=ing_fn.name, parent='ffff:fff2', class_id=1, direct_action=True)

        self.b['NOTIFY_EVT'].open_perf_buffer(print_notification)

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
    parser.add_argument('macs', type=str, nargs='+')

    args = parser.parse_args()
    sc = MacChanger('tc_mac_rewrite.c', args.iface, args.macs)
    sc.run(args.iface)
