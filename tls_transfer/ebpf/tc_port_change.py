import sys
from pyroute2 import IPRoute
from bcc import BPF
from time import sleep

iface = sys.argv[1]
src = sys.argv[2]
dst = sys.argv[3]

def do_port_rewrite(src, dst, iface):
    cflags = ['-DTARGET_PORT=%d'%src,
              '-DDST_PORT=%d'% dst]

    b = BPF(src_file='tc_port_change.c', cflags=cflags)

    ing_fn = b.load_func('rewrite_ingress', BPF.SCHED_CLS)
    egr_fn = b.load_func('rewrite_egress', BPF.SCHED_CLS)

    ip = IPRoute()

    ifindex = ip.get_links(ifname=iface)[0]['index']
    print(ifindex, ing_fn.fd)

    try:
        # Add ingress and egress qdisc
        try:
            ip.tc("add", "clsact", ifindex)
        except:
            print("Couldnt add clsact")
            pass


        ip.tc('add-filter', 'bpf', ifindex,
                fd=ing_fn.fd, name=ing_fn.name, parent='ffff:fff2', class_id=1, direct_action=True)

        ip.tc('add-filter', 'bpf', ifindex,
                fd=egr_fn.fd, name=egr_fn.name, parent='ffff:fff3', direct_action=True, class_id=1)

        while 1:
            sleep(1)

    finally:
        try:
            ip.tc('del', 'clsact', ifindex)
        except:
            print("Couldn't delete ingress")
        try:
            ip.tc('del', 'sfq', ifindex)
        except:
            print("Couldn't delete egress")


do_port_rewrite(int(src), int(dst), iface)
