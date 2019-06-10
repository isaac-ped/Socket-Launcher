#!/usr/bin/env python
import yaml
import subprocess
import logging
import sys
from argparse import ArgumentParser
from node import ControlNode


class ProxyNode(ControlNode):

    DNAT_CMD = ''' \
    iptables \
        -A PREROUTING \
        -t nat \
        -p tcp \
        -j DNAT \
        -m statistic \
        --mode nth \
        --packet 0 \
        --dport {app_port} \
        -d {proxy_ip} \
        --to-destination {server_ip}:{app_port} \
        --every {n}
    '''

    SNAT_CMD = ''' \
    iptables \
        -A POSTROUTING \
        -t nat \
        -p tcp \
        -j SNAT \
        -d {server_ip} \
        --dport {app_port} \
        --to-source {proxy_ip}
    '''

    def __init__(self, proxy_ip, proxy_port, app_port, n_peers):
        super(ProxyNode, self).__init__(proxy_port, 'proxy')
        self.proxy_ip = proxy_ip
        self.app_port = app_port
        self.n_peers = n_peers

        self.register_callback('hello', self.check_nat_setup)
        self.register_callback('rewrite', self.rcv_rewrite)

    def check_nat_setup(self, connection, port):
        if len(self.get_connections()) == self.n_peers:
            self.setup_nat()

    @classmethod
    def set_dnat(cls, proxy_ip, server_ip, app_port, n):
        cmd = cls.DNAT_CMD.format(
                proxy_ip=proxy_ip,
                server_ip=server_ip,
                app_port=app_port,
                n=n)
        subprocess.check_call(cmd, shell=True)
        logging.debug("Set DNAT for {}".format(server_ip))

    @classmethod
    def set_snat(cls, proxy_ip, server_ip, app_port):
        cmd = cls.SNAT_CMD.format(
                proxy_ip = proxy_ip,
                server_ip = server_ip,
                app_port = app_port)
        subprocess.check_call(cmd, shell=True)
        logging.debug("Set SNAT for {}".format(server_ip))

    @staticmethod
    def clear_nat():
        subprocess.check_call("iptables -t nat -F", shell=True)
        logging.debug("Cleared iptables rules")

    def setup_nat(self):
        self.clear_nat()

        connections = self.get_connections()
        for i, connection in enumerate(connections):
            self.set_dnat(self.proxy_ip, connection.ip, self.app_port, len(connections) - i)
            self.set_snat(self.proxy_ip, connection.ip, self.app_port)

    LIST_NAT_CMD = '''\
    conntrack -L --reply-src {orig_ip} -p TCP --sport {source_port}'''


    DELETE_NAT_CMD = ''' \
    conntrack -D --reply-src {orig_ip} -p TCP --sport {source_port}'''

    INSERT_NAT_CMD = ''' \
    conntrack -I -p TCP -t 1000 --src {src_ip} --dst {proxy_ip} \
        --sport {source_port} --dport {app_port} \
        --src-nat {proxy_ip} \
        --dst-nat {new_ip} --state NONE'''

    def rewrite_nat(self, orig_ip, source_port, new_ip):
        logging.info("Rewriting NAT table")
        app_port = self.app_port
        proxy_ip = self.proxy_ip

        cmd = self.LIST_NAT_CMD.format(
                orig_ip = orig_ip,
                source_port = source_port)

        output = subprocess.check_output(cmd, shell=True)
        sip_idx = output.find('src=')
        sip_start = sip_idx + 4
        sip = output[sip_start:].split()[0]


        cmd = self.DELETE_NAT_CMD.format(
                orig_ip = orig_ip,
                source_port = source_port)

        subprocess.check_call(cmd, shell=True)

        cmd = self.INSERT_NAT_CMD.format(
                src_ip = sip,
                proxy_ip = proxy_ip,
                source_port = source_port,
                app_port = app_port,
                new_ip = new_ip)
        subprocess.check_call(cmd, shell=True)
        logging.debug("Rewrote NAT table")

    def rcv_rewrite(self, connection, orig_ip, source_port):
        self.rewrite_nat(orig_ip, source_port, connection.ip)

if __name__ == '__main__':
    logging.basicConfig(level = logging.DEBUG)
    parser = ArgumentParser("Runs transfer proxy")
    parser.add_argument("proxy_ip")
    parser.add_argument("proxy_port", type=int)
    parser.add_argument("app_port", type=int)
    parser.add_argument("n_peers", type=int)

    args = parser.parse_args()

    proxy = ProxyNode(args.proxy_ip, args.proxy_port, args.app_port, args.n_peers)
    proxy.loop()
