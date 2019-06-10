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

    def check_nat_setup(self, sender, sock, addr, port):
        if len(self.connections) == self.n_peers:
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
        logging.info("Cleared iptables rules")

    def setup_nat(self):
        self.clear_nat()

        for i, (name, (_, addr)) in enumerate(self.connections.items()):
            logging.info("Setting nat for {}".format(name))
            self.set_dnat(self.proxy_ip, addr[0], self.app_port, len(self.connections) - i)
            self.set_snat(self.proxy_ip, addr[0], self.app_port)

    DELETE_NAT_CMD = ''' \
    conntrack -D -s {source_ip} -p TCP --sport {source_port}'''

    INSERT_NAT_CMD = ''' \
    conntrack -I -p TCP -t 1000 --src {source_ip} --dst {proxy_ip} \
        --sport {source_port} --dport {app_port} \
        --src-nat {proxy_ip} \
        --dst-nat {server_ip} --state NONE'''

    def rewrite_nat(self, source_ip, source_port, dst_ip):
        source_ip = '11.0.0.1'
        app_port = self.app_port
        proxy_ip = self.proxy_ip
        cmd = self.DELETE_NAT_CMD.format(
                source_ip = source_ip,
                source_port = source_port)

        subprocess.check_call(cmd, shell=True)
        logging.debug("Deleted NAT entry")

        cmd = self.INSERT_NAT_CMD.format(
                source_ip = source_ip,
                proxy_ip = proxy_ip,
                source_port = source_port,
                app_port = app_port,
                server_ip = dst_ip)
        subprocess.check_call(cmd, shell=True)
        logging.info("Rewrote NAT entry")

    def rcv_rewrite(self, sender, sock, addr, source_ip, source_port, dst_ip):
        logging.info("Received rewrite command")
        self.rewrite_nat(source_ip, source_port, dst_ip)


    @classmethod
    def rewrite_cmd(cls, source_ip, source_port, dst_ip):
        return dict(
            cmd = 'rewrite',
            source_ip = source_ip,
            source_port = source_port,
            dst_ip = dst_ip)


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
