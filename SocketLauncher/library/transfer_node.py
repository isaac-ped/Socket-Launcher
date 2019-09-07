import logging
logging.basicConfig(level = logging.DEBUG)
import socket
import random
from ebpf_lib.transferer import Transferer
from node import PeerNode
from argparse import ArgumentParser
from collections import defaultdict

class TransferNode(PeerNode):

    def __init__(self, listen_port, name, app_port, peer_iface, local_ip, pool_size = 10):
        super(TransferNode, self).__init__(listen_port, name)
        self.app_port = app_port
        self.pool_size = pool_size
        self.transferer = Transferer()
        self.iface = peer_iface
        self.local_ip = local_ip

        self.pool_sockets = defaultdict(list)

        self.register_callback("pool_ready", self.pool_ready_cb)
        self.register_callback("transfer", self.transfer_cb)

    def start(self):
        self.transferer.start(self.iface)

    def update_node_connection(self, connection):
        super(TransferNode, self).update_node_connection(connection)
        if connection.name != 'proxy':
            self.transferer.set_port_range(connection.ip, self.app_port, 0, 65535)
            self.send(connection, 'pool_ready')

    def add_peer(self, name):
        super(TransferNode, self).add_peer(name)
        peer_addr = self.connections[name][1][0]
        logging.info("Adding peer named {} ({}) to tranfer node".format(name, peer_addr))
        self.transferer.set_port_range(peer_addr, self.app_port, 0, 65535)
        self.pool_ready(name)

    def transfer_cb(self, connection, client_addr, client_port):
        existing = self.transferer.pop_connection(connection.ip)
        self.transferer.set_rewrite(client_addr, client_port,
                                  existing.addr, existing.port,
                                  existing.seq, existing.ack)
        self.send('proxy', 'rewrite',
                  orig_ip = connection.ip,
                  source_port = client_port)


    def send_transfer(self, to, orig_addr, orig_port):
        if to is None:
            to = random.choice(self.get_peers())

        logging.info("Transferring connection to %s", to)
        self.send(to, 'transfer',
                  client_addr=orig_addr,
                  client_port=orig_port)

    def open_pool(self, peer_ip, n, localport=None):
        for i in range(n):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            if localport is not None:
                raise NotImplementedException("Can't use local port yet")
            sock.connect((peer_ip, self.app_port))
            self.pool_sockets[peer_ip].append(sock)

        logging.debug("Opened %d connections to %s:%d", n, peer_ip, self.app_port)

    def pool_ready_cb(self, connection):
        self.open_pool(connection.ip, self.pool_size)

    def stop(self):
        super(TransferNode, self).stop()
        logging.debug("Stopping connection pool")
        self.transferer.stop()


if __name__ == '__main__':
    parser = ArgumentParser("Peer node")
    parser.add_argument("name")
    parser.add_argument("listen_port", type=int)
    parser.add_argument('peer_iface', type=str)
    parser.add_argument("app_port", type=int)
    parser.add_argument("control_ip")
    parser.add_argument("control_port", type = int)

    args = parser.parse_args()

    node = TransferNode(args.listen_port, args.name, args.app_port, args.peer_iface)
    node.connect_to_control(args.control_ip, args.control_port)
    node.start()
    try:
        node.loop()
    except:
        node.stop()
