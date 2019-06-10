import logging
import socket
from transfer_node import TransferNode
from threading import Thread
import time

_PARAMS = {}

def set_params(iface, node_name, ctl_ip, ctl_port, local_ip, pool_size=10):
    _PARAMS['iface'] = iface
    _PARAMS['node_name'] = node_name
    _PARAMS['ctl_ip'] = ctl_ip
    _PARAMS['ctl_port'] = ctl_port
    _PARAMS['pool_size'] = pool_size
    _PARAMS['local_ip'] = local_ip

class TransferSock(object):

    def __init__(self, sock, node):
        self.sock = sock
        self.node = node
        self.peername = sock.getpeername()

    def close(self):
        return self.sock.close()

    def recv(self, *args, **kwargs):
        return self.sock.recv(*args, **kwargs)

    def send(self, *args, **kwargs):
        return self.sock.send(*args, **kwargs)

    def sendall(self, *args, **kwargs):
        return self.sock.sendall(*args, **kwargs)

    def transfer(self, to = None):
        print("Transferring")
        self.node.send_transfer(to, *self.peername)

    def fileno(self):
        return self.sock.fileno()


class TransferListenSocket(object):

    def __init__(self, *args, **kwargs):
        self.node = None
        self.sock = socket.socket(*args, **kwargs)
        self.thread = None

    def close(self):
        self.node.stop()
        return self.sock.close()

    def fileno(self):
        return self.sock.fileno()

    def setsockopt(self, *args, **kwargs):
        self.sock.setsockopt(*args, **kwargs)

    def bind(self, addr):
        print("Binding to {}".format(addr))
        self.sock.bind(addr)
        self.ip = addr[0]
        self.port = addr[1]

    def listen(self, *args, **kwargs):
        logging.info("App listening start: {} {}".format(args, kwargs))
        self.sock.listen(*args, **kwargs)
        logging.info("Creating node")
        self.node = TransferNode(_PARAMS['ctl_port'], _PARAMS['node_name'],
                                self.port, _PARAMS['iface'], _PARAMS['local_ip'],  _PARAMS['pool_size'])
        self.node.connect_to_control(_PARAMS['ctl_ip'], _PARAMS['ctl_port'])
        logging.info("Connected to control")
        self.node.start()
        logging.info("Creating thread")
        self.thread = Thread(target = self.node.loop)
        logging.info("Starting thread")
        self.thread.start()
        logging.info("App Finished listening!")

    def accept(self):
        print("Accepting")
        connection, addr = self.sock.accept()
        print("Accepted")
        return TransferSock(connection, self.node), addr
