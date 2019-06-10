from collections import defaultdict
import select
import json
import socket
import logging
import traceback

class SocketDispatcher(object):

    def __init__(self, port):
        self.listen_port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("Binding socket dispatch to {}".format(port))
        self.sock.bind(('', port))
        self.sock.listen(16)
        self.other_sockets = []
        self.poller = None
        self.running = True

    def dispatch(self, cb, new_cb=None):
        logging.info("Listening on socket {}".format(self.sock.fileno()))

        self.connections = {}
        self.poller = select.poll()
        self.poller.register(self.sock, select.POLLIN)
        for (socket, ip, port) in self.other_sockets:
            self.poller.register(socket, select.POLLIN)
            self.connections[socket.fileno()] = (socket, (ip, port))

        while self.running:
            activity = self.poller.poll(1)
            for conn in activity:
                logging.debug("Activity on socket {}".format(conn[0]))
                if conn[0] == self.sock.fileno():
                    connection, cli_addr = self.sock.accept()
                    logging.info("Accepted {} from {}".format(connection.fileno(), cli_addr))
                    self.poller.register(connection, select.POLLIN)
                    self.connections[connection.fileno()] = (connection, cli_addr)
                    if new_cb is not None:
                        new_cb(connection, cli_addr)
                else:
                    if cb(*self.connections[conn[0]]) == False:
                        self.poller.unregister(conn[0])

    def add_socket(self, socket, ip, port):
        self.other_sockets.append((socket, ip, port))
        if self.poller is not None:
            self.poller.register(socket, select.POLLIN)
            self.connections[socket.fileno()] = (socket, (ip, port))


class ConnectedNode(object):

    def __init__(self, listen_port, name):
        self.sd = SocketDispatcher(listen_port)
        self.listen_port = listen_port
        self.name = name
        self.callbacks = defaultdict(list)
        self.connections = {}
        self.senders = {}

        self.register_callback("hello", self._hello_cb)
        self.register_callback("hello_ack", self._hello_ack_cb)

    def connect(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            print("Attempting to connect to {}:{}".format(ip, port))
            sock.connect((ip, port))
            logging.info("Connected to {}:{}".format(ip, port))
        except:
            logging.error("Could not connect to {}:{}".format(ip, port))
            raise
        self.send(sock, 'hello',
                  port=self.listen_port)
        self.sd.add_socket(sock, ip, port)

    def _hello_cb(self, sender, sock, addr, port):
        logging.info("Got hello from {}:{}".format(sender, port))
        self.connections[sender] = (sock, addr)
        self.senders[sock] = sender
        self.send(sender, 'hello_ack')

    def _hello_ack_cb(self, sender, sock, addr):
        logging.info("Hello acked from {}".format(sender))
        self.connections[sender] = (sock, addr)
        self.senders[sock] = sender

    def register_callback(self, cmd, callback):
        logging.debug("Registered callback {} for command {}".format(callback.__name__, cmd))
        self.callbacks[cmd].append(callback)

    def _callback(self, connection, addr):
        logging.debug("Callback for addr {}".format(addr))

        try:
            data = connection.recv(1024)

            logging.debug("Received {}".format(data))
            print("RECEIVED " + data)

            if data:
                split_data = data.split("~~")
                for data_item in split_data:
                    if len(data_item) == 0:
                        continue
                    try:
                        d = json.loads(data_item)
                    except:
                        logging.error("Malformed JSON!")
                        raise

                    try:
                        cmd = d['cmd']
                        del d['cmd']

                        logging.info("Received {} from {}".format(cmd, d['sender']))
                        if cmd not in self.callbacks:
                            logging.error("command {} unmapped".format(cmd))
                        for cb in self.callbacks[cmd]:
                            logging.debug("Calling {}".format(cb.__name__))
                            cb(sock = connection, addr=addr, **d)
                    except:
                        logging.error("Error callbacking")
                        traceback.print_exc()
                        raise
            else:
                logging.info("{} received 0 bytes:  exiting".format(addr))
                connection.close()
                return False
        except:
            logging.info("{} errored".format(addr))
            traceback.print_exc()
            if connection in self.senders:
                sender = self.senders[connection]
                del self.senders[connection]
                del self.connections[sender]
            connection.close()

            return False

    def loop(self):
        self.sd.dispatch(self._callback)

    def stop(self):
        self.sd.running = False

    def send(self, to, cmd, **kwargs):
        kwargs['cmd'] = cmd
        kwargs['sender'] = self.name

        print("Sending {} to {}".format(cmd, to))
        if isinstance(to, (str, unicode)):
            if to not in self.connections:
                logging.error("Attempting to send to unknown host {}".format(to))
                return # TODO: Exception?
            logging.debug("Connection {} : {}".format(self.connections[to], self.connections[to][0]))
            self.connections[to][0].sendall(json.dumps(kwargs) + "~~")
        else:
            to.sendall(json.dumps(kwargs)+"~~")

class ControlNode(ConnectedNode):

    def __init__(self, listen_port, name):
        super(ControlNode, self).__init__(listen_port, name)
        self.register_callback('hello', self.broadcast_join)

    def broadcast_join(self, sender, sock, addr, port):
        logging.info("Broadcasting join to {} nodes".format(len(self.connections) - 1))
        for old_peer in self.connections:
            if old_peer != sender:
                self.send(old_peer, 'peer_join', peer=sender, peer_addr=(addr[0], port))


class PeerNode(ConnectedNode):

    def __init__(self, listen_port, name):
        super(PeerNode, self).__init__(listen_port, name)
        self.peers = []
        self.register_callback("peer_join", self.connect_to_peer)
        self.register_callback("hello", self.peer_hello_cb)
        self.register_callback("hello_ack", self.peer_hello_ack_cb)

    def add_peer(self, name):
        logging.debug("Adding peer {}".format(name))
        self.peers.append(name)

    def peer_hello_cb(self, sender, sock, addr, port):
        self.add_peer(sender)

    def peer_hello_ack_cb(self, sender, sock, addr):
        if sender != 'proxy':
            self.add_peer(sender)

    def connect_to_peer(self, sender, sock, addr, peer, peer_addr):
        self.connect(*peer_addr)

    def connect_to_control(self, control_ip, control_port):
        self.connect(control_ip, control_port)
