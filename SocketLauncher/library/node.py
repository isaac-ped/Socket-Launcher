from collections import defaultdict, namedtuple
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
        logging.info("Binding socket dispatcher to :%d", port)
        self.sock.bind(('', port))
        self.sock.listen(16)
        self.other_sockets = []
        self.poller = None
        self.running = True
        self.connections = {}
        self.poller = select.poll()

    def dispatch(self, cb, new_cb=None):
        logging.info("Listening on socket {}".format(self.sock.fileno()))

        self.poller.register(self.sock, select.POLLIN)

        while self.running:
            activity = self.poller.poll(.25)
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
        self.poller.register(socket, select.POLLIN)
        self.connections[socket.fileno()] = (socket, (ip, port))


class ConnectedNode(object):

    DELIMITER = '~~'

    Connection = namedtuple('NodeConnection', ['name', 'ip', 'port', 'socket'])

    def __init__(self, listen_port, name):
        self.sd = SocketDispatcher(listen_port)
        self.listen_port = listen_port
        self.name = name
        self.callbacks = defaultdict(list)

        self.node_map = {}
        self._socket_map = {}

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
        self.send(sock, 'hello', port=self.listen_port)
        self.sd.add_socket(sock, ip, port)

    def get_connections(self):
        return list(self.node_map.values())

    def get_connection(self, name):
        return self.node_map[name]

    def update_node_connection(self, connection):
        self.node_map[connection.name] = connection
        self._socket_map[connection.socket] = connection

    def _hello_cb(self, connection, port):
        self.update_node_connection(connection)
        self.send(connection, 'hello_ack')

    def _hello_ack_cb(self, connection):
        self.update_node_connection(connection)

    def register_callback(self, cmd, callback):
        logging.debug("Registered callback {} for command {}".format(callback.__name__, cmd))
        self.callbacks[cmd].append(callback)

    def _callback(self, socket, addr):
        try:
            data = socket.recv(1024)

            logging.debug("Received '%s' from %s", data, addr)

            if data:
                split_data = data.split(self.DELIMITER)
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

                        conn = self.Connection(d['sender'], addr[0], addr[1], socket)

                        logging.info("Received {} from {}".format(cmd, d['sender']))

                        if cmd not in self.callbacks:
                            logging.error("command {} is not mapped to a callback".format(cmd))

                        for cb in self.callbacks[cmd]:
                            logging.debug("Calling callback %s for cmd %s", cb.__name__, cmd)
                            cb(conn, *d['args'], **d['kwargs'])
                    except:
                        logging.error("Error callbacking")
                        traceback.print_exc()
                        raise
            else:
                logging.info("%s received 0 bytes. Closing connection", addr)
                socket.close()
                return False
        except Exception as e:
            logging.info("{} errored: {}".format(addr, e))
            traceback.print_exc()
            if socket in self._socket_map:
                conn = self._socket_map[socket]
                del self._socket_map[socket]
                del self.node_map[conn.name]

                socket.close()
                if conn.name == 'proxy':
                    raise Exception("Proxy disconnected!")

            socket.close()

            return False

    def loop(self):
        self.sd.dispatch(self._callback)

    def stop(self):
        self.sd.running = False

    def send(self, to, cmd, *args, **kwargs):

        msg_d = dict(cmd=cmd, sender=self.name, args=args, kwargs=kwargs)
        logging.debug("Sending cmd %s to socket", cmd)

        if to in self.node_map:
            to = self.node_map[to]
            to.socket.sendall(json.dumps(msg_d) + self.DELIMITER)
        elif to in self._socket_map:
            to = self._socket_map[to]
            to.socket.sendall(json.dumps(msg_d) + self.DELIMITER)
        elif type(to) == self.Connection:
            to.socket.sendall(json.dumps(msg_d) + self.DELIMITER)
        elif type(to) == socket.socket:
            to.sendall(json.dumps(msg_d) + self.DELIMITER)
            return


class ControlNode(ConnectedNode):

    def __init__(self, listen_port, name):
        super(ControlNode, self).__init__(listen_port, name)
        self.register_callback('hello', self.broadcast_join)

    def broadcast_join(self, connection, port):
        connections = self.get_connections()
        if len(connections) == 1:
            logging.info("First node joined")
        else:
            logging.info("Broadcasting join to %d nodes", len(connections) - 1)

        for old_connection in connections:
            if old_connection.name != connection.name:
                self.send(old_connection, 'peer_join', peer=connection.name, peer_addr=(connection.ip, port))


class PeerNode(ConnectedNode):

    def __init__(self, listen_port, name):
        super(PeerNode, self).__init__(listen_port, name)
        self.register_callback("peer_join", self.peer_join_cb)

    def get_peers(self):
        return [c for c in self.get_connections() if c.name != 'proxy']

    def peer_join_cb(self, connection, peer, peer_addr):
        logging.debug("Attempting to connect to %s at %s:%d", peer, peer_addr[0], peer_addr[1])
        self.connect(*peer_addr)

    def connect_to_control(self, control_ip, control_port):
        self.connect(control_ip, control_port)
