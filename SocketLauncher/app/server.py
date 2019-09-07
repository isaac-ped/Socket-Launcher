#!/usr/bin/env python
import socket
import argparse
import sys
import select
from threading import Thread

def handle_activity(connection, cli_addr):
    try:
        data = connection.recv(1024)
        print(cli_addr, "Received", data)
        if data:
            print(cli_addr, "Echoing", data)
            connection.sendall(data)
            return True
        else:
            print(cli_addr, "Exiting")
            connection.close()
            return False
    except:
        connection.close()
        return False

def listen(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip, port))

    sock.listen(1)


    conns = {}
    poller = select.poll()
    poller.register(sock, select.POLLIN)
    while True:
        activity = poller.poll()
        for conn in activity:
            print conn[0], sock
            if conn[0] == sock.fileno():
                connection, cli_addr = sock.accept()
                print("Accepted on %d %s" % (connection.fileno(), cli_addr))
                poller.register(connection, select.POLLIN)
                conns[connection.fileno()] = (connection, cli_addr)
            else:
                if handle_activity(*conns[conn[0]]) == False:
                    poller.unregister(conn[0])

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage %s PORT IP" % sys.argv[0])
        exit(-1)

    listen(sys.argv[2] if len(sys.argv) > 2 else '', int(sys.argv[1]))
