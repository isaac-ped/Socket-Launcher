#!/usr/bin/env python
import socket
import sys
import time
from threading import Thread

def tcp_connect(ip, port, localport=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    if localport is not None:
        sock.bind(('12.0.0.1', localport))

    sock.connect((ip, port))

    try:
        time.sleep(10000)
    except:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: %s IP PORT")
        exit(-1)

    if len(sys.argv) == 4:
        tcp_connect(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
    else:
        tcp_connect(sys.argv[1], int(sys.argv[2]))
