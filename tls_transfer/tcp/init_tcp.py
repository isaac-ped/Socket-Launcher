#!/usr/bin/env python
import socket
import sys
import time
from threading import Thread

def tcp_connect(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.connect((ip, port))

    time.sleep(10000)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: %s IP PORT")
        exit(-1)

    tcp_connect(sys.argv[1], int(sys.argv[2]))
