#!/usr/bin/env python
import socket
import sys
import time
from threading import Thread

def tcp_ping(ip, port, N=20, auto=True, reps=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.connect((ip, port))

    try:
        for i in range(N):
            expected = 0

            for _ in range(reps):
                message = 'Ping: %d' % i

                sendtime = time.time()
                sock.sendall(message)

                expected += len(message)
            if not auto:
                x = raw_input()
            else:
                pass
            rcvd = 0
            expected *= 1
            data = ''
            time.sleep(.05)
            while rcvd < expected:
                data += sock.recv(expected)
                rcvtime = time.time()
                rcvd += len(data)
            print("Received %s in %.3fs" % (data, rcvtime - sendtime))
    except Exception as e:
        print("Got exception:", e)

    finally:
        print("Closing socket")
        sock.close()


def many_pings(ip, port, n, n_per=20):

    if n == 1:
        tcp_ping(ip, port, n_per)
        exit(0)
    if n == -1:
        tcp_ping(ip, port, 1000, False, 1)

    threads = []
    for i in range(n):
        threads.append(Thread(target=tcp_ping, args=(ip, port, n_per, 10)))
        threads[-1].start()

    for t in threads:
        t.join()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: %s IP PORT [N_SIMUL] [N_PER]")
        exit(-1)

    n_simul = int(sys.argv[3])if len(sys.argv) > 3 else 1
    n_per = int(sys.argv[4]) if len(sys.argv) > 4 else 10

    many_pings(sys.argv[1], int(sys.argv[2]), n_simul, n_per)
