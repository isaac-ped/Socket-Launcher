#!/usr/bin/env python
'''
client (h1) -- proxy host (h2)
                   |
             h3 ---|--- h4
'''
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI



class LinuxRouter( Node ):
    "A Node with IP forwarding enabled."

    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()

class RouterStarTopo(Topo):

    ROUTER = dict(
            ip = '11.0.0.2',
    )
    ROUTER_MACS = {
            'r0-eth2': '00:00:00:00:AA:AA',
            'r0-eth3': '00:00:00:00:BB:BB',
            'r0-eth4': '00:00:00:00:CC:CC'
    }

    HOSTS = dict(
            h1 = {'ip': '11.0.0.1/16'},
            h2 = {'ip': '12.0.0.1/16',
                  'mac': '00:00:00:00:00:AA'},
            h3 = {'ip': '13.0.0.1/16',
                  'mac': '00:00:00:00:00:BB'},
            h4 = {'ip': '14.0.0.1/16',
                  'mac': '00:00:00:00:00:CC'}
    )

    LINKS = dict(
            h1 = dict(
                params2 = {'ip': '11.0.0.2/16'},
                intfName2 = 'r0-eth1'
            ),
            h2 = dict(
                params2 = {'ip': '12.0.0.2/16'},
                intfName2 = 'r0-eth2'
            ),
            h3 = dict(
                params2 = {'ip': '13.0.0.2/16'},
                intfName2 = 'r0-eth3'
            ),
            h4 = dict(
                params2 = {'ip': '14.0.0.2/16'},
                intfName2 = 'r0-eth4'
            )
    )



    def build(self):
        router = self.addNode('r0', cls=LinuxRouter, **self.ROUTER)

        hosts = [self.addHost(k,
                              defaultRoute = 'via %s' % self.LINKS[k]['params2']['ip'].split('/')[0],
                              **v) for k, v in self.HOSTS.items()]

        for host in sorted(hosts):
            self.addLink(host, router, **self.LINKS[host])

    def set_macs(self, net):
        r0 = net.get('r0')
        for intf, mac in self.ROUTER_MACS.items():
            r0.intf(intf).setMAC(mac)

    def disable_offload(self, net):
        for host in self.HOSTS:
            h = net.get(host)
            h.cmd("ethtool -K {}-eth0 rx off tx off".format(host))
            h.cmd('echo "0" > /proc/sys/net/ipv4/tcp_timestamps')

def simpleTest():
    "Create and test a simple network"
    topo = RouterStarTopo()
    net = Mininet(topo)
    net.staticArp()
    net.start()
    #topo.setIp(net)

    #net.get('h2').cmd('bash proxy/set_nat.sh')

    topo.disable_offload(net)
    topo.set_macs(net)

    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    CLI(net)
    print "Testing network connectivity"
    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()

