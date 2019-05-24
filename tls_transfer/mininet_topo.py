#!/usr/bin/env python
'''
client (h1) -- proxy host (h2)
                   |
             h3 ---|--- h4
'''
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI

class SingleSwitchTopo(Topo):
    "Single switch connected to n hosts."
    def build(self):
        switch = self.addSwitch('s1')
        # Python's range(N) generates 0..N-1
        h1 = self.addHost('h1', ip='10.0.0.10')
        h2 = self.addHost('h2', ip='10.0.0.2', mac='00:00:00:00:00:AA')
        h3 = self.addHost('h3', ip='10.0.0.3', mac='00:00:00:00:00:BB')
        h4 = self.addHost('h4', ip='10.0.0.4', mac='00:00:00:00:00:CC')


        self.addLink(h1, switch)
        self.addLink(h2, switch, port2=2)
        self.addLink(h3, switch, port2=3)
        self.addLink(h4, switch, port2=4)

    def setArp(self, net):
        #net.get('h1').cmd('arp -s %s %s' % ('10.0.0.2', '00:00:00:00:00:AA'))
        #net.get('s1').cmd('ovs-ofctl add-flow s1 dl_dst=11:22:33:44:55:66,actions=output:1')
        net.get('s1').cmd('ovs-ofctl add-flow s1 dl_dst=00:00:00:00:00:AA,actions=output:2')
        net.get('s1').cmd('ovs-ofctl add-flow s1 dl_dst=00:00:00:00:00:BB,actions=output:3')
        net.get('s1').cmd('ovs-ofctl add-flow s1 dl_dst=00:00:00:00:00:CC,actions=output:4')

    def setIp(self, net):
        net.get('h2').cmd('ip addr add 10.0.0.1/8 dev h2-eth0')
        net.get('h3').cmd('ip addr add 10.0.0.1/8 dev h3-eth0')
        net.get('h4').cmd('ip addr add 10.0.0.1/8 dev h4-eth0')

def simpleTest():
    "Create and test a simple network"
    topo = SingleSwitchTopo()
    net = Mininet(topo)
    net.start()
    topo.setArp(net)
    topo.setIp(net)

    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    CLI(net)
    print "Testing network connectivity"
    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()

