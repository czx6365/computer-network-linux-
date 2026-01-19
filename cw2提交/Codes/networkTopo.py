#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Simple SDN Topology for CAN201 Part II
Three-host topology: Client connected to two servers via a single switch
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class SimpleSDNTopo(Topo):
    """Client - Switch - Server1/Server2 topology configuration"""

    def build(self):
        # Configure hosts with specified IP and MAC addresses
        client = self.addHost(
            'Client',
            ip='10.0.1.5/24',
            mac='00:00:00:00:00:03'
        )

        server1 = self.addHost(
            'Server1',
            ip='10.0.1.2/24',
            mac='00:00:00:00:00:01'
        )

        server2 = self.addHost(
            'Server2',
            ip='10.0.1.3/24',
            mac='00:00:00:00:00:02'
        )

        # Single OpenFlow switch
        s1 = self.addSwitch('s1')

        # Network links
        self.addLink(client, s1)
        self.addLink(server1, s1)
        self.addLink(server2, s1)


def run():
    """Initialize and start Mininet network"""
    topo = SimpleSDNTopo()

    # Create Mininet with remote controller for Ryu
    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSKernelSwitch,
        autoSetMacs=False,
        autoStaticArp=False
    )

    # Remote controller (default Ryu: 127.0.0.1:6633)
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    net.start()

    info('\n*** Host IP/MAC information:\n')
    for host in net.hosts:
        info('%s: IP=%s, MAC=%s\n' % (host.name, host.IP(), host.MAC()))

    # Enter CLI for network testing
    CLI(net)

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()