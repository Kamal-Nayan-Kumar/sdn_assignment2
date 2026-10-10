#!/usr/bin/env python3
"""
Mininet integration for SDN Assignment 2 using the Python OpenFlow switch.

This script creates a Mininet network with 4 hosts and 1 switch,
where the switch is our pure-Python OpenFlow 1.0 switch (oswitch.py).

Usage (from the project root, inside a user namespace):
    unshare -Urn python3 run_demo.py
"""

import os
import sys
import time
from functools import partial

from mininet.net import Mininet
from mininet.node import UserSwitch, RemoteController
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel, info, debug

# Path to our Python OpenFlow switch
OSWITCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'oswitch.py')

# Host MAC addresses (as specified in the assignment)
HOST_MACS = {
    'h1': '00:00:00:00:00:01',
    'h2': '00:00:00:00:00:02',
    'h3': '00:00:00:00:00:03',
    'h4': '00:00:00:00:00:04',
}


class PythonSwitch(UserSwitch):
    """User-space switch that runs our Python OpenFlow switch."""

    def start(self, controllers):
        """Start the Python OpenFlow switch instead of ofdatapath/ofprotocol."""
        clist = ','.join(['%s:%d' % (c.IP(), c.port) for c in controllers])
        port_args = ' '.join(
            '--port %d:%s' % (self.ports[intf], intf.name)
            for intf in self.intfList() if intf.name != 'lo')
        # Launch our switch in the background within this switch's namespace
        self.cmd('nohup python3 %s --controller %s --dpid %s %s '
                  '> /tmp/oswitch.log 2>&1 &' % (OSWITCH_PATH, clist, self.dpid, port_args))
        time.sleep(1)  # Give the switch time to start

    def stop(self, deleteIntfs=True):
        """Stop the Python OpenFlow switch."""
        self.cmd('pkill -f oswitch.py')
        super(PythonSwitch, self).stop(deleteIntfs)


class FourHostTopo(Topo):
    """Single switch with four hosts, each with a fixed MAC address."""

    def build(self):
        # inNamespace=False so the switch runs in the root namespace
        # and can reach the controller at 127.0.0.1:6633
        s1 = self.addSwitch('s1', cls=PythonSwitch, inNamespace=False)
        for name in ('h1', 'h2', 'h3', 'h4'):
            self.addHost(name, mac=HOST_MACS[name])
            self.addLink(name, s1)


topos = {'fourhost': (lambda: FourHostTopo())}


if __name__ == '__main__':
    setLogLevel('info')

    net = Mininet(topo=FourHostTopo(), switch=PythonSwitch,
                  controller=partial(RemoteController, ip='127.0.0.1', port=6633))

    info('*** Starting network\n')
    net.start()

    info('*** Testing connectivity\n')
    net.pingAll()

    info('*** Running CLI (type "exit" to quit)\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()
