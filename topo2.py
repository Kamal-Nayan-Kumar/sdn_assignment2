"""
Custom Mininet topology for SDN Assignment 2.

    h1 ---+
    h2 ---+--- s1 (OpenFlow switch)  --- POX controller (remote)
    h3 ---+
    h4 ---+

Four hosts, each with a well-known MAC address:

    h1 = 00:00:00:00:00:01
    h2 = 00:00:00:00:00:02
    h3 = 00:00:00:00:00:03
    h4 = 00:00:00:00:00:04

Usage:

    sudo mn --custom topo2.py --topo fourhost \
            --switch user --controller remote,ip=127.0.0.1,port=6633
"""

from mininet.topo import Topo

# The MAC database used by the assignment (and given to the LLM in Part 2).
HOST_MACS = {
  "h1": "00:00:00:00:00:01",
  "h2": "00:00:00:00:00:02",
  "h3": "00:00:00:00:00:03",
  "h4": "00:00:00:00:00:04",
}


class FourHostTopo(Topo):
  "Single switch with four hosts, each with a fixed MAC address."

  def build(self):
    s1 = self.addSwitch("s1")
    for name in ("h1", "h2", "h3", "h4"):
      self.addHost(name, mac=HOST_MACS[name])
      self.addLink(name, s1)


# Make the topology usable with `--topo fourhost`
topos = {"fourhost": (lambda: FourHostTopo())}
