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

The switch is *our* pure-Python OpenFlow 1.0 switch (oswitch.py) rather
than ofdatapath, so it runs in the root namespace (inNamespace=False) and
can reach the controller at 127.0.0.1:6633.

Usage (from the project root, inside a user namespace):

    unshare -Urn mn --custom topo2.py --topo fourhost \
            --controller remote,ip=127.0.0.1,port=6633
"""

import os
import time

from mininet.node import UserSwitch
from mininet.topo import Topo

# Path to our Python OpenFlow switch, next to this file.
# NOTE: `mn --custom` loads this module by exec()ing its source, so __file__
# is not always defined -- fall back to the current working directory (which
# is the project root for every entry point we ship).
def _project_dir():
  """Directory holding this file, robust to being exec()'d by `mn --custom`."""
  here = os.path.dirname(os.path.abspath(__file__)) \
      if '__file__' in globals() else ''
  if here and os.path.exists(os.path.join(here, 'oswitch.py')):
    return here
  return os.getcwd()


_HERE = _project_dir()
OSWITCH_PATH = os.path.join(_HERE, 'oswitch.py')

# The MAC database used by the assignment (and given to the LLM in Part 2).
HOST_MACS = {
  "h1": "00:00:00:00:00:01",
  "h2": "00:00:00:00:00:02",
  "h3": "00:00:00:00:00:03",
  "h4": "00:00:00:00:00:04",
}


class PythonSwitch(UserSwitch):
  """
  User-space switch that runs our Python OpenFlow switch (oswitch.py)
  instead of Mininet's bundled ofdatapath/ofprotocol.
  """

  def start(self, controllers):
    clist = ','.join(['%s:%d' % (c.IP(), c.port) for c in controllers])
    port_args = ' '.join(
      '--port %d:%s' % (self.ports[intf], intf.name)
      for intf in self.intfList() if intf.name != 'lo')
    # Launch oswitch.py in the background within this switch's namespace.
    # Logs go to the project's logs/ dir (not /tmp) so they survive the
    # network namespace and can be collected as evidence.
    LOG_PATH = os.path.join(_HERE, 'logs', 'oswitch.log')
    self.cmd('mkdir -p %s && nohup python3 %s --controller %s --dpid %s %s '
             '> %s 2>&1 &' % (os.path.dirname(LOG_PATH), OSWITCH_PATH,
                              clist, self.dpid, port_args, LOG_PATH))
    time.sleep(1)  # Give the switch time to start

  def stop(self, deleteIntfs=True):
    """Stop the Python OpenFlow switch."""
    self.cmd('pkill -f oswitch.py')
    super(PythonSwitch, self).stop(deleteIntfs)


class FourHostTopo(Topo):
  "Single switch with four hosts, each with a fixed MAC address."

  def build(self):
    s1 = self.addSwitch("s1", cls=PythonSwitch, inNamespace=False)
    for name in ("h1", "h2", "h3", "h4"):
      h = self.addHost(name, mac=HOST_MACS[name])
      self.addLink(name, s1)


# Make the topology usable with `--topo fourhost`
topos = {"fourhost": (lambda: FourHostTopo())}

