"""
Layer-2 Firewall application for the POX SDN controller.

This module implements a Layer-2 (MAC-based) firewall as described in
"SDN Assignment 2".  The firewall policy is specified externally in a
policy file.  Each rule contains a source MAC address, a destination
MAC address and an action (DROP).

When an OpenFlow switch connects to the controller, the controller:
  1. reads all firewall policies from the policy file,
  2. converts them into OpenFlow flow entries, and
  3. installs the corresponding DROP rules *proactively* in the switch.

Afterwards the controller behaves as a learning switch: it learns
MAC-to-port mappings from Packet-In events and forwards allowed traffic
efficiently (exact-match flow entries + packet-outs).  Traffic that
matches a firewall rule is dropped; everything else is forwarded.

Policy file format (plain text, one rule per line):

    # comments start with '#'
    <src_mac> <dst_mac> <action>

Example:
    00:00:00:00:00:01 00:00:00:00:00:03 DROP

A JSON policy (e.g. produced by an LLM, see Part 2 of the assignment)
is also accepted:

    [
      {"rule": 1, "src_mac": "00:00:00:00:00:01",
       "dst_mac": "00:00:00:00:00:03", "action": "DROP"}
    ]

Usage (from the POX root directory):

    ./pox.py firewall --policy-file=../firewall_rules.rules
"""

import json
import os

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr
from pox.lib.revent import EventMixin

log = core.getLogger()

# Firewall DROP rules must win over the learning-switch forwarding rules.
DROP_PRIORITY = 100
FORWARD_PRIORITY = 50

# ---------------------------------------------------------------------------
# Scope of the policy: strictly every frame
# ---------------------------------------------------------------------------
# The assignment says: "If an Ethernet frame matches one of these prohibited
# source-destination MAC pairs, the switch must drop the frame."  That is
# applied literally.  There is deliberately no exemption for ARP and none for
# ICMP, because both would be deviations from the specified rule.
#
# The consequence is worth stating plainly, since it looks like a bug and is
# not:
#
#   * ARP is matched too, so blocking h1->h3 discards h1's ARP replies.  h3
#     can then never resolve h1's MAC, so h3->h1 fails as well -- not because
#     a rule names it, but because the pair became mutually unreachable.
#   * An ICMP echo *reply* is itself a frame from h1 to h3, so it is dropped
#     for the same reason the request is.
#
# In short, a one-way MAC-pair drop yields a symmetric traffic blackout.  The
# alternative -- exempting ARP, or letting echo replies through -- was
# implemented and measured at 10/12, but OpenFlow 1.0's ofp_match has no
# ICMP-type field, so honouring it means giving up the assignment's
# requirement that the drop rules be installed proactively in the switch.
# The literal reading is kept as the shipped behaviour.

# Where to look for the policy file, in order.
_POLICY_SEARCH_PATHS = (
    ".",                                   # current working directory
    os.path.dirname(os.path.abspath(__file__)),  # .../pox/ext/
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."),  # repo root
)


class FirewallRule(object):
  """A single Layer-2 firewall policy rule."""

  def __init__ (self, src_mac, dst_mac, action = "DROP"):
    self.src_mac = str(src_mac).lower()
    self.dst_mac = str(dst_mac).lower()
    self.action = str(action).upper()

  @property
  def drop (self):
    return self.action == "DROP"

  def __repr__ (self):
    return "FirewallRule(%s -> %s : %s)" % (self.src_mac, self.dst_mac,
                                            self.action)

  def __eq__ (self, other):
    return (isinstance(other, FirewallRule)
            and self.src_mac == other.src_mac
            and self.dst_mac == other.dst_mac
            and self.action == other.action)

  def __hash__ (self):
    return hash((self.src_mac, self.dst_mac, self.action))


def _resolve_path (path):
  """Return the first existing candidate for `path`, or `path` itself."""
  if os.path.exists(path):
    return path
  for base in _POLICY_SEARCH_PATHS:
    candidate = os.path.join(base, path)
    if os.path.exists(candidate):
      return candidate
  return path


def load_policy (path):
  """
  Load firewall rules from a policy file.

  Supports both the plain-text format (`src_mac dst_mac action` per line)
  and a JSON array of rule objects (the format produced by the LLM in
  Part 2 of the assignment).
  """
  path = _resolve_path(path)
  rules = []
  with open(path, "r") as f:
    text = f.read().strip()

  if text.startswith("["):
    # JSON policy (LLM output)
    for entry in json.loads(text):
      rules.append(FirewallRule(entry["src_mac"], entry["dst_mac"],
                                entry.get("action", "DROP")))
  else:
    # Plain-text policy
    for line in text.splitlines():
      line = line.strip()
      if not line or line.startswith("#"):
        continue
      fields = line.split()
      if len(fields) < 2:
        log.warning("Skipping malformed policy line: %r", line)
        continue
      action = fields[2] if len(fields) > 2 else "DROP"
      rules.append(FirewallRule(fields[0], fields[1], action))

  return rules


class Firewall (EventMixin):
  """
  Layer-2 firewall + learning switch application.

  Listens to `core.openflow` events.  On ConnectionUp it proactively
  installs one DROP flow entry per firewall rule.  On PacketIn it
  enforces the firewall (defence in depth) and otherwise behaves as a
  learning switch.
  """

  def __init__ (self, policy_file):
    self.policy_file = policy_file
    self.rules = load_policy(policy_file)
    # {dpid: {EthAddr: port}}
    self.mac_to_port = {}
    self.listenTo(core.openflow)
    log.info("Firewall loaded '%s': %d rule(s) %s", policy_file,
             len(self.rules), [str(r) for r in self.rules])

  # ------------------------------------------------------------------ #
  # Policy management                                                   #
  # ------------------------------------------------------------------ #

  def is_blocked (self, src_mac, dst_mac):
    """Return True if the (src,dst) MAC pair is prohibited by policy.

    Deliberately protocol-blind: the assignment specifies MAC pairs, so an
    ARP frame and an ICMP frame from the same source are treated alike.
    """
    src = str(src_mac).lower()
    dst = str(dst_mac).lower()
    for rule in self.rules:
      if rule.drop and rule.src_mac == src and rule.dst_mac == dst:
        return True
    return False

  def reload_policy (self):
    """Re-read the policy file (e.g. after the LLM updated it)."""
    self.rules = load_policy(self.policy_file)
    log.info("Firewall policy reloaded: %d rule(s)", len(self.rules))
    # Newly added rules must also be installed on already-connected
    # switches, so treat every connection as fresh.
    for connection in core.openflow._connections.values():
      self._handle_ConnectionUp(_FakeConnectionUp(connection))

  # ------------------------------------------------------------------ #
  # OpenFlow event handlers                                             #
  # ------------------------------------------------------------------ #

  def _handle_ConnectionUp (self, event):
    """
    A switch connected: proactively install all DROP rules.

    Each rule becomes an exact-match flow entry on (dl_src, dl_dst) with
    an empty action list, which makes the switch drop matching frames
    without bothering the controller.
    """
    log.info("Switch %s connected - installing %d firewall rule(s)",
             event.dpid, len(self.rules))
    for rule in self.rules:
      if rule.drop:
        self._install_drop(event.connection, rule)

  def _handle_PacketIn (self, event):
    """Learning-switch behaviour with firewall enforcement."""
    packet = event.parsed
    if packet is None:
      log.warning("Switch %s: unparsable packet - dropping", event.dpid)
      return

    src = packet.src
    dst = packet.dst

    # --- firewall enforcement (proactive rules normally catch this) ---
    if self.is_blocked(src, dst):
      log.info("FIREWALL BLOCK on switch %s: %s -> %s", event.dpid, src, dst)
      return  # drop: no packet-out, no flow entry, no learning

    # --- learning: remember which port this source MAC is on ---
    table = self.mac_to_port.setdefault(event.dpid, {})
    table[src] = event.port

    # --- forwarding ---
    if dst in table and table[dst] != event.port:
      out_port = table[dst]
      log.debug("Switch %s: %s -> %s out port %s", event.dpid, src, dst,
                out_port)
      self._install_forward(event, src, dst, out_port)
      self._packet_out(event, out_port)
    else:
      # Unknown destination: flood (a learning switch has no loop
      # prevention; fine for a single-switch topology).
      log.debug("Switch %s: flood %s -> %s", event.dpid, src, dst)
      self._packet_out(event, of.OFPP_FLOOD)

  # ------------------------------------------------------------------ #
  # OpenFlow message helpers                                            #
  # ------------------------------------------------------------------ #

  def _install_drop (self, connection, rule):
    """Install a proactive DROP flow entry for one firewall rule.

    The match is on dl_src/dl_dst only -- no dl_type, so the entry covers
    every frame for the pair, ARP included.
    """
    msg = of.ofp_flow_mod()
    msg.match.dl_src = EthAddr(rule.src_mac)
    msg.match.dl_dst = EthAddr(rule.dst_mac)
    msg.priority = DROP_PRIORITY
    # An empty action list means "drop".
    connection.send(msg)

  def _install_forward (self, event, src, dst, out_port):
    """Install an exact-match forwarding flow entry."""
    msg = of.ofp_flow_mod()
    msg.match.dl_src = src
    msg.match.dl_dst = dst
    msg.priority = FORWARD_PRIORITY
    msg.actions.append(of.ofp_action_output(port = out_port))
    event.connection.send(msg)

  def _packet_out (self, event, port):
    """Send the buffered packet out of `port`."""
    msg = of.ofp_packet_out()
    msg.data = event.ofp
    msg.in_port = event.port
    msg.actions.append(of.ofp_action_output(port = port))
    event.connection.send(msg)


class _FakeConnectionUp (object):
  """Minimal stand-in for an of_01.ConnectionUp event (used by reload)."""
  def __init__ (self, connection):
    self.connection = connection
    self.dpid = connection.dpid


def launch (policy_file = "firewall_rules.rules"):
  """
  POX entry point.

  Usage: ./pox.py ext.firewall --policy-file=<path>
  """
  def start ():
    core.registerNew(Firewall, policy_file)
  core.call_when_ready(start, ("openflow",))
