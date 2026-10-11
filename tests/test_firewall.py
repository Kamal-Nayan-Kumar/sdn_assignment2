"""
Offline tests for the POX Layer-2 firewall application.

These tests simulate an OpenFlow switch (fake connection + fake
events) and drive the Firewall application directly, so the
firewall logic can be verified without Mininet/OVS.

Run from the repository root:

    .venv/bin/python -m pytest tests/test_firewall.py -v
"""

import sys
from pathlib import Path

# Make the POX tree importable: <repo>/pox contains the `pox`
# package and the `ext` package (with our firewall app).
REPO_ROOT = Path(__file__).resolve().parents[1]
POX_ROOT = REPO_ROOT / "pox"
sys.path.insert(0, str(POX_ROOT))

from pox.core import core                                  # noqa: E402
from pox.lib.revent import EventMixin                      # noqa: E402
import pox.openflow.libopenflow_01 as of                   # noqa: E402
from pox.lib.packet.ethernet import ethernet               # noqa: E402
from pox.lib.addresses import EthAddr                      # noqa: E402

import ext.firewall as firewall                            # noqa: E402

H1 = "00:00:00:00:00:01"
H2 = "00:00:00:00:00:02"
H3 = "00:00:00:00:00:03"
H4 = "00:00:00:00:00:04"


# ---------------------------------------------------------------------- #
# Fake OpenFlow machinery                                                #
# ---------------------------------------------------------------------- #

class FakeOpenFlowComponent(EventMixin):
  """Stands in for core.openflow so the Firewall can listen to it."""
  _eventMixin_events = set()

  def __init__(self):
    self._connections = {}


class FakeConnection(object):
  """Records every OpenFlow message the controller sends."""

  def __init__(self, dpid=1):
    self.dpid = dpid
    self.sent = []

  def send(self, msg):
    self.sent.append(msg)

  @property
  def flow_mods(self):
    return [m for m in self.sent if isinstance(m, of.ofp_flow_mod)]

  @property
  def packet_outs(self):
    return [m for m in self.sent if isinstance(m, of.ofp_packet_out)]


class FakeEvent(object):
  """Minimal ConnectionUp / PacketIn event."""

  def __init__(self, connection, dpid=None, port=None,
               parsed=None, ofp=None):
    self.connection = connection
    self.dpid = dpid if dpid is not None else connection.dpid
    self.port = port
    self.parsed = parsed
    self.ofp = ofp if ofp is not None else b"\x00" * 64


def make_packet(src, dst, ethertype=ethernet.IP_TYPE):
  pkt = ethernet()
  pkt.src = EthAddr(src)
  pkt.dst = EthAddr(dst)
  pkt.type = ethertype
  pkt.parsed = True
  return pkt


def make_firewall(policy_file=None):
  """Start a fresh Firewall app with a fake openflow component."""
  if "openflow" not in core.components:
    core.register("openflow", FakeOpenFlowComponent())
  return firewall.Firewall(policy_file or str(REPO_ROOT /
                                               "firewall_rules.rules"))


# ---------------------------------------------------------------------- #
# Tests                                                                #
# ---------------------------------------------------------------------- #

def test_policy_file_loads():
  fw = make_firewall()
  assert len(fw.rules) == 2
  assert firewall.FirewallRule(H1, H3, "DROP") in fw.rules
  assert firewall.FirewallRule(H2, H4, "DROP") in fw.rules
  assert fw.is_blocked(H1, H3)
  assert fw.is_blocked(H2, H4)
  assert not fw.is_blocked(H1, H2)
  assert not fw.is_blocked(H3, H1)      # rules are directional


def test_policy_file_loads_json_format():
  """The live policy file on disk (LLM output) must load too."""
  live = REPO_ROOT / "firewall_rules.rules"
  rules = firewall.load_policy(str(live))
  assert len(rules) == 2
  assert firewall.FirewallRule(H1, H3, "DROP") in rules
  assert firewall.FirewallRule(H2, H4, "DROP") in rules


def test_json_policy_loads():
  import json, tempfile, os
  llm_output = json.dumps([
    {"rule": 1, "src_mac": H1, "dst_mac": H3, "action": "DROP"},
    {"rule": 2, "src_mac": H2, "dst_mac": H4, "action": "DROP"},
  ])
  with tempfile.NamedTemporaryFile("w", suffix=".json",
                                   delete=False) as f:
    f.write(llm_output)
    path = f.name
  try:
    fw = make_firewall(path)
    assert len(fw.rules) == 2
    assert fw.is_blocked(H1, H3)
    assert fw.is_blocked(H2, H4)
  finally:
    os.unlink(path)


def test_connectionup_installs_proactive_drop_rules():
  fw = make_firewall()
  conn = FakeConnection(dpid=1)
  fw._handle_ConnectionUp(FakeEvent(conn, dpid=1))

  drops = conn.flow_mods
  assert len(drops) == 2, "expected one DROP flow per rule"

  matches = sorted((str(m.match.dl_src), str(m.match.dl_dst))
                   for m in drops)
  assert matches == sorted([(H1, H3), (H2, H4)])

  for m in drops:
    assert m.priority >= firewall.DROP_PRIORITY
    assert len(m.actions) == 0, "DROP flow must have empty action list"


def test_blocked_frames_are_dropped():
  fw = make_firewall()
  conn = FakeConnection(dpid=1)
  fw._handle_ConnectionUp(FakeEvent(conn, dpid=1))

  # h1 -> h3 : prohibited
  pkt = make_packet(H1, H3)
  fw._handle_PacketIn(FakeEvent(conn, dpid=1, port=1, parsed=pkt))
  assert conn.packet_outs == [], "blocked frame must not be forwarded"
  assert len(conn.flow_mods) == 2, "no new flow entries expected"
  assert H1 not in fw.mac_to_port.get(1, {}), \
      "blocked traffic must not be learned"

  # h2 -> h4 : prohibited
  pkt = make_packet(H2, H4)
  before = len(conn.sent)
  fw._handle_PacketIn(FakeEvent(conn, dpid=1, port=2, parsed=pkt))
  assert len(conn.sent) == before, "blocked frame must not be forwarded"


def test_allowed_traffic_is_learned_and_forwarded():
  fw = make_firewall()
  conn = FakeConnection(dpid=1)
  fw._handle_ConnectionUp(FakeEvent(conn, dpid=1))

  # h1 -> h2, controller doesn't know where h2 is yet => flood
  pkt = make_packet(H1, H2)
  fw._handle_PacketIn(FakeEvent(conn, dpid=1, port=1, parsed=pkt))
  assert len(conn.packet_outs) == 1
  assert conn.packet_outs[0].actions[0].port == of.OFPP_FLOOD
  assert fw.mac_to_port[1][EthAddr(H1)] == 1

  # h2 -> h1 : now h1 is known on port 1 => forward + install flow
  pkt = make_packet(H2, H1)
  fw._handle_PacketIn(FakeEvent(conn, dpid=1, port=2, parsed=pkt))
  assert fw.mac_to_port[1][EthAddr(H2)] == 2

  outs = conn.packet_outs
  assert len(outs) == 2
  assert outs[1].actions[0].port == 1, "packet must go out port 1"

  fwd = [m for m in conn.flow_mods if len(m.actions) > 0]
  assert len(fwd) == 1, "expected one forwarding flow entry"
  assert str(fwd[0].match.dl_src) == H2
  assert str(fwd[0].match.dl_dst) == H1
  assert fwd[0].actions[0].port == 1


def test_allowed_traffic_between_blocked_pairs_neighbours():
  """h1->h2, h3->h4 etc. must all work (only 2 pairs are blocked)."""
  fw = make_firewall()
  conn = FakeConnection(dpid=1)
  fw._handle_ConnectionUp(FakeEvent(conn, dpid=1))

  for src, dst in [(H1, H2), (H1, H4), (H3, H1), (H3, H2), (H3, H4)]:
    pkt = make_packet(src, dst)
    fw._handle_PacketIn(FakeEvent(conn, dpid=1, port=1, parsed=pkt))
    assert len(conn.packet_outs) >= 1
    conn.packet_outs.clear()

  assert not fw.is_blocked(H1, H2)
  assert not fw.is_blocked(H3, H4)
