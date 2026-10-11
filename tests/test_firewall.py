"""
Offline tests for the POX Layer-2 firewall application.

These tests simulate an OpenFlow switch (fake connection + fake
events) and drive the Firewall application directly, so the
firewall logic can be verified without Mininet/OVS.

Run from the repository root:

    .venv/bin/python -m pytest tests/test_firewall.py -v
"""

import shutil
import sys
from pathlib import Path

# Make the POX tree importable: <repo>/pox contains the `pox` package.
REPO_ROOT = Path(__file__).resolve().parents[1]
POX_ROOT = REPO_ROOT / "pox"
sys.path.insert(0, str(POX_ROOT))

# The firewall app is tracked at app/firewall.py and copied into pox/ext/ by
# install_firewall_app.sh (upstream POX's own .gitignore contains `ext/*`, so
# pox/ext/ cannot be tracked).  If it has not been installed yet, put it in
# place here so the tests run straight from a fresh clone.
_APP_SRC = REPO_ROOT / "app" / "firewall.py"
_APP_DST = POX_ROOT / "ext" / "firewall.py"
if _APP_SRC.exists() and not _APP_DST.exists():
    _APP_DST.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(str(_APP_SRC), str(_APP_DST))

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


# ---------------------------------------------------------------------- #
# Strict scope: the policy applies to EVERY frame for the pair         #
# ---------------------------------------------------------------------- #

def test_policy_applies_to_arp_too():
  """No ARP exemption.

  The assignment says to drop *frames* matching a prohibited MAC pair.
  ARP frames are frames, so h1's ARP reply to h3 is dropped like any other
  traffic.  Exempting ARP would make h3->h1 reachable and yield 10/12, but
  it would also mean the firewall does not do what it was told to do.
  """
  fw = make_firewall()
  conn = FakeConnection(dpid=1)
  fw._handle_ConnectionUp(FakeEvent(conn, dpid=1))

  arp = make_packet(H1, H3, ethertype=ethernet.ARP_TYPE)
  fw._handle_PacketIn(FakeEvent(conn, dpid=1, port=1, parsed=arp))
  assert conn.packet_outs == [], \
      "ARP from a prohibited pair must be dropped like any other frame"


def test_is_blocked_ignores_protocol():
  """is_blocked() is a pure MAC-pair lookup: no ethertype argument exists.

  This is the contract that makes the behaviour above deliberate rather
  than accidental -- if a protocol parameter is ever reintroduced, this
  signature is what breaks.
  """
  import inspect
  params = list(inspect.signature(
      __import__('ext.firewall', fromlist=['Firewall'])
      .Firewall.is_blocked).parameters)
  assert params == ['self', 'src_mac', 'dst_mac'], \
      "is_blocked() must stay a pure (src,dst) MAC-pair test"


def test_drop_flow_entry_is_not_scoped_by_ethertype():
  """The proactive entry must match the pair regardless of protocol."""
  fw = make_firewall()
  conn = FakeConnection(dpid=1)
  fw._handle_ConnectionUp(FakeEvent(conn, dpid=1))

  drops = conn.flow_mods
  assert len(drops) == 2, "one proactive DROP entry per rule"
  for m in drops:
    assert not m.match.dl_type, \
        "the match must not be narrowed by dl_type, or ARP escapes the rule"
    assert len(m.actions) == 0, "an empty action list means drop"


def test_reverse_direction_is_unreachable_but_unnamed():
  """h3->h1 is not in the policy; it fails only as a downstream effect.

  Blocking h1->h3 discards h1's ARP replies, so h3 never resolves h1's MAC.
  The firewall forwards every h3->h1 frame it is offered; there is simply no
  traffic, because ARP never completed.
  """
  fw = make_firewall()
  assert fw.is_blocked(H3, H1) is False, \
      "no rule names h3->h1; the reverse failure is an ARP consequence"
  assert fw.is_blocked(H1, H3) is True


def test_proactive_drops_are_always_installed():
  """The assignment requires proactive installation on ConnectionUp."""
  fw = make_firewall()
  conn = FakeConnection(dpid=1)
  fw._handle_ConnectionUp(FakeEvent(conn, dpid=1))
  assert len(conn.flow_mods) == 2
