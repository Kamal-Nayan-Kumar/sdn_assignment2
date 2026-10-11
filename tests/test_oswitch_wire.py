"""Wire-format tests for oswitch.py.

Every OpenFlow 1.0 struct we pack or unpack is checked against POX's own
`pox.openflow.libopenflow_01` definitions, so a layout bug in oswitch.py
shows up here as a size mismatch instead of an AssertionError deep inside
POX's `_readzs()`.
"""

import os
import struct
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, 'pox'))

import oswitch  # noqa: E402

lib = pytest.importorskip('pox.openflow.libopenflow_01',
                          reason='POX not importable')


# --------------------------------------------------------------------------- #
# Sizes match the OpenFlow 1.0 specification                                  #
# --------------------------------------------------------------------------- #
def test_fixed_struct_sizes_match_spec():
    assert oswitch.OFP_MATCH_SZ == 40        # ofp_match
    assert oswitch.OFP_FLOW_MOD_SZ == 24     # cookie(8)+command(2)+idle(2)+
                                             # hard(2)+prio(2)+buf(4)+out(2)+
                                             # flags(2)
    assert oswitch.OFP_PHY_PORT_SZ == 48     # ofp_phy_port
    assert oswitch.OFP_PACKET_OUT_SZ == 8    # buffer_id+in_port+actions_len
    assert oswitch.OFP_PACKET_IN_SZ == 10    # buffer_id+total_len+in_port+
                                             # reason+pad
    assert oswitch.DESC_LEN == 1056          # 4*256 + 32


def test_wildcard_bits_agree_with_pox():
    """Our wildcard numbers must be POX's, or every rule is mis-parsed."""
    assert oswitch.OFPFW_IN_PORT == lib.OFPFW_IN_PORT
    assert oswitch.OFPFW_DL_VLAN == lib.OFPFW_DL_VLAN
    assert oswitch.OFPFW_DL_SRC == lib.OFPFW_DL_SRC
    assert oswitch.OFPFW_DL_DST == lib.OFPFW_DL_DST
    assert oswitch.OFPFW_DL_TYPE == lib.OFPFW_DL_TYPE


def test_cookie_is_eight_bytes():
    """Regression: cookie was once packed with 'I' (4 bytes).

    That made the FLOW_MOD command section 20 bytes long and shifted every
    following field, which POX reported as an AssertionError in _readzs().
    """
    cookie, command, idle, hard, prio, buf, out_port, flags = \
        struct.unpack(oswitch.OFP_FLOW_MOD_FMT,
                      struct.pack(oswitch.OFP_FLOW_MOD_FMT,
                                  0x0102030405060708, 0, 0, 0, 100, 0, 0, 0))
    assert cookie == 0x0102030405060708


# --------------------------------------------------------------------------- #
# Sizes match what POX expects                                                #
# --------------------------------------------------------------------------- #
def test_sizes_match_pox_definitions():
    """POX's message lengths include the 8-byte header; ours are bodies."""
    assert len(lib.ofp_match()) == oswitch.OFP_MATCH_SZ
    assert len(lib.ofp_flow_mod()) - 8 == oswitch.OFP_MATCH_SZ + \
        oswitch.OFP_FLOW_MOD_SZ
    assert len(lib.ofp_phy_port()) == oswitch.OFP_PHY_PORT_SZ
    assert len(lib.ofp_packet_out()) - 8 == oswitch.OFP_PACKET_OUT_SZ
    assert len(lib.ofp_packet_in()) - 8 == oswitch.OFP_PACKET_IN_SZ
    assert len(lib.ofp_desc_stats()) == oswitch.DESC_LEN


def test_features_reply_body_parses_in_pox():
    """A FEATURES_REPLY we build must survive POX's parser verbatim."""
    sw = oswitch.OFSwitch.__new__(oswitch.OFSwitch)   # no sockets needed
    sw.dpid = 1
    sw.n_buffers, sw.n_tables = oswitch.OFP_NO_BUFFER, 1
    sw.capabilities, sw.actions = 0, 0
    sw.ports = {1: 's1-eth1', 2: 's1-eth2'}

    class _Ctrl:
        def __init__(self):
            self.sent = b''

        def send(self, data):
            self.sent += data

    sw.ctrl = _Ctrl()
    sw.handle_features_request(7)

    raw = sw.ctrl.sent
    version, msg_type, length, xid = struct.unpack('!BBHI', raw[:8])
    assert (version, msg_type, xid) == (oswitch.OFP_VERSION,
                                         oswitch.OFPT_FEATURES_REPLY, 7)
    assert length == len(raw)

    # ...and POX must agree on the length it computes.
    msg = lib.ofp_switch_features()
    msg.unpack(raw, 0)
    assert msg.datapath_id == 1
    assert msg.n_buffers == oswitch.OFP_NO_BUFFER
    assert msg.n_tables == 1
    assert len(msg.ports) == 2
    assert {p.port_no for p in msg.ports} == {1, 2}
    assert len(msg) == length


def test_flow_mod_packed_by_pox_parses_in_oswitch():
    """A FLOW_MOD POX generates must land in oswitch at the right offsets."""
    from pox.lib.addresses import EthAddr
    # adjust_wildcards=False keeps dl_src/dl_dst out of the wildcard mask,
    # which is what a firewall DROP rule needs (exact-match on both).
    m = lib.ofp_match(dl_src=EthAddr('00:00:00:00:00:01'),
                      dl_dst=EthAddr('00:00:00:00:00:03'))
    m.wildcards = lib.OFPFW_ALL & ~(lib.OFPFW_DL_SRC | lib.OFPFW_DL_DST)
    m.adjust_wildcards = False
    fm = lib.ofp_flow_mod(match=m, cookie=0xdeadbeefcafe0001,
                          priority=100, command=lib.OFPFC_ADD)
    fm.actions = [lib.ofp_action_output(port=lib.OFPP_NONE)]
    raw = fm.pack()
    body = raw[8:]                      # strip the 8-byte header

    parsed_cookie, command, _idle, _hard, priority, _buf, _out, _flags = \
        struct.unpack(oswitch.OFP_FLOW_MOD_FMT,
                      body[oswitch.OFP_MATCH_SZ:
                           oswitch.OFP_MATCH_SZ + oswitch.OFP_FLOW_MOD_SZ])
    (wildcards, _in_port, dl_src, dl_dst, _vlan, _pcp,
     _dtype, _tos, _proto, _nsrc, _ndst, _psrc, _pdst) = \
        struct.unpack(oswitch.OFP_MATCH_FMT, body[:oswitch.OFP_MATCH_SZ])

    assert parsed_cookie == 0xdeadbeefcafe0001
    assert command == lib.OFPFC_ADD
    assert priority == 100
    assert dl_src == bytes.fromhex('000000000001')
    assert dl_dst == bytes.fromhex('000000000003')
    assert not wildcards & (oswitch.OFPFW_DL_SRC | oswitch.OFPFW_DL_DST)


def test_stats_reply_layout_is_type_flags_then_body():
    """STATS_REPLY = header(8) + type(2) + flags(2) + body."""
    sw = oswitch.OFSwitch.__new__(oswitch.OFSwitch)
    sw.mfr_desc, sw.hw_desc, sw.sw_desc = 'a', 'b', 'c'
    sw.serial_num, sw.dp_desc = '1', '2'

    class _Ctrl:
        def __init__(self):
            self.sent = b''

        def send(self, data):
            self.sent += data

    sw.ctrl = _Ctrl()
    sw.handle_stats_request(3, struct.pack('!HH', lib.OFPST_DESC, 0) + b'')

    version, msg_type, length, xid = struct.unpack('!BBHI', sw.ctrl.sent[:8])
    stats_type, flags = struct.unpack('!HH', sw.ctrl.sent[8:12])
    assert (version, msg_type, xid) == (oswitch.OFP_VERSION,
                                        oswitch.OFPT_STATS_REPLY, 3)
    assert stats_type == lib.OFPST_DESC and flags == 0
    assert length == 12 + oswitch.DESC_LEN == len(sw.ctrl.sent)

    # POX must parse it without an UnderrunError.
    msg = lib.ofp_stats_reply()
    msg.unpack(sw.ctrl.sent, 0)
    assert msg.type == lib.OFPST_DESC
    assert msg.body.mfr_desc == 'a'
    assert len(msg) == length


# --------------------------------------------------------------------------- #
# Match semantics                                                              #
# --------------------------------------------------------------------------- #
def _frame(dst='00:00:00:00:00:03', src='00:00:00:00:00:01', ethertype=0x0806):
    return (bytes.fromhex(dst.replace(':', '')) +
            bytes.fromhex(src.replace(':', '')) +
            struct.pack('!H', ethertype))


def _match(**kw):
    base = {'wildcards': 0, 'in_port': 0, 'dl_src': b'\x00' * 6,
            'dl_dst': b'\x00' * 6, 'dl_vlan': 0, 'dl_type': 0,
            'nw_src': 0, 'nw_dst': 0, 'tp_src': 0, 'tp_dst': 0}
    base.update(kw)
    return base


def test_exact_mac_match():
    flow = oswitch.FlowEntry(_match(dl_src=bytes.fromhex('000000000001'),
                                    dl_dst=bytes.fromhex('000000000003')),
                             [('output', 4)], priority=100)
    assert flow.matches(1, _frame())
    assert not flow.matches(1, _frame(src='00:00:00:00:00:02'))
    assert not flow.matches(1, _frame(dst='00:00:00:00:00:04'))


def test_wildcarded_fields_are_not_compared():
    """A controller may set a value *and* wildcard it; wildcards win."""
    flow = oswitch.FlowEntry(_match(dl_src=bytes.fromhex('000000000001'),
                                    dl_dst=bytes.fromhex('000000000003'),
                                    wildcards=oswitch.OFPFW_DL_SRC),
                             [('output', 4)], priority=10)
    # dl_src is wildcarded, so the source MAC must not matter...
    assert flow.matches(1, _frame(src='00:00:00:00:00:02'))
    assert flow.matches(1, _frame(src='00:00:00:00:00:09'))
    # ...but dl_dst still does.
    assert not flow.matches(1, _frame(dst='00:00:00:00:00:04'))
