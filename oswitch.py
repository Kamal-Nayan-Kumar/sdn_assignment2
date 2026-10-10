#!/usr/bin/env python3
"""
Minimal OpenFlow 1.0 software switch for testing POX controllers.

This switch implements enough of the OpenFlow 1.0 protocol to work
with the POX controller. It supports:
  - HELLO handshake
  - FEATURES_REPLY
  - FLOW_MOD (install/delete flows)
  - PACKET_OUT (forward buffered or inline packet)
  - PACKET_IN (ask controller for forwarding decision)
  - ECHO_REQUEST/REPLY
  - STATS_REQUEST/REPLY (empty flow stats)
  - BARRIER_REQUEST/REPLY

Usage:
    python3 oswitch.py --controller 127.0.0.1:6633 --dpid 1 \
        --port 1:s1-eth1 --port 2:s1-eth2 --port 3:s1-eth3 --port 4:s1-eth4
"""

import argparse
import os
import select
import signal
import socket
import subprocess
import struct
import sys
import time

# ---- OpenFlow 1.0 constants ----
OFP_VERSION = 0x01

OFPT_HELLO = 0
OFPT_ERROR = 1
OFPT_ECHO_REQUEST = 2
OFPT_ECHO_REPLY = 3
OFPT_VENDOR = 4
OFPT_FEATURES_REQUEST = 5
OFPT_FEATURES_REPLY = 6
OFPT_GET_CONFIG_REQUEST = 7
OFPT_GET_CONFIG_REPLY = 8
OFPT_SET_CONFIG = 9
OFPT_PACKET_IN = 10
OFPT_FLOW_REMOVED = 11
OFPT_PORT_STATUS = 12
OFPT_PACKET_OUT = 13
OFPT_FLOW_MOD = 14
OFPT_PORT_MOD = 15
OFPT_STATS_REQUEST = 16
OFPT_STATS_REPLY = 17
OFPT_BARRIER_REQUEST = 18
OFPT_BARRIER_REPLY = 19

# OFPST_DESC descriptor block: 4x256-byte strings + 32-byte serial.
DESC_LEN = 4 * 256 + 32

OFPFC_ADD = 0
OFPFC_MODIFY = 1
OFPFC_DELETE = 2

OFPP_NONE = 0xfffe
OFPP_FLOOD = 0xfffb
OFPP_ALL = 0xfffc
OFPP_CONTROLLER = 0xfffd

# Match structure (40 bytes):
#   wildcards(4) in_port(2) dl_src(6) dl_dst(6) dl_vlan(2) dl_vlan_pcp(1)
#   pad(1) dl_type(2) nw_tos(1) nw_proto(1) pad(2) nw_src(4) nw_dst(4)
#   tp_src(2) tp_dst(2)
#   tp_src(2) tp_dst(2)
# The match field carries two alignment pads (after dl_vlan_pcp and after
# nw_proto), giving the full 40-byte ofp_match that POX packs.
OFP_MATCH_FMT = '!IH6s6sHBxHBB2xIIHH'
OFP_MATCH_SZ = struct.calcsize(OFP_MATCH_FMT)

# FLOW_MOD command section that follows the match:
#   cookie(8) command(2) idle_timeout(2) hard_timeout(2) priority(2)
#   buffer_id(4) out_port(2) flags(2) = 24 bytes
OFP_FLOW_MOD_FMT = '!QHHHHLHH'
OFP_FLOW_MOD_SZ = struct.calcsize(OFP_FLOW_MOD_FMT)

# Flow mod body after 8-byte header:
#   match(40) cookie(8) command(2) idle(2) hard(2) priority(2)
#   buffer_id(4) out_port(2) flags(2)
OFP_FLOW_MOD_BODY_FMT = '!40sIHHHHHIHH'

# Action output: type(2) len(2) port(2) max_len(2)
OFP_ACTION_OUTPUT_FMT = '!HHHH'


class FlowEntry:
    """A single flow table entry."""

    def __init__(self, match, actions, priority=0, cookie=0):
        self.match = match
        self.actions = actions
        self.priority = priority
        self.cookie = cookie

    def matches(self, in_port, frame):
        """Check if a frame matches this flow entry."""
        m = self.match
        if m['in_port'] and m['in_port'] != in_port:
            return False
        if m['dl_src'] != b'\x00' * 6 and m['dl_src'] != frame[6:12]:
            return False
        if m['dl_dst'] != b'\x00' * 6 and m['dl_dst'] != frame[0:6]:
            return False
        if m['dl_type'] and m['dl_type'] != struct.unpack('!H', frame[12:14])[0]:
            return False
        return True


class OFSwitch:
    """Minimal OpenFlow 1.0 software switch."""

    def __init__(self, controller_host, controller_port, dpid, ports):
        self.controller_addr = (controller_host, controller_port)
        self.dpid = dpid
        self.ports = {}       # port_num -> iface_name
        self.socks = {}       # port_num -> raw socket
        self.flow_table = []  # list of FlowEntry
        self.xid = 1
        self.next_buffer_id = 1
        self.buffers = {}     # buffer_id -> (port_num, frame)
        self.dead_ports = set()  # ports whose socket errored out
        self.ctrl = None

        for port_num, iface in ports:
            self.ports[port_num] = iface

    def log(self, msg):
        print('[oswitch] %s' % msg, flush=True)

    def connect(self):
        """Connect to the controller and send HELLO."""
        self.ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ctrl.connect(self.controller_addr)
        self.ctrl.setblocking(False)
        self.send_hello()
        self.log('Connected to controller %s:%d' % self.controller_addr)

    def send_hello(self):
        msg = struct.pack('!BBHI', OFP_VERSION, OFPT_HELLO, 8, self.xid)
        self.ctrl.send(msg)
        self.xid += 1

    def open_ports(self):
        """Open raw sockets on all data ports.

        Mininet creates the veth pairs but may leave them administratively
        down when the switch process starts, so bring each interface up
        first; otherwise recv() fails with ENETDOWN and no frames are ever
        read.
        """
        for port_num, iface in self.ports.items():
            subprocess.run(['ip', 'link', 'set', iface, 'up'],
                           capture_output=True)
            # The protocol must be in network byte order; passing a bare
            # ETH_P_ALL silently yields a socket that never receives.
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.htons(0x0003))
            s.bind((iface, 0))
            s.setblocking(False)
            self.socks[port_num] = s
            self.log('Opened port %d on %s' % (port_num, iface))

    def send_msg(self, msg_type, body=b''):
        """Send an OpenFlow message to the controller."""
        length = 8 + len(body)
        header = struct.pack('!BBHI', OFP_VERSION, msg_type, length, self.xid)
        self.ctrl.send(header + body)
        self.xid += 1

    def handle_echo_request(self, xid, data):
        """Reply to ECHO_REQUEST with ECHO_REPLY."""
        length = 8 + len(data)
        header = struct.pack('!BBHI', OFP_VERSION, OFPT_ECHO_REPLY, length, xid)
        self.ctrl.send(header + data)

    def handle_features_request(self, xid):
        """Reply to FEATURES_REQUEST with FEATURES_REPLY."""
        # OpenFlow 1.0 FEATURES_REPLY body (fixed 24-byte header):
        #   datapath_id(8) n_buffers(4) n_tables(1) pad(3) capabilities(4) actions(4)
        # n_buffers is 4 bytes (L), not 1 byte (B).
        body = struct.pack('!QLB3sII', self.dpid, 255, 1, b'\x00' * 3, 0, 0)
        for port_num in sorted(self.ports.keys()):
            iface = self.ports[port_num]
            # OpenFlow 1.0 phy_port: port_no(2) hw_addr(6) name(16)
            #   config(4) state(4) curr(4) advertised(4) supported(4) peer(4) = 48 bytes
            port_desc = struct.pack('!H', port_num)
            port_desc += b'\x00' * 6
            # Name field: 16 bytes, null-terminated, zero-padded
            name_bytes = iface.encode()[:15] + b'\x00'
            port_desc += name_bytes.ljust(16, b'\x00')
            port_desc += struct.pack('!IIIIII', 0, 0, 0, 0, 0, 0)
            body += port_desc
        length = 8 + len(body)
        header = struct.pack('!BBHI', OFP_VERSION, OFPT_FEATURES_REPLY, length, xid)
        self.ctrl.send(header + body)

    def handle_flow_mod(self, data):
        """Handle FLOW_MOD from controller."""
        match_data = data[:OFP_MATCH_SZ]
        (wildcards, in_port, dl_src, dl_dst, dl_vlan, dl_vlan_pcp,
         dl_type, nw_tos, nw_proto, nw_src, nw_dst, tp_src, tp_dst) = \
            struct.unpack(OFP_MATCH_FMT, match_data)

        (cookie, command, idle_timeout, hard_timeout, priority,
         buffer_id, out_port, flags) = \
            struct.unpack(OFP_FLOW_MOD_FMT,
                          data[OFP_MATCH_SZ:OFP_MATCH_SZ + OFP_FLOW_MOD_SZ])

        match = {
            'in_port': in_port, 'dl_src': dl_src, 'dl_dst': dl_dst,
            'dl_vlan': dl_vlan, 'dl_type': dl_type,
            'nw_src': nw_src, 'nw_dst': nw_dst,
            'tp_src': tp_src, 'tp_dst': tp_dst,
        }

        actions = []
        action_data = data[OFP_MATCH_SZ + OFP_FLOW_MOD_SZ:]
        offset = 0
        while offset + 4 <= len(action_data):
            act_type, act_len = struct.unpack('!HH', action_data[offset:offset + 4])
            if act_type == 0 and act_len >= 8:
                act_port, max_len = struct.unpack('!HH', action_data[offset + 4:offset + 8])
                actions.append(('output', act_port))
            offset += act_len

        if command == OFPFC_ADD:
            self.flow_table = [f for f in self.flow_table
                               if not (f.match == match and f.priority == priority)]
            self.flow_table.append(FlowEntry(match, actions, priority, cookie))
            self.log('Installed flow: %s -> %s prio=%d' % (dl_src.hex(), dl_dst.hex(), priority))
        elif command == OFPFC_DELETE:
            self.flow_table = [f for f in self.flow_table
                               if not (f.match == match and f.priority == priority)]
            self.log('Deleted flow: prio=%d' % priority)

    def handle_packet_out(self, data):
        """Handle PACKET_OUT from controller."""
        buffer_id, in_port, actions_len = struct.unpack('!IHH', data[:8])
        action_data = data[8:8 + actions_len]
        frame_data = data[8 + actions_len:]

        if buffer_id == 0xffffffff and frame_data:
            frame = frame_data
        elif buffer_id in self.buffers:
            frame = self.buffers[buffer_id][1]
        else:
            self.log('PACKET_OUT with unknown buffer_id %d' % buffer_id)
            return

        self.execute_actions(in_port, frame, action_data)

    def execute_actions(self, in_port, frame, action_data):
        """Execute actions on a frame."""
        offset = 0
        while offset + 4 <= len(action_data):
            act_type, act_len = struct.unpack('!HH', action_data[offset:offset + 4])
            if act_type == 0 and act_len >= 8:
                act_port, max_len = struct.unpack('!HH', action_data[offset + 4:offset + 8])
                self.output_frame(in_port, frame, act_port)
            offset += act_len

    def output_frame(self, in_port, frame, port):
        """Send a frame out a port."""
        if port in (OFPP_FLOOD, OFPP_ALL):
            for pn in self.socks:
                if pn != in_port:
                    try:
                        self.socks[pn].send(frame)
                    except Exception as e:
                        self.log('Error sending on port %d: %s' % (pn, e))
        elif port == OFPP_CONTROLLER:
            pass
        elif port == OFPP_NONE:
            pass
        elif port in self.socks:
            try:
                self.socks[port].send(frame)
            except Exception as e:
                self.log('Error sending on port %d: %s' % (port, e))

    def handle_packet_in(self, port_num, frame):
        """Handle a frame received on a port."""
        self.log('PacketIn on port %d (%d bytes)' % (port_num, len(frame)))
        for flow in sorted(self.flow_table, key=lambda f: -f.priority):
            if flow.matches(port_num, frame):
                if flow.actions:
                    action_data = b''
                    for act_type, act_port in flow.actions:
                        action_data += struct.pack(OFP_ACTION_OUTPUT_FMT, 0, 8, act_port, 0)
                    self.execute_actions(port_num, frame, action_data)
                return

        bid = self.next_buffer_id
        self.next_buffer_id += 1
        self.buffers[bid] = (port_num, frame)

        reason = 0  # OFPR_NO_MATCH
        body = struct.pack('!IHHBB', bid, len(frame), port_num, reason, 0)
        body += frame
        length = 8 + len(body)
        header = struct.pack('!BBHI', OFP_VERSION, OFPT_PACKET_IN, length, self.xid)
        self.ctrl.send(header + body)
        self.xid += 1

    def handle_stats_request(self, xid, data):
        """Reply to STATS_REQUEST with a STATS_REPLY.

        OFPT_STATS_REPLY for OFPST_DESC must echo the 1056-byte
        manufacturer/hardware/software/serial/datapath descriptor block
        ahead of the 4-byte stats header, or POX raises UnderrunError.
        """
        # The request body carries the stats type followed by the desc block.
        desc = data[4:] if len(data) >= 4 else b''
        if len(desc) < DESC_LEN:
            desc = desc.ljust(DESC_LEN, b'\x00')
        body = desc[:DESC_LEN] + struct.pack('!HH', 0, 0)
        length = 8 + len(body)
        header = struct.pack('!BBHI', OFP_VERSION, OFPT_STATS_REPLY, length, xid)
        self.ctrl.send(header + body)

    def handle_barrier_request(self, xid):
        """Reply to BARRIER_REQUEST with BARRIER_REPLY."""
        header = struct.pack('!BBHI', OFP_VERSION, OFPT_BARRIER_REPLY, 8, xid)
        self.ctrl.send(header)

    def handle_controller_data(self, data):
        """Process data received from the controller."""
        offset = 0
        while offset + 8 <= len(data):
            version, msg_type, length, xid = struct.unpack('!BBHI', data[offset:offset + 8])
            if length < 8 or offset + length > len(data):
                break
            body = data[offset + 8:offset + length]

            if msg_type == OFPT_ECHO_REQUEST:
                self.handle_echo_request(xid, body)
            elif msg_type == OFPT_FEATURES_REQUEST:
                self.handle_features_request(xid)
            elif msg_type == OFPT_FLOW_MOD:
                self.handle_flow_mod(body)
            elif msg_type == OFPT_PACKET_OUT:
                self.handle_packet_out(body)
            elif msg_type == OFPT_STATS_REQUEST:
                self.handle_stats_request(xid, body)
            elif msg_type == OFPT_BARRIER_REQUEST:
                self.handle_barrier_request(xid)
            elif msg_type == OFPT_HELLO:
                pass
            elif msg_type == OFPT_ERROR:
                self.log('ERROR from controller: %s' % body.hex())

            offset += length

    def run(self):
        """Main event loop."""
        self.connect()
        self.open_ports()
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

        while True:
            try:
                readable, _, _ = select.select(
                    [self.ctrl] + [s for pn, s in self.socks.items()
                                   if pn not in self.dead_ports],
                    [], [], 1.0)
            except (ValueError, OSError):
                break

            for sock in readable:
                if sock == self.ctrl:
                    try:
                        data = self.ctrl.recv(65535)
                    except BlockingIOError:
                        continue
                    if not data:
                        self.log('Controller disconnected')
                        return
                    self.handle_controller_data(data)
                else:
                    for pn, s in self.socks.items():
                        if s == sock:
                            try:
                                frame = s.recv(65535)
                            except BlockingIOError:
                                continue
                            except OSError as e:
                                # The port went away (teardown / link down).
                                # Drop the dead socket instead of killing the
                                # whole switch, otherwise the data plane dies
                                # with the control plane.
                                self.log('Port %d recv error: %s' % (pn, e))
                                self.dead_ports.add(pn)
                                continue
                            if frame:
                                self.handle_packet_in(pn, frame)
                            break


def main():
    parser = argparse.ArgumentParser(description='Minimal OpenFlow 1.0 switch')
    parser.add_argument('--controller', required=True, help='Controller address (host:port)')
    parser.add_argument('--dpid', type=int, default=1, help='Datapath ID')
    parser.add_argument('--port', action='append', default=[],
                        help='Port mapping (port_num:iface_name)')
    args = parser.parse_args()

    host, port = args.controller.rsplit(':', 1)
    ports = []
    for p in args.port:
        port_num, iface = p.split(':', 1)
        ports.append((int(port_num), iface))

    sw = OFSwitch(host, int(port), args.dpid, ports)
    sw.run()


if __name__ == '__main__':
    main()
