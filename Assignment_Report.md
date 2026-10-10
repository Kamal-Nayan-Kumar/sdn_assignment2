SDN Assignment 2: Layer-2 Firewall & Intent-based Networking
================================================================

Assignment Parts:
- Part 1: Layer-2 firewall using POX + OpenFlow + Mininet
- Part 2: Intent-based networking — LLM converts natural language to JSON rules

================================================================
PART 1: Layer-2 Firewall with POX + OpenFlow + Mininet
================================================================

Deliverables:
- pox/ext/firewall.py ................ POX firewall app (written)
- firewall_rules.rules .................. Policy: h1→h3 DROP, h2→h4 DROP (written)
- topo2.py ............................ Mininet topology (4 hosts, 1 switch, fixed MACs) (written)
- tests/test_firewall.py ................ 6 offline tests (6/6 pass)
- oswitch.py .......................... Minimal Python OpenFlow 1.0 switch (written, fixed)
- run_demo.py ......................... Mininet integration using PythonSwitch (written)

The Blockers and Fixes:

1. FEATURES_REPLY AssertionError in _readzs()
   - Root cause: oswitch.py sent structurally invalid FEATURES_REPLY message
   - Bug 1: n_buffers field was 4 bytes (I) instead of 1 byte (B) per OpenFlow 1.0 spec
   - Bug 2: Port description had 8 config fields (32 bytes) instead of 6 config fields (24 bytes)
   - Bug 3: FLOW_MOD cookie field was 4 bytes (I) instead of 8 bytes (Q)
   - Fix applied in oswitch.py handle_features_request() and handle_flow_mod()

2. ifconfig shim for Mininet
   - System has iproute2 but Mininet uses ifconfig
   - Created ifconfig shim at shim/ifconfig translating ifconfig → ip commands
   - Runs inside unshare -Urn (user namespace) since no sudo available

3. 100% ping drop in end-to-end Mininet
   - POX's of_01 crashed with AssertionError in _readzs() when parsing FEATURES_REPLY from oswitch
   - Fixated on stale oswitch process from previous run connecting with old code
   - Fixed the struct packing bugs (see above)
   - End-to-end: Mininet network builds, switch connects to POX, but pings fail due to
     namespace networking constraints (veth pair creation not permitted in user namespace without sudo)

Offline Test Results (6/6 pass):
- test_policy_file_loads ........................ PASSED
- test_json_policy_loads ........................ PASSED
- test_connectionup_installs_proactive_drop_rules ....... PASSED
- test_blocked_frames_are_dropped ................... PASSED
- test_allowed_traffic_is_learned_and_forwarded ......... PASSED
- test_allowed_traffic_between_blocked_pairs_neighbours ... PASSED

Policy File (firewall_rules.rules):
  00:00:00:00:00:01 00:00:00:00:00:03 DROP
  00:00:00:00:00:02 00:00:00:00:00:04 DROP

Firewall Rule Logic:
- DROP_PRIORITY = 100 (wins over learning-switch forwarding)
- FORWARD_PRIORITY = 50
- On ConnectionUp: proactively installs one DROP flow per firewall rule
- On PacketIn: enforces firewall rules (defence in depth), otherwise behaves as learning switch
- Exact-match flow entries + packet-outs for allowed traffic

================================================================
PART 2: Intent-based Networking
================================================================

Deliverable:
- intent_to_policy.py .................... Phi-3/Ollama integration with deterministic fallback parser (built)

Intent-to-Policy Parser (intent_to_policy.py):

The script converts natural language intent into POX-compatible firewall rules:

Supported deterministic patterns:
  "Block h1 from h3"           → h1→h3 DROP
  "Block h2 from h4"           → h2→h4 DROP
  "Allow h1 to h2"             → h1→h2 ALLOW
  "Deny h3 to h4"              → h3→h4 DROP
  "Block host 1 from host 3"   → h1→h3 DROP

LLM Integration (via Ollama + Phi-3):
  - Uses requests to POST to Ollama API (default: http://localhost:11434/api/generate)
  - System prompt guides Phi-3 to output valid JSON array
  - temperature: 0.0 for deterministic output
  - Fallback to deterministic parser if LLM unavailable or fails

Output Formats:
  - Plain text: firewall_rules.rules (format: src_mac dst_mac action per line)
  - JSON: [{"rule": 1, "src_mac": "...", "dst_mac": "...", "action": "DROP"}]

Usage Examples:
  python3 intent_to_policy.py "Block h1 from h3"
  python3 intent_to_policy.py "Block h1 from h3" "Block h2 from h4"
  python3 intent_to_policy.py --llm "Block h1 from h3"
  python3 intent_to_policy.py -f json "Block h1 from h3"

Current Policy File (after running intent_to_policy.py):
  00:00:00:00:00:01 00:00:00:00:00:03 DROP
  00:00:00:00:00:02 00:00:00:00:00:04 DROP

================================================================
CURRENT STATUS & NEXT STEPS
================================================================

STATUS:
- All 6 offline tests pass (firewall logic fully verified)
- oswitch.py FEATURES_REPLY struct packing bugs fixed
- intent_to_policy.py built with deterministic + LLM parsing
- Policy file correctly written and loadable by POX firewall
- END-TO-END MININET NOW WORKS (see fixes below)

END-TO-END RESULT (measured, not assumed):
  h1->h2=PASS  h1->h3=FAIL  h1->h4=PASS
  h2->h1=PASS  h2->h3=PASS  h2->h4=FAIL
  h3->h1=FAIL  h3->h2=PASS  h3->h4=PASS
  h4->h1=PASS  h4->h2=FAIL  h4->h3=PASS
  => 8/12 pass, 4 fail = 33% dropped

Note on the reverse direction (h3->h1, h4->h2):
  These fail as a *consequence* of the DROP rules, not independently.
  Blocking h1->h3 also drops h1's ARP replies to h3, so h3 can never
  resolve h1's MAC (`ip neigh` stays INCOMPLETE) and the ping cannot be
  sent. This is inherent to a strict L2 MAC-pair firewall: a one-way
  MAC-pair drop implies an unusable ARP path in the blocked direction.
  Letting ARP through would fix the reverse pings but weakens the policy.

BLOCKERS FIXED to get end-to-end working (all were real defects):
1. mnexec was never built. `make mnexec` reported "up to date" due to a
   stale timestamp while the binary did not exist; Mininet then hung
   spawning node shells. Fix: rm + make mnexec.
2. POX module path is `firewall`, not `pox.ext.firewall` — boot.py adds
   ext/ to sys.path itself, and upstream ext/ lives outside the package.
3. FEATURES_REPLY body packed 21 bytes (!QBB3sII) vs POX's 24 (!QLB).
   n_buffers is 4 bytes (L), not 1 byte (B). This is what produced the
   AssertionError in libopenflow_01._readzs().
4. STATS_REPLY for OFPST_DESC must echo a 1056-byte descriptor block
   before the 4-byte stats header, else UnderrunError.
5. FLOW_MOD match was 36 bytes; POX's ofp_match is 40 (two pad fields).
   Command section is !QHHHHLHH (24 bytes), not !IHHHHHIHH.
6. oswitch bound AF_PACKET sockets with protocol 0x0003 instead of
   socket.htons(0x0003). The unconverted value silently yields a socket
   that NEVER RECEIVES — this was the true cause of "100% dropped".
7. Mininet may leave veth ports down when the switch starts; oswitch now
   runs `ip link set <iface> up` before binding, else recv() gives ENETDOWN.
8. A dead port socket killed the whole switch; it now drops just that port.

Environment notes:
- No sudo available; everything runs under `unshare -Urn`.
- ICMP works fine inside the namespace (verified with a plain 2-host link),
  so the namespace was never the blocker.
- Run: `unshare -Urn bash run_e2e.sh`

NEXT STEPS:
1. Decide whether reverse-direction pings (h3->h1, h4->h2) must pass.
   If yes, the firewall needs an ARP exemption or L3-aware matching.
2. Capture Mininet CLI ping screenshots (the report still needs them).
3. Write up the assignment summary/challenges section.

================================================================
ASSIGNMENT CHECKLIST
================================================================

[✓] Part 1: Layer-2 firewall with POX + OpenFlow + Mininet
  [✓] 4 hosts on 1 switch with fixed MACs
  [✓] Policy file with src/dst MAC pairs (h1→h3 DROP, h2→h4 DROP)
  [✓] Proactive DROP flow installation on ConnectionUp
  [✓] Learning-switch for allowed traffic forwarding
  [✓] All 6 offline tests passing

[✓] Part 2: Intent-based networking
  [✓] Phi-3/Ollama integration with deterministic fallback parser
  [✓] Natural language → JSON rules conversion
  [✓] Policy file output in both text and JSON formats
  [✓] intent_to_policy.py built and tested

[✓] Environment setup
  [✓] Python 3.12.15 via mise with .venv (requests, pytest, packaging)
  [✓] POX 0.7.0 running (with version warning handled)
  [✓] Mininet cloned, mnexec built
  [✓] ifconfig shim created
  [✓] Running inside unshare -Urn (user namespace)

[ ] End-to-end Mininet validation
  [ ] Re-run with proper network namespace configuration
  [ ] Verify: h1↔h3 and h2↔h4 fail, all other pairs pass
  [ ] Screenshots of Mininet CLI ping results

[ ] Report
  [ ] Assignment summary and challenges
  [ ] Screenshots of test results and CLI output