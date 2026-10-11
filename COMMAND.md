# How to run and test this assignment

Everything here runs from the repository root:
`/home/nayan/Projects/sdn_assignment2`

Requirements already handled for you: Python 3.12 (`.venv/`), Ollama with
`qwen2.5:0.5b`, a built `mnexec`, and the `ifconfig` shim. The network
commands need a user namespace because this machine has no `sudo`.

---

## A note on `run_e2e.sh` — why a script and not one-liners

`run_e2e.sh` is deliberately a script rather than a wall of commands to
paste. Bringing the network up needs roughly a dozen steps, and most of them
exist because of a real bug that took time to find:

| Step | Why it is not obvious |
|---|---|
| put `app/firewall.py` into `pox/ext/` | `pox/` is a nested upstream checkout whose own `.gitignore` contains `ext/*`, so the app cannot be tracked in place |
| build `mnexec` | `make mnexec` reports "up to date" against a stale timestamp while the binary does not exist, so Mininet hangs with no error |
| kill stale `pox.py` / `oswitch.py` | a leftover switch from a previous run connects with old code and the run looks like a firewall bug |
| wait ~6s, then check for `is up` | the controller must be listening before Mininet tries to connect |
| `mn --post <file>` with stdin at EOF | this Mininet has no `--batch`; `--post` runs the *interactive* CLI first, so without stdin at EOF the run hangs |

A script is reproducible, reviewable, and one command to run in a demo. It
also has an interactive mode (below) for when you want to click around.

The trade-off is that a script can hide the individual steps. They are all
traceable — the file is ~40 lines of plain shell, and every command in
"Manual step-by-step" below is a literal fragment of it.

---

## 1. Offline tests — no network, no LLM (~1 second)

```bash
.venv/bin/python -m pytest tests/ -q
```

Expected: `51 passed`.

```bash
.venv/bin/python -m pytest tests/ -v --color=yes    # per-test detail
```

| File | Tests | What it covers |
|---|---|---|
| `tests/test_firewall.py` | 11 | Firewall logic against a fake OpenFlow connection |
| `tests/test_oswitch_wire.py` | 9 | OpenFlow wire format, asserted against POX's own classes |
| `tests/test_intent_to_policy.py` | 31 | LLM output handling (stubbed HTTP, so deterministic) |

---

## 2. End-to-end: POX + our switch + Mininet

### The one command

```bash
unshare -Urn bash run_e2e.sh --batch
```

`--batch` is scripted and non-interactive: it runs `pingall` plus explicit
per-pair pings, then exits. Without `--batch` it drops you into the Mininet
CLI so you can drive it by hand.

Expected:

```
*** Ping: testing ping reachability
h1 -> h2 X h4
h2 -> h1 h3 X
h3 -> X h2 h4
h4 -> h1 X h3
*** Results: 33% dropped (8/12 received)
```

`33%` is exactly the policy: the two prohibited pairs, plus the two reverse
directions that ARP makes unusable. Deterministic — six consecutive runs all
returned this.

### The check that actually matters

The two failure directions fail for *different reasons*, and telling them
apart is the interesting test:

```bash
# h1 -> h3 : the policy drop. No replies at all.
unshare -Urn bash run_e2e.sh --batch 2>&1 | grep -A3 "PING 10.0.0.3"
#   -> "2 packets transmitted, 0 received, 100% packet loss"

# h3 -> h1 : ARP, not the policy. h1's replies were dropped, so h3 never
# resolved h1's MAC and never sent anything.
unshare -Urn bash run_e2e.sh --batch 2>&1 | grep -A3 "PING 10.0.0.1"
#   -> "From 10.0.0.3 icmp_seq=1 Destination Host Unreachable"
```

`Destination Host Unreachable` is an ARP failure. A policy drop produces
plain packet loss with no error. This is documented in the report rather than
being left as an apparent inconsistency.

### Interactive

```bash
unshare -Urn bash run_e2e.sh
```

Then at the `mininet>` prompt:

```
pingall
h1 ping -c 2 h3          # blocked by policy
h2 ping -c 2 h4          # blocked by policy
h1 ping -c 2 h2          # allowed
h3 ping -c 2 h1          # allowed by policy, fails on ARP
exit
```

Note: use `h1 ping -c 2 h3`, not `ping h1 h3 -c 2 — this Mininet's CLI takes
node-first syntax.

### Watch the controller while it runs

```bash
tail -f logs/pox.log
```

You should see, in order:

```
INFO:firewall:Firewall loaded 'firewall_rules.rules': 2 rule(s) [...]
INFO:core:POX 0.7.0 (gar) is up.
INFO:openflow.of_01:[00-00-00-00-00-01 1] connected
INFO:firewall:Switch 1 connected - installing 2 firewall rule(s)
```

### Look at the switch's own flow table

```bash
grep "Installed flow" logs/oswitch.log
```

Expect the two proactive DROP entries at priority 100 (one per rule), then
priority-50 forwarding entries learned from live traffic.

---

## 3. Part 2: natural language → policy file

Needs Ollama running. If it is not:

```bash
~/.local/opt/ollama/bin/ollama serve &
ollama pull qwen2.5:0.5b          # ~400 MB; only this model is needed
```

Then run the assignment's exact request:

```bash
.venv/bin/python intent_to_policy.py \
    "Block h1 from sending traffic to h3." \
    "Block h2 from sending traffic to h4." \
    "Allow everything else." -f json
```

Expected:

```
LLM parsed 2 rule(s) for the combined request
  00:00:00:00:00:01 -> 00:00:00:00:00:03: DROP
  00:00:00:00:00:02 -> 00:00:00:00:00:04: DROP
Parsed 2 unique rule(s):
  1. 00:00:00:00:00:01 -> 00:00:00:00:00:03: DROP
  2. 00:00:00:00:00:02 -> 00:00:00:00:00:04: DROP
Summary: 2 DROP rule(s), 0 ALLOW rule(s)
```

`"Allow everything else."` is the interesting case: the learning switch
already implements it, so the correct answer is no rule at all — and the
script prints `NOTE: ... produced no rules (treated as no-op)` rather than
erroring.

```bash
cat firewall_rules.rules      # exactly the 2 DROP rules, as JSON
```

Round trip: feed that file straight back into Part 1 —

```bash
cp firewall_rules.rules /tmp/p.json
unshare -Urn bash run_e2e.sh --batch    # loads it at ControllerUp
```

---

## 4. Rebuild the report and figures

```bash
bash report/capture.sh          # regenerate all 6 screenshots (needs the LLM
                                #  + a working network for the last three)
bash report/build.sh            # tectonic or pdflatex -> report/report.pdf
```

```bash
bash make_submission.sh         # rebuild sdn_assignment2_submission.zip
```

---

## 5. Manual step-by-step (what `run_e2e.sh` does)

Use this to run the individual commands yourself, or to debug one stage in
isolation. All of it must be in **one** namespace, since the controller is
reached on loopback.

```bash
unshare -Urn bash -c '
  cd /home/nayan/Projects/sdn_assignment2

  # 1. put the firewall app where POX expects it
  bash install_firewall_app.sh

  # 2. Mininet needs mnexec on PATH, and an ifconfig that talks to iproute2
  export PYTHONPATH=$PWD/mininet
  export PATH=$PWD/mininet:$PWD/shim:$PATH
  ls mininet/mnexec || make -C mininet mnexec

  # 3. nothing from a previous run
  pkill -f pox.py; pkill -f oswitch.py; sleep 1

  # 4. controller
  python pox/pox.py firewall > logs/pox.log 2>&1 &
  sleep 6
  grep "is up" logs/pox.log

  # 5. network (scripted; add --batch style feed via --post)
  mn --custom topo2.py --topo fourhost \
     --controller remote,ip=127.0.0.1,port=6633 \
     --post report/mininet_cli.txt < /dev/null
'
```

### Do not skip the cleanup step

When building the network by hand, the `pkill` line is **not** optional. A
stale `oswitch.py` left behind by an interrupted run still holds the
`AF_PACKET` sockets on `s1-eth1..4`. Mininet deletes and recreates those
interfaces, but the old switch process survives and keeps its controller
connection with dpid 1, so the new switch shares the datapath with a ghost.

The symptom is a *silently wrong* result, not an error. Observed directly:
one run of the manual sequence without the `pkill` returned **41% dropped
(7/12)** because `h4 -> h3` failed, where every clean run returns **33%
(8/12)**. No warning is printed anywhere. `run_e2e.sh` kills both processes
before starting, which is why it is reliable.

The three non-obvious details, spelled out because each cost real debugging
time:

- **`install_firewall_app.sh`** — `app/firewall.py` is the tracked copy;
  `pox/ext/firewall.py` is generated. Skipping this means the controller
  loads whatever stale version happens to be there, or nothing.
- **`< /dev/null` on `mn`** — `--post` runs the interactive CLI *first*, so
  without stdin at EOF the run sits at `mininet>` forever.
- **`logs/`, not `/tmp`** — Mininet's cleanup does `rm -f /tmp/*.log`, so a
  controller log written there is destroyed on shutdown.

The switch itself is `topo2.py`'s `PythonSwitch.start()`, which launches
`oswitch.py` behind the scenes:

```bash
grep "nohup python3" topo2.py
```

---

## 6. Checking the wire format (the part tests do not show you)

```bash
# every struct size POX expects, vs what oswitch.py packs
.venv/bin/python -m pytest tests/test_oswitch_wire.py -v
```

To see it directly:

```bash
.venv/bin/python - <<'PY'
import sys, os
sys.path[:0] = [os.getcwd(), os.path.join(os.getcwd(), 'pox')]
import oswitch, pox.openflow.libopenflow_01 as lib
print('ofp_match       ', len(lib.ofp_match()),      oswitch.OFP_MATCH_SZ)
print('ofp_flow_mod    ', len(lib.ofp_flow_mod())-8, oswitch.OFP_MATCH_SZ+oswitch.OFP_FLOW_MOD_SZ)
print('ofp_phy_port    ', len(lib.ofp_phy_port()),   oswitch.OFP_PHY_PORT_SZ)
print('ofp_desc_stats  ', len(lib.ofp_desc_stats()), oswitch.DESC_LEN)
PY
```

---

## Quick reference

| What | Command |
|---|---|
| Everything, in order | `bash run_all.sh` (inside the repo) |
| Tests | `.venv/bin/python -m pytest tests/ -q` |
| End-to-end | `unshare -Urn bash run_e2e.sh --batch` |
| Interactive | `unshare -Urn bash run_e2e.sh` |
| Intent → policy | `.venv/bin/python intent_to_policy.py "Block h1 from h3"` |
| Controller log | `tail -f logs/pox.log` |
| Switch flow table | `grep "Installed flow" logs/oswitch.log` |
| Rebuild figures | `bash report/capture.sh` |
| Rebuild PDF | `bash report/build.sh` |
| Rebuild submission zip | `bash make_submission.sh` |
