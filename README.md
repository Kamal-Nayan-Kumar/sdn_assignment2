# SDN Assignment 2 — Layer-2 Firewall & Intent-Based Networking

A Layer-2 firewall for POX/OpenFlow driven by a policy file, plus an LLM
pipeline that writes that policy from natural-language intent.

**Start with [`report/report.pdf`](report/report.pdf)** — architecture,
implementation details, environment setup, known limitations, results, and
every screenshot. This file is the quick-start.

---

## What's here

| Path | What it is |
|---|---|
| **`report/report.pdf`** | **The report. Read this.** |
| `report/report.tex`, `report/figs/` | LaTeX source + the 6 screenshots |
| `report/capture.sh`, `report/build.sh` | regenerate figures / compile the PDF |
| **`app/firewall.py`** | The POX firewall application — main deliverable |
| `pox/ext/firewall.py` | a copy, already where POX expects it |
| `oswitch.py` | a pure-Python OpenFlow 1.0 switch |
| `topo2.py` | the four-host, one-switch Mininet topology |
| `intent_to_policy.py` | natural language → policy file (Part 2) |
| `firewall_rules.rules` | the generated policy: `h1→h3`, `h2→h4` DROP |
| `tests/` | 51 offline tests |
| `run_e2e.sh` | brings up the whole stack |
| `COMMAND.md` | every command, and what each is for |

---

## One-command start

```bash
bash run_all.sh
```

That runs the tests, prints the policy, and brings up the network. Or do the
steps yourself:

```bash
# 1. Offline tests — no network, no LLM, ~1 second
.venv/bin/python -m pytest tests/ -q          # 51 passed

# 2. End-to-end: POX + our switch + Mininet
unshare -Urn bash run_e2e.sh --batch          # 33% dropped (8/12)

# 3. Part 2: natural language → policy (needs `ollama serve`)
.venv/bin/python intent_to_policy.py \
    "Block h1 from sending traffic to h3." \
    "Block h2 from sending traffic to h4." \
    "Allow everything else." -f json
```

Full detail, including the interactive CLI and the manual step-by-step
sequence, is in **`COMMAND.md`**.

---

## Setup (what this machine needs)

No `sudo` on this box, so the network runs inside a user namespace. The
project also carries two vendored checkouts that are **not** committed —
`pox/` and `mininet/` are third-party, cloned separately.

```bash
# once
git clone https://github.com/noxrepo/pox.git pox
git clone https://github.com/mininet/mininet.git mininet
make -C mininet
bash install_firewall_app.sh       # put app/firewall.py in pox/ext/

# Part 2, if you want the LLM
~/.local/opt/ollama/bin/ollama serve &
ollama pull qwen2.5:0.5b
```

`install_firewall_app.sh` matters: `pox/` is an upstream clone whose own
`.gitignore` contains `ext/*`, so the firewall app cannot be tracked inside
it. The authoritative copy is `app/firewall.py`; that script installs it.
`run_e2e.sh` calls it automatically, and so does the test suite, so a fresh
clone works without running it by hand.

---

## Expected result

```
h1 -> h2 X h4
h2 -> h1 h3 X
h3 -> X h2 h4
h4 -> h1 X h3
*** Results: 33% dropped (8/12 received)
```

The two prohibited pairs (`h1→h3`, `h2→h4`) are dropped by the policy. The
two *reverse* directions also fail, for a different reason — `is_blocked(h3,
h1)` is `False`; no rule names that pair. Blocking `h1→h3` discards h1's ARP
replies, so h3 never resolves h1's MAC and the ping is never sent. The report
explains this in full, including why an alternative reading (10/12) was
measured and deliberately rejected.

---

## Design notes

**Part 1.** The policy is a plain text file of `src_mac dst_mac action`
lines, loaded at startup. On `ConnectionUp` the controller installs one
exact-match DROP flow per rule at priority 100, above the learning switch's
forwarding rules at 50 — so the two rule families cannot shadow each other.
The firewall is validated offline against a fake OpenFlow connection, and the
switch's wire format against POX's own message classes.

**Part 2.** `intent_to_policy.py` sends the whole request to `qwen2.5:0.5b`
(Ollama) in one call and asks for JSON. Correctness does not depend on the
model being smart: `validate_rules()` rejects malformed MACs, bad actions and
MACs outside the known host inventory, and `filter_phantom_rules()` discards
rules echoed back from the prompt's examples. The model may only *remove*
rules from consideration, never add one the text does not support. It fails
loudly — non-zero exit, no policy file — if the LLM is unreachable, returns
invalid JSON, or produces nothing usable.

qwen2.5:0.5b was chosen over the Phi-3 the assignment names: this is a
mechanical extraction task, and on this 4-core CPU-only box the 0.5B model
answered in ~42 s against Phi-3's 80–330 s, with identical output.
`report/bench_models.py` has the comparison.

---

## Tests

```bash
.venv/bin/python -m pytest tests/ -v
```

| File | Tests | Covers |
|---|---|---|
| `tests/test_firewall.py` | 11 | firewall logic against a fake OpenFlow connection |
| `tests/test_oswitch_wire.py` | 9 | the OpenFlow wire format, asserted against POX |
| `tests/test_intent_to_policy.py` | 31 | LLM output handling, via a stubbed HTTP layer |

---

## Rebuilding the artefacts

```bash
bash make_submission.sh     # sdn_assignment2_submission.zip
bash report/capture.sh      # regenerate all screenshots
bash report/build.sh        # compile report/report.pdf
```

`make_submission.sh` bundles the PDF, the LaTeX source and figures, the code,
the tests, and the assignment statement — third-party checkouts excluded.
