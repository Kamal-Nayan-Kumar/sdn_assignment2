#!/usr/bin/env python3
"""
split_e2e.py - Build the e2e figures from a captured run.

Three figures come out of one `run_e2e.sh` invocation:

  pingall.png  the network bring-up, pingall, and the per-pair pings,
               sliced out of the transcript
  dptable.png  the flow entries the switch actually installed
  poxlog.png   the controller log

Note: the flow table is read from /tmp/oswitch.log, not from `dpctl` --
our switch is a Python program rather than Open vSwitch, so OVS's
userspace tools do not apply to it.

Usage:
    split_e2e.py <e2e.ansi> <figs_dir>
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RENDER = os.path.join(HERE, "render_term.py")

# Logs are written to <repo>/logs/ by run_e2e.sh (not /tmp: the whole run
# happens inside a user network namespace, and Mininet's cleanup removes
# files it finds in /tmp anyway).
LOGS_DIR = os.path.join(ROOT, "logs")
OSWITCH_LOG = os.path.join(LOGS_DIR, "oswitch.log")
POX_LOG = os.path.join(LOGS_DIR, "pox.log")


def render(text, out_png, title):
    """Render a text slice to a PNG via render_term.py."""
    tmp = out_png + ".slice.ansi"
    with open(tmp, "w", errors="replace") as f:
        f.write(text)
    try:
        subprocess.run([sys.executable, RENDER, tmp, out_png,
                        "--title", title], check=True)
    finally:
        os.unlink(tmp)


def read(path):
    if not (os.path.exists(path) and os.path.getsize(path) > 0):
        return None
    with open(path, errors="replace") as f:
        return f.read()


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: split_e2e.py <e2e.ansi> <figs_dir>")
    src, figs = sys.argv[1], sys.argv[2]

    with open(src, errors="replace") as f:
        text = f.read()
    os.makedirs(figs, exist_ok=True)
    problems = []

    # --- pingall.png: bring-up + pingall + the per-pair pings -------------
    start = re.search(r'\[e2e\] starting network', text)
    if start:
        stop = re.search(r'\*\*\* Stopping 1 controllers', text[start.end():])
        stop = start.end() + stop.start() if stop else len(text)
        render(text[start.start():stop].rstrip() + "\n",
               os.path.join(figs, "pingall.png"),
               "mininet: topology up, pingall, per-pair policy pings")
    else:
        problems.append("pingall.png (no '[e2e] starting network' marker)")

    # --- dptable.png: flow entries installed in the switch ----------------
    osw = read(OSWITCH_LOG)
    if osw:
        rows = [l for l in osw.splitlines() if "Installed flow" in l
                or "Deleted flow" in l]
        if rows:
            header = ("%s\n%s\n\nflow entries installed in s1:\n"
                      % (OSWITCH_LOG,
                         "-" * len(OSWITCH_LOG)))
            render(header + "\n".join(rows) + "\n",
                   os.path.join(figs, "dptable.png"),
                   "s1: installed flow entries")
        else:
            problems.append("dptable.png (no flow installs in %s)" % OSWITCH_LOG)
    else:
        problems.append("dptable.png (%s missing or empty)" % OSWITCH_LOG)

    # --- poxlog.png: the controller log -----------------------------------
    pox = read(POX_LOG)
    if pox:
        # Keep the interesting lines: policy load, connection, rule install.
        keep = [l for l in pox.splitlines()
                if re.search(r'firewall|openflow\.of_01|is up|Traceback|'
                             r'Error|Warning', l, re.I)]
        if keep:
            header = ("%s\n%s\n\n" % (POX_LOG, "-" * len(POX_LOG)))
            render(header + "\n".join(keep) + "\n",
                   os.path.join(figs, "poxlog.png"),
                   "POX controller: policy load + rule install")
        else:
            problems.append("poxlog.png (no firewall lines in %s)" % POX_LOG)
    else:
        problems.append("poxlog.png (%s missing or empty)" % POX_LOG)

    for p in problems:
        print("[split] MISSING %s" % p)
    if not problems:
        print("[split] all e2e figures written")


if __name__ == "__main__":
    main()
