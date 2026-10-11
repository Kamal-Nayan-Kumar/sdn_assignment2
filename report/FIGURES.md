# Report figures

`report.tex` includes every figure by name from this directory. If a PNG is
absent, LaTeX draws a labelled placeholder instead — so the document always
compiles, and you can see exactly which screenshot is outstanding.

## Regenerating everything

```bash
bash report/capture.sh          # all figures
bash report/capture.sh tests    # just one
```

Each capture runs the command under `script(1)` to keep ANSI colour, then
`render_term.py` turns the transcript into a styled PNG.

| File | What it shows | Needs |
|------|---------------|-------|
| `tests.png` | `pytest -v` — the 48 offline tests | nothing |
| `intent.png` | LLM converting the assignment's English request → JSON rules | `ollama serve` + `qwen2.5:0.5b` |
| `pingall.png` | topology up, `pingall`, the policy pings | full stack |
| `dptable.png` | flow entries the switch actually installed | full stack |
| `poxlog.png` | `logs/pox.log` — policy load + rule install | full stack |
| `e2e.png` | the whole `run_e2e.sh --batch` transcript | full stack |

## Running the live parts by hand

If you would rather drive Mininet interactively and screenshot that, the
capture script's e2e block is equivalent to:

```bash
unshare -Urn bash run_e2e.sh
```

then inside the `mininet>` CLI:

```
pingall
h1 ping -c 2 h3
h2 ping -c 2 h4
h1 ping -c 2 h2
exit
```

> Note: this Mininet (2.3-era) has no `--batch`. `run_e2e.sh --batch` uses
> `mn --post report/mininet_cli.txt` with stdin at EOF, because `--post` runs
> the interactive CLI *first*. Do not pipe commands into `mn` by hand.

Take your screenshot however you like and save it as `figs/<name>.png` using
the names in the table above.

## Dropping in your own images

Any file named `<name>.png` in this directory is picked up automatically.
Nothing needs editing in `report.tex`.
