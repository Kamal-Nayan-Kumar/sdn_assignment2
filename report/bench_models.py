"""Model selection benchmark — evidence for the report (Part 2).

Times each candidate LLM on the assignment's exact administrator request
and records whether it produced the correct two DROP rules.

Reproduce with:  bash report/bench_models.sh
Results are written to report/model_benchmark.md
"""

import json
import os
import re
import subprocess
import sys
import time

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from intent_to_policy import SYSTEM_PROMPT, validate_rules  # noqa: E402

OLLAMA_URL = 'http://localhost:11434/api/generate'

# The assignment's request, verbatim.
REQUEST = ("Block h1 from sending traffic to h3. "
           "Block h2 from sending traffic to h4. "
           "Allow everything else.")

EXPECTED = {('00:00:00:00:00:01', '00:00:00:00:00:03'),
            ('00:00:00:00:00:02', '00:00:00:00:00:04')}

# Probes beyond the assignment request: paraphrase, reordering and garbage.
PROBES = [
    REQUEST,
    "Prevent h4 from talking to h1",
    "Stop h3 from reaching h2",
    "asdf qwerty zzz",
]

MODELS = ['phi3', 'qwen2.5:0.5b', 'qwen2.5:1.5b', 'llama3.2:1b', 'gemma2:2b']


def installed():
    try:
        r = requests.get('http://localhost:11434/api/tags', timeout=10)
        return {m['name'] for m in r.json().get('models', [])}
    except Exception:
        return set()


def ask(model, intent, timeout=900):
    prompt = f"{SYSTEM_PROMPT}\n\nUser intent: {intent}\nJSON:"
    t0 = time.time()
    try:
        r = requests.post(OLLAMA_URL, json={
            'model': model, 'prompt': prompt, 'stream': False,
            'think': False,
            'options': {'temperature': 0.0, 'num_predict': 200},
        }, timeout=timeout)
    except Exception as e:
        return {'err': str(e), 'secs': time.time() - t0, 'rules': []}
    secs = time.time() - t0
    if r.status_code != 200:
        return {'err': 'HTTP %d' % r.status_code, 'secs': secs, 'rules': []}
    text = r.json().get('response', '').strip()
    m = re.search(r'\[.*\]', text, re.DOTALL)
    try:
        rules = validate_rules(json.loads(m.group(0))) if m else []
    except json.JSONDecodeError:
        rules = []
    return {'secs': secs, 'rules': rules, 'text': text}


def main():
    have = installed()
    if not have:
        sys.exit('Ollama is not reachable on :11434')

    rows = []
    for model in MODELS:
        if model not in have:
            print('skip %s (not installed)' % model)
            continue
        entry = {'model': model, 'probes': []}
        for probe in PROBES:
            res = ask(model, probe)
            entry['probes'].append(res)
            print('%-14s %5.1fs  %s' % (
                model, res['secs'],
                [(r['src_mac'][-2:], r['dst_mac'][-2:], r['action'])
                 for r in res['rules']] or 'no rules'))
        primary = entry['probes'][0]
        got = {(r['src_mac'], r['dst_mac']) for r in primary['rules']}
        entry['correct'] = got == EXPECTED
        entry['secs'] = primary['secs']
        rows.append(entry)
        print()

    out = os.path.join(ROOT, 'report', 'model_benchmark.json')
    with open(out, 'w') as f:
        json.dump(rows, f, indent=2)
    print('wrote', out)


if __name__ == '__main__':
    main()
