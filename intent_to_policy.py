#!/usr/bin/env python3
"""
intent_to_policy.py - Convert natural language intent into POX firewall rules.

Parsing is done exclusively by an LLM (served by Ollama).
If the LLM is unreachable or returns unusable output, the script fails
with a non-zero exit code and writes no policy file.

Default model is qwen2.5:0.5b.  This is a mechanical extraction task
(host name -> MAC -> action); on a CPU-only box the 3.8B phi3 needed
~45 s per request while the 0.5B model takes ~5 s with the same accuracy
on the assignment's intents.  Reasoning is switched off (`think: false`)
because no chain of thought helps here.

Correctness does not rest on the model being clever: validate_rules()
rejects malformed actions and invented MAC addresses, and
filter_phantom_rules() discards rules echoed back from the prompt's
examples -- both of which small models do get wrong.

Usage:
    python3 intent_to_policy.py "Block h1 from h3"
    python3 intent_to_policy.py "Block h1 from h3" "Block h2 from h4"
    python3 intent_to_policy.py --model phi3 "Allow h2 to h4"

Policy format supported (both accepted by pox/ext/firewall.py):
  Plain text:   00:00:00:00:00:01 00:00:00:00:00:03 DROP
  JSON:         [{"rule": 1, "src_mac": "00:00:00:00:00:01",
                "dst_mac": "00:00:00:00:00:03", "action": "DROP"}]
"""

import sys
import json
import re
import argparse

# MAC address pattern
MAC_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')

# Host inventory from the assignment.  Used two ways: injected into the
# prompt, and used by validate_rules() to reject MACs the model invented.
HOST_MACS = {
  "h1": "00:00:00:00:00:01",
  "h2": "00:00:00:00:00:02",
  "h3": "00:00:00:00:00:03",
  "h4": "00:00:00:00:00:04",
}
KNOWN_MACS = {m.lower() for m in HOST_MACS.values()}

# Generation cap.  A correct answer is a short JSON array (<60 tokens);
# anything much longer is the model rambling, and cutting it off is faster
# and safer than letting it invent extra rules.
NUM_PREDICT = 200

SYSTEM_PROMPT = """You are an SDN policy parser. Convert natural language
firewall intent into JSON rules. The policy format is a JSON array of objects,
each with src_mac, dst_mac, and action (DROP or ALLOW).

The ONLY hosts that exist:
h1 = 00:00:00:00:00:01
h2 = 00:00:00:00:00:02
h3 = 00:00:00:00:00:03
h4 = 00:00:00:00:00:04

Rules:
- Only output valid JSON, no explanatory text
- src_mac and dst_mac must be one of the four MAC addresses listed above;
  never invent any other address
- action must be "DROP" or "ALLOW"
- "Block A from B" means src_mac = A, dst_mac = B, in the order written
- Output exactly one rule per host pair mentioned; do not add extra rules
- If the request names no source and destination host, output an empty array []

Examples:
"Block h1 from h3" -> [{"src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:03", "action": "DROP"}]
"Allow h2 to h4" -> [{"src_mac": "00:00:00:00:00:02", "dst_mac": "00:00:00:00:00:04", "action": "ALLOW"}]
"""


class NoRules(Exception):
    """The LLM answered validly but with an *empty* rule list.

    Raised instead of RuntimeError so the caller can tell "the LLM gave me
    nothing usable" apart from "the LLM answered 'no rules needed'".
    """

    def __init__(self, intent):
        super().__init__(intent)
        self.intent = intent


def validate_rules(rules):
    """
    Validate LLM-produced rules, returning the list of well-formed ones.

    Rejects, in order:
      * anything that is not a list / not a dict
      * missing or non-string MAC fields
      * an action that is not exactly DROP or ALLOW
      * a malformed MAC
      * a well-formed MAC that is NOT one of the four known hosts -- small
        models happily invent 00:00:00:00:00:07, and a firewall must never
        silently drop traffic for a host that does not exist.

    Returns list of {src_mac, dst_mac, action} dicts (possibly empty).
    """
    valid = []
    if not isinstance(rules, list):
        return valid

    for r in rules:
        if not isinstance(r, dict):
            continue
        src = r.get('src_mac')
        dst = r.get('dst_mac')
        action = r.get('action')
        if not isinstance(src, str) or not isinstance(dst, str):
            continue
        if action not in ('DROP', 'ALLOW'):
            continue
        src = src.lower()
        dst = dst.lower()
        if not MAC_RE.match(src) or not MAC_RE.match(dst):
            continue
        # reject invented hosts
        if src not in KNOWN_MACS or dst not in KNOWN_MACS:
            continue
        valid.append({'src_mac': src, 'dst_mac': dst, 'action': action})

    return valid


def hosts_in_intent(intent):
    """Return the set of MACs whose host name is mentioned in the text."""
    low = intent.lower()
    return {mac for host, mac in HOST_MACS.items()
            if re.search(r'\b%s\b' % host, low)}


def filter_phantom_rules(rules, intent):
    """Drop rules whose endpoints are not actually named in the intent.

    This guards against a small model echoing an example rule back: if the
    administrator only mentioned h1 and h3, a returned h4 -> h1 rule is a
    copy-paste artefact, not an instruction, and installing it would drop
    real traffic.  Returns (kept_rules, rejected_rules).
    """
    mentioned = hosts_in_intent(intent)
    if not mentioned:
        return rules, []
    kept, rejected = [], []
    for r in rules:
        if r['src_mac'] in mentioned and r['dst_mac'] in mentioned:
            kept.append(r)
        else:
            rejected.append(r)
    return kept, rejected


def llm_parse(intent, ollama_url='http://localhost:11434/api/generate', model='qwen2.5:0.5b', timeout=300):
    """
    Parse natural language using an LLM served by Ollama.

    Returns list of {src_mac, dst_mac, action} dicts (possibly empty).
    Raises RuntimeError if the LLM cannot be reached or gives no usable output.
    """
    try:
        import requests
    except ImportError as e:
        raise RuntimeError("'requests' module not available") from e

    prompt = f"{SYSTEM_PROMPT}\n\nUser intent: {intent}\nJSON:"

    try:
        response = requests.post(ollama_url, json={
            'model': model,
            'prompt': prompt,
            'stream': False,
            # Disable reasoning/thinking: this task is a mechanical
            # extraction, and any chain-of-thought tokens are pure latency
            # (and a chance to talk itself out of a correct answer).
            'think': False,
            'options': {'temperature': 0.0, 'num_predict': NUM_PREDICT}
        }, timeout=timeout)
    except Exception as e:
        raise RuntimeError(f"could not reach Ollama at {ollama_url}: {e}") from e

    if response.status_code != 200:
        raise RuntimeError(
            f"Ollama returned HTTP {response.status_code}: {response.text.strip()[:200]}"
        )

    try:
        result = response.json()
    except ValueError as e:
        raise RuntimeError(f"Ollama returned a non-JSON response: {e}") from e

    text = result.get('response', '').strip()
    json_match = re.search(r'\[.*\]', text, re.DOTALL)
    if not json_match:
        raise RuntimeError(f"no JSON array found in LLM output: {text[:200]!r}")

    try:
        parsed = json.loads(json_match.group(0))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"LLM output was not valid JSON: {e}") from e

    rules = validate_rules(parsed)

    # A small model sometimes echoes a rule from the prompt's examples
    # alongside the real answer.  Such a rule would silently drop live
    # traffic, so drop it here rather than trusting the model.
    rules, phantom = filter_phantom_rules(rules, intent)
    for p in phantom:
        print("WARNING: discarded rule %s -> %s (%s): neither host is "
              "named in the request"
              % (p['src_mac'], p['dst_mac'], p['action']), file=sys.stderr)

    if not rules:
        # Not every intent is meant to produce a rule.  "Allow everything
        # else" is a catch-all that the learning switch already implements,
        # so the LLM -- correctly -- answers with [].  That is a valid
        # answer, not a failure; the caller decides whether it is a problem.
        raise NoRules(intent)

    return rules


def write_policy_file(rules, output_path, format_type='text'):
    """
    Write rules to a policy file.

    format_type: 'text' or 'json'
    """
    if format_type == 'json':
        json_rules = []
        for i, rule in enumerate(rules, 1):
            json_rules.append({
                'rule': i,
                'src_mac': rule['src_mac'],
                'dst_mac': rule['dst_mac'],
                'action': rule['action']
            })
        with open(output_path, 'w') as f:
            json.dump(json_rules, f, indent=2)
    else:
        with open(output_path, 'w') as f:
            for rule in rules:
                f.write(f"{rule['src_mac']} {rule['dst_mac']} {rule['action']}\n")
    print(f"Policy written to {output_path}")


def merge_rules(rule_lists):
    """Merge per-intent rule lists into one deterministic policy.

    Precedence rules:
      * DROP beats ALLOW for the same (src_mac, dst_mac) pair (fail-closed):
        if two intents disagree we keep the DROP and report the conflict
        rather than silently dropping one of them.
      * Identical duplicates collapse to a single entry.
      * First-seen order is preserved so the output file is reproducible.
    """
    by_pair = {}   # (src, dst) -> rule
    order = []     # insertion order
    conflicts = []

    for rules in rule_lists:
        for r in rules:
            key = (r['src_mac'], r['dst_mac'])
            if key not in by_pair:
                by_pair[key] = r
                order.append(key)
                continue
            existing = by_pair[key]['action']
            if existing == r['action']:
                continue  # duplicate, nothing to do
            conflicts.append({
                'src_mac': key[0], 'dst_mac': key[1],
                'kept': 'DROP', 'discarded': existing,
            })
            if existing == 'ALLOW':        # replace the weaker rule
                by_pair[key] = r

    return [by_pair[k] for k in order], conflicts


def main():
    parser = argparse.ArgumentParser(
        description='Convert natural language intent into POX firewall rules (LLM-only)'
    )
    parser.add_argument(
        'intents',
        nargs='+',
        help='Natural language intent(s) e.g. "Block h1 from h3"'
    )
    parser.add_argument(
        '--model',
        default='qwen2.5:0.5b',
        help='Ollama model name (default: qwen2.5:0.5b)'
    )
    parser.add_argument(
        '--output', '-o',
        default='firewall_rules.rules',
        help='Output policy file path (default: firewall_rules.rules)'
    )
    parser.add_argument(
        '--format', '-f',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text, also supports json)'
    )
    parser.add_argument(
        '--ollama-url',
        default='http://localhost:11434/api/generate',
        help='Ollama API endpoint (default: http://localhost:11434/api/generate)'
    )
    parser.add_argument(
        '--timeout', type=int, default=300,
        help='Per-request LLM timeout in seconds (default: 300)'
    )

    parser.add_argument(
        '--per-sentence', dest='combined', action='store_false',
        help='Ask the LLM about each intent separately instead of sending '
             'them all as one request.  Slower and less accurate (a small '
             'model tends to leak a rule from one sentence into another), '
             'but useful for showing the difference in the report.'
    )
    parser.set_defaults(combined=True)

    args = parser.parse_args()

    all_rules = []
    empty_intents = []

    # The assignment's administrator request is one paragraph of several
    # sentences, so by default we ask about it in ONE shot: faster, and
    # less prone to a small model leaking a rule from one sentence into
    # another.  --per-sentence restores the old one-call-per-intent path.
    if args.combined:
        combined = ' '.join(args.intents)
        try:
            rules = llm_parse(combined, args.ollama_url, args.model,
                              args.timeout)
            print(f"LLM parsed {len(rules)} rule(s) for the combined request")
            for r in rules:
                print(f"  {r['src_mac']} -> {r['dst_mac']}: {r['action']}")
            all_rules.append(rules)
        except NoRules:
            print("NOTE: the combined request produced no rules.")
        except RuntimeError as e:
            print(f"ERROR: LLM parsing failed: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        for intent in args.intents:
            try:
                rules = llm_parse(intent, args.ollama_url, args.model,
                                  args.timeout)
            except NoRules as e:
                # Valid but empty answer: the intent is a catch-all such as
                # "Allow everything else", which the learning switch
                # already implements.  Keep going; fail only if *nothing*
                # was produced.
                print(f"NOTE: {e.intent!r} produced no rules "
                      f"(treated as no-op).")
                empty_intents.append(intent)
                continue
            except RuntimeError as e:
                print(f"ERROR: LLM parsing failed for {intent!r}: {e}",
                      file=sys.stderr)
                sys.exit(1)

            print(f"LLM parsed {len(rules)} rule(s) for: {intent}")
            for r in rules:
                print(f"  {r['src_mac']} -> {r['dst_mac']}: {r['action']}")
            all_rules.append(rules)

    if not any(all_rules):
        # every intent was a no-op -> nothing to write
        print("ERROR: no DROP or ALLOW rules were produced for any "
              "intent; refusing to write an empty policy.", file=sys.stderr)
        sys.exit(1)

    # Merge with explicit precedence (see merge_rules docstring).
    unique_rules, conflicts = merge_rules(all_rules)

    if not unique_rules:
        print("ERROR: no rules after merging; refusing to write an "
              "empty policy.", file=sys.stderr)
        sys.exit(1)

    for c in conflicts:
        # fail-closed warning, not a silent failure
        print("WARNING: conflicting actions for %s -> %s: keeping %s, "
              "ignoring %s" % (c['src_mac'], c['dst_mac'],
                               c['kept'], c['discarded']),
              file=sys.stderr)

    print(f"\nParsed {len(unique_rules)} unique rule(s):")
    for i, r in enumerate(unique_rules, 1):
        print(f"  {i}. {r['src_mac']} -> {r['dst_mac']}: {r['action']}")

    write_policy_file(unique_rules, args.output, args.format)

    blocked = sum(1 for r in unique_rules if r['action'] == 'DROP')
    allowed = sum(1 for r in unique_rules if r['action'] == 'ALLOW')
    print(f"\nSummary: {blocked} DROP rule(s), {allowed} ALLOW rule(s)")


if __name__ == '__main__':
    main()
