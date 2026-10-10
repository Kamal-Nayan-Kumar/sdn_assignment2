#!/usr/bin/env python3
"""
intent_to_policy.py - Convert natural language intent into POX firewall rules.

Supports:
  1. LLM integration (Phi-3/Ollama) for natural language -> JSON parsing
  2. Deterministic fallback parser for when LLM is unavailable
  3. Output in both plain-text policy file format and JSON policy format

Usage:
    python3 intent_to_policy.py "Block h1 from h3"
    python3 intent_to_policy.py --llm "Block h1 from h3"
    python3 intent_to_policy.py "Block h1 from h3" "Block h2 from h4"

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


def parse_mac(text):
    """Extract and normalize a MAC address from text."""
    macs = re.findall(r'[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}', text)
    if macs:
        mac = macs[0].lower()
        if MAC_RE.match(mac):
            return mac
    return None


def deterministic_parse(intent):
    """
    Deterministic fallback parser for natural language intent.
    
    Supported patterns:
      "Block h1 from h3"           -> h1->h3 DROP
      "Block h2 from h4"           -> h2->h4 DROP
      "Allow h1 to h2"             -> h1->h2 ALLOW
      "Deny h3 to h4"              -> h3->h4 DROP
      "Block host 1 from host 3"   -> h1->h3 DROP
    
    Returns list of {src_mac, dst_mac, action} dicts or None.
    """
    intent_lower = intent.lower().strip()
    
    # Pattern: "Block/X hX from hY" or "Block/X hX to hY"
    block_match = re.search(r'(?:block|deny|drop)\s*(\w+)\s*(?:from|to)\s*(\w+)', intent_lower)
    allow_match = re.search(r'(?:allow|permit|forward)\s*(\w+)\s*(?:to|from)\s*(\w+)', intent_lower)
    
    rules = []
    
    # Helper to convert h1/h2/h3/h4 to MACs
    def mac_from_host(label):
        m = re.search(r'(\d+)', label)
        if m:
            num = m.group(1)
            if num == '1': return '00:00:00:00:00:01'
            if num == '2': return '00:00:00:00:00:02'
            if num == '3': return '00:00:00:00:00:03'
            if num == '4': return '00:00:00:00:00:04'
        return None
    
    # Try block/deny/drop pattern first
    if block_match:
        src_label = block_match.group(1)
        dst_label = block_match.group(2)
        src_mac = mac_from_host(src_label)
        dst_mac = mac_from_host(dst_label)
        if src_mac and dst_mac:
            rules.append({'src_mac': src_mac, 'dst_mac': dst_mac, 'action': 'DROP'})
    
    # Try allow/permit/forward pattern
    elif allow_match:
        src_label = allow_match.group(1)
        dst_label = allow_match.group(2)
        src_mac = mac_from_host(src_label)
        dst_mac = mac_from_host(dst_label)
        if src_mac and dst_mac:
            rules.append({'src_mac': src_mac, 'dst_mac': dst_mac, 'action': 'ALLOW'})
    
    return rules if rules else None


def llm_parse(intent, ollama_url='http://localhost:11434/api/generate'):
    """
    Parse natural language using Phi-3 via Ollama.
    
    Returns list of {src_mac, dst_mac, action} dicts or None.
    """
    try:
        import requests
        
        system_prompt = """You are an SDN policy parser. Convert natural language 
        firewall intent into JSON rules. The policy format is a JSON array of objects,
        each with src_mac, dst_mac, and action (DROP or ALLOW). 
        
        Rules:
        - Only output valid JSON, no explanatory text
        - src_mac and dst_mac must be in format 00:00:00:00:00:01 etc.
        - action must be "DROP" or "ALLOW"
        - If the intent is ambiguous, output an empty array []
        
        Examples:
        "Block h1 from h3" -> [{"src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:03", "action": "DROP"}]
        "Allow h2 to h4" -> [{"src_mac": "00:00:00:00:00:02", "dst_mac": "00:00:00:00:00:04", "action": "ALLOW"}]
        """
        
        prompt = f"{system_prompt}\n\nUser intent: {intent}\nJSON:"
        
        response = requests.post(ollama_url, json={
            'model': 'phi3',
            'prompt': prompt,
            'stream': False,
            'options': {'temperature': 0.0}
        }, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            text = result.get('response', '').strip()
            json_match = re.search(r'\[.*\]', text, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                try:
                    rules = json.loads(json_str)
                    valid = []
                    for r in rules:
                        if (isinstance(r, dict) and 
                            'src_mac' in r and 'dst_mac' in r and 
                            'action' in r and r['action'] in ('DROP', 'ALLOW') and
                            ':' in r['src_mac'] and ':' in r['dst_mac']):
                            valid.append({'src_mac': r['src_mac'].lower(),
                                          'dst_mac': r['dst_mac'].lower(),
                                          'action': r['action']})
                    if valid:
                        return valid
                except json.JSONDecodeError:
                    pass
        
        return None
    
    except ImportError:
        print("ERROR: 'requests' module not available", file=sys.stderr)
        return None
    except Exception as e:
        print(f"ERROR: LLM parsing failed: {e}", file=sys.stderr)
        return None


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


def main():
    parser = argparse.ArgumentParser(
        description='Convert natural language intent into POX firewall rules'
    )
    parser.add_argument(
        'intents',
        nargs='+',
        help='Natural language intent(s) e.g. "Block h1 from h3"'
    )
    parser.add_argument(
        '--llm', 
        action='store_true',
        help='Use Phi-3 LLM via Ollama for parsing'
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
    
    args = parser.parse_args()
    
    # Step 1: Try LLM parsing if requested
    all_rules = []
    if args.llm:
        for intent in args.intents:
            rules = llm_parse(intent, args.ollama_url)
            if rules:
                print(f"LLM parsed {len(rules)} rule(s) for: {intent}")
                for r in rules:
                    print(f"  {r['src_mac']} -> {r['dst_mac']}: {r['action']}")
                all_rules.extend(rules)
            else:
                print(f"LLM parsing failed for: {intent}, falling back to deterministic parser...")
    
    # Step 2: Deterministic fallback parser (for all intents if LLM was requested and failed,
    # or if LLM was not requested)
    if not args.llm or True:  # Always run deterministic as fallback
        for intent in args.intents:
            rules = deterministic_parse(intent)
            if rules:
                print(f"Deterministic parsed {len(rules)} rule(s) for: {intent}")
                for r in rules:
                    print(f"  {r['src_mac']} -> {r['dst_mac']}: {r['action']}")
                all_rules.extend(rules)
    
    # Remove duplicates (same src_mac + dst_mac, keep the last action)
    seen = set()
    unique_rules = []
    for r in all_rules:
        key = (r['src_mac'], r['dst_mac'])
        if key not in seen:
            seen.add(key)
            unique_rules.append(r)
    
    if not unique_rules:
        print("ERROR: Could not parse any intent into rules.")
        print("Supported formats:")
        print('  "Block h1 from h3"')
        print('  "Allow h2 to h4"')
        print('  "Deny h3 from h1"')
        sys.exit(1)
    
    # Display parsed rules
    print(f"\nParsed {len(unique_rules)} unique rule(s):")
    for i, r in enumerate(unique_rules, 1):
        print(f"  {i}. {r['src_mac']} -> {r['dst_mac']}: {r['action']}")
    
    # Write output file
    write_policy_file(unique_rules, args.output, args.format)
    
    # Summary
    blocked = sum(1 for r in unique_rules if r['action'] == 'DROP')
    allowed = sum(1 for r in unique_rules if r['action'] == 'ALLOW')
    print(f"\nSummary: {blocked} DROP rule(s), {allowed} ALLOW rule(s)")


if __name__ == '__main__':
    main()