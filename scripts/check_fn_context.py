#!/usr/bin/env python3
"""Check where ARM template functions appear: policyRule.if vs policyRule.then."""
import json, re, glob

functions = {
    'greater':      r'greater\(',
    'less':         r'less\(',
    'json':         r'json\(',
    'or':           r'\bor\(',
    'guid':         r'\bguid\(',
    'uniqueString': r'uniqueString\(',
    'join':         r'join\(',
    'null':         r'null\(',
    'true':         r'true\(',
    'false':        r'false\(',
    'items':        r'items\(',
    'substring':    r'substring\(',
}

files = glob.glob('regolator/policyDefinitions/**/*.json', recursive=True)
for fn_name, pattern in functions.items():
    if_count = 0
    then_count = 0
    if_files = []
    for f in files:
        try:
            d = json.load(open(f))
            p = d.get('properties', d)
            r = p.get('policyRule', {})
            si = json.dumps(r.get('if', {}))
            st = json.dumps(r.get('then', {}))
            if re.search(pattern, si, re.IGNORECASE):
                if_count += 1
                if_files.append(f.split('/')[-1])
            if re.search(pattern, st, re.IGNORECASE):
                then_count += 1
        except:
            pass
    files_str = ', '.join(if_files[:3]) if if_files else ''
    print(f'{fn_name:20s} in_if={if_count:4d}  in_then={then_count:4d}  if_examples: {files_str}')
