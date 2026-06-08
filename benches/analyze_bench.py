#!/usr/bin/env python3
"""Analyze rvm_benchmark criterion output."""
import re, sys

path = sys.argv[1] if len(sys.argv) > 1 else "benches/rvm_benchmark_optimized_value.txt"
text = open(path).read()

# Match: benchmark_name\n  time: [...median... unit]\n  change: [lo mid hi]
pattern = (
    r"^(\S+/\S+)\s*\n"
    r"\s*time:\s*\[.*?(\d+\.?\d*)\s*(ns|.s|ms|s).*?\]\s*\n"
    r"\s*change:\s*\[([\+\-\u2212][\d\.]+%)\s+([\+\-\u2212][\d\.]+%)\s+([\+\-\u2212][\d\.]+%)\]"
)
results = re.findall(pattern, text, re.MULTILINE)

def parse_pct(s):
    return float(s.replace("\u2212", "-").replace("+", "").rstrip("%"))

improved, regressed, noise = [], [], []
cats = {}
for name, tval, unit, lo, mid, hi in results:
    pct = parse_pct(mid)
    cat = name.split("/")[0]
    cats.setdefault(cat, []).append(pct)
    entry = (name, pct, tval, unit)
    if pct < -0.5:
        improved.append(entry)
    elif pct > 0.5:
        regressed.append(entry)
    else:
        noise.append(entry)

improved.sort(key=lambda x: x[1])
regressed.sort(key=lambda x: x[1], reverse=True)

print("=== OVERALL SUMMARY ===")
print(f"Total benchmarks: {len(results)}")
print(f"Improved (faster):  {len(improved)}")
print(f"Regressed (slower): {len(regressed)}")
print(f"Noise (<0.5%):      {len(noise)}")
print()

print("=== BY CATEGORY (median change) ===")
for cat in ["cold", "hot", "compilation", "serialization", "startup", "end_to_end"]:
    vals = sorted(cats.get(cat, []))
    if vals:
        med = vals[len(vals) // 2]
        avg = sum(vals) / len(vals)
        print(f"  {cat:20s}: median {med:+5.1f}%  avg {avg:+5.1f}%  (n={len(vals)}, range [{vals[0]:+.1f}%, {vals[-1]:+.1f}%])")

print()
print("=== TOP 10 IMPROVEMENTS ===")
for name, pct, t, u in improved[:10]:
    print(f"  {pct:+7.2f}%  {t:>8s} {u}  {name}")

print()
print("=== TOP 15 REGRESSIONS ===")
for name, pct, t, u in regressed[:15]:
    print(f"  {pct:+7.2f}%  {t:>8s} {u}  {name}")

# Check for outlier: azure_nsg_input2
print()
print("=== AZURE_NSG DETAIL (outlier check) ===")
for name, pct, t, u in sorted(improved + regressed + noise, key=lambda x: x[0]):
    if "azure_nsg" in name:
        print(f"  {pct:+7.2f}%  {t:>8s} {u}  {name}")
