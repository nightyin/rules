#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def uniq_sorted(xs):
    return sorted(set(x for x in xs if x and isinstance(x, str)))

def main():
    if len(sys.argv) != 3:
        print("Usage: openai_json_to_surge.py <input_json> <output_txt>", file=sys.stderr)
        sys.exit(2)

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    data = json.loads(in_path.read_text(encoding="utf-8"))
    rules = data.get("rules") or []

    domains, suffixes, regexes = [], [], []

    for r in rules:
        domains.extend(r.get("domain") or [])
        suffixes.extend(r.get("domain_suffix") or [])

        dr = r.get("domain_regex")
        if isinstance(dr, str):
            regexes.append(dr)
        elif isinstance(dr, list):
            regexes.extend([x for x in dr if isinstance(x, str)])

    domains = uniq_sorted(domains)
    suffixes = uniq_sorted(suffixes)
    regexes = uniq_sorted(regexes)

    lines = []
    lines.append("# Generated from MetaCubeX/meta-rules-dat (sing) geo/geosite/openai.json")
    lines.append("# Surge format: DOMAIN / DOMAIN-SUFFIX / DOMAIN-REGEX")
    lines.append("")

    if domains:
        lines.append("# --- domain ---")
        for d in domains:
            lines.append(f"DOMAIN,{d}")
        lines.append("")

    if suffixes:
        lines.append("# --- domain_suffix ---")
        for s in suffixes:
            lines.append(f"DOMAIN-SUFFIX,{s}")
        lines.append("")

    if regexes:
        lines.append("# --- domain_regex ---")
        for rg in regexes:
            lines.append(f"DOMAIN-REGEX,{rg}")
        lines.append("")

    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"wrote {out_path} (domain={len(domains)}, suffix={len(suffixes)}, regex={len(regexes)})")

if __name__ == "__main__":
    main()
