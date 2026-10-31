#!/usr/bin/env bash
# Werkt de lijsten bij die de scan gebruikt voor verouderde software, en zet ze
# in keuring/data/. Daarna opnieuw bouwen en uitrollen (de lijsten zitten in het
# programma; de scandienst haalt zelf niets op).
#  - wordpress.json: api.wordpress.org/core/stable-check (open data)
#  - retire.json:    RetireJS jsrepository.json (Apache-2.0), ingekort tot wat
#                    aan een bestandsnaam of adres te herkennen is
set -euo pipefail
cd "$(dirname "$0")/keuring/data"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
curl -sSf -m 60 https://api.wordpress.org/core/stable-check/1.0/ -o "$T/wp.json"
curl -sSfL -m 60 https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json -o "$T/retire.json"
python3 -I - "$T" <<'PY'
import json, sys, datetime
t = sys.argv[1]
wp = json.load(open(f"{t}/wp.json"))
assert any(v == "latest" for v in wp.values()), "geen 'latest' in de WordPress-lijst"
json.dump({"bijgewerkt": datetime.date.today().isoformat(), "versies": wp}, open("wordpress.json", "w"), separators=(",", ":"), sort_keys=True)
r = json.load(open(f"{t}/retire.json"))
uit = {}
for naam, lib in r.items():
    if naam == "retire-example":
        continue
    ex = lib.get("extractors", {})
    pat = ex.get("uri", []) + ex.get("filename", [])
    kw = []
    for v in lib.get("vulnerabilities", []):
        ids = v.get("identifiers", {})
        kw.append({k: v[k] for k in ("below", "atOrAbove", "severity") if k in v} |
                  {"cve": (ids.get("CVE") or [])[:3], "samenvatting": (ids.get("summary") or "")[:160]})
    if pat and kw:
        uit[naam] = {"patronen": pat, "lekken": kw}
json.dump({"bijgewerkt": datetime.date.today().isoformat(), "bibliotheken": uit}, open("retire.json", "w"), separators=(",", ":"), sort_keys=True)
print(f"WordPress: {len(wp)} versies; retire.js: {len(uit)} bibliotheken")
PY
