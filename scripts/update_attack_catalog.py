"""Build a small, pinned ATT&CK catalogue from official MITRE STIX data."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="19.2")
    parser.add_argument("--output", default=str(Path(__file__).resolve().parents[1] / "data" / "attack_catalog.json"))
    args = parser.parse_args()
    if not all(c.isdigit() or c == "." for c in args.version):
        parser.error("Version must be numeric")
    url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-{args.version}.json"
    response = requests.get(url, timeout=90)
    response.raise_for_status()
    raw = response.content
    techniques = {}
    for obj in json.loads(raw)["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T"):
                techniques[ref["external_id"]] = {"name": obj["name"], "url": ref.get("url", ""),
                    "tactics": [x["phase_name"] for x in obj.get("kill_chain_phases", [])],
                    "revoked": obj.get("revoked", False), "deprecated": obj.get("x_mitre_deprecated", False)}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"version": args.version, "source_url": url,
        "source_sha256": hashlib.sha256(raw).hexdigest(), "techniques": techniques}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {len(techniques)} ATT&CK techniques to {output}")


if __name__ == "__main__":
    main()
