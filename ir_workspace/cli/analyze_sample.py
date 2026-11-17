"""Run Ghidra static analysis on a real sample INSIDE an isolated VM.

The malware stays in the VM; only the JSON this writes is copied to the host and
imported there (tab Ghidra → "Nhập kết quả từ máy ảo"). The JSON holds metadata and
inert disassembly text, never executable code.

In the VM (snapshot, no shared folders, network off):
    python start.py                 # one-time: prepares Ghidra and JDK in the project
    python -m ir_workspace.cli.analyze_sample "C:\\samples\\sample.exe" -o result.json

Then copy result.json out and import it on the host against the matching sandbox case.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ir_workspace.integrations.ghidra_analyzer import analyze_sample


def main() -> None:
    parser = argparse.ArgumentParser(description="Ghidra static analysis runner for an isolated VM")
    parser.add_argument("sample", help="Path to the sample to analyse (never leaves the VM)")
    parser.add_argument("-o", "--output", required=True, help="Where to write the JSON result")
    parser.add_argument("--timeout", type=int, default=240, help="Ghidra headless timeout in seconds")
    args = parser.parse_args()

    result = analyze_sample(args.sample, timeout=args.timeout)
    result["analysis_origin"] = "vm_headless"
    result["triage"]["filename"] = Path(args.sample).name
    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    ghidra = result.get("ghidra") or {}
    behaviors = [b["id"] for b in (result.get("code_evidence") or {}).get("behaviors", [])]
    print(json.dumps({
        "output": str(Path(args.output).resolve()),
        "sha256": result["triage"].get("sha256"),
        "ghidra_status": ghidra.get("status"),
        "behaviors": behaviors,
    }, ensure_ascii=False))
    if ghidra.get("status") != "ok":
        print("CẢNH BÁO: Ghidra chưa chạy đầy đủ (" + str(ghidra.get("status")) +
              "). Chạy 'python start.py' trong VM để chuẩn bị Ghidra/JDK.")


if __name__ == "__main__":
    main()
