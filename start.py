"""One-command Windows startup: python start.py (Internet on first setup)."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import venv

from runtime_setup import ensure_runtimes

ROOT = Path(__file__).resolve().parent


def prepare_python():
    executable = ROOT / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    if not executable.is_file():
        venv.EnvBuilder(with_pip=True).create(ROOT / '.venv')
    requirements = ROOT / 'requirements.txt'
    fingerprint = hashlib.sha256(requirements.read_bytes()).hexdigest()
    marker = ROOT / '.venv/.requirements-sha256'
    if not marker.exists() or marker.read_text() != fingerprint:
        subprocess.run([str(executable), '-X', 'utf8', '-m', 'pip', 'install', '--disable-pip-version-check', '-r', str(requirements)], cwd=ROOT, check=True)
        marker.write_text(fingerprint)
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--setup-only', action='store_true')
    parser.add_argument('--without-ghidra', action='store_true')
    args = parser.parse_args()
    if not args.without_ghidra:
        ensure_runtimes()
    executable = prepare_python()
    if args.setup_only:
        print('Project is ready. Run: python start.py')
        return 0
    return subprocess.call([str(executable), '-X', 'utf8', str(ROOT / 'app.py')], cwd=ROOT)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f'Setup failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
