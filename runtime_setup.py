"""Install pinned, checksum-verified Windows runtimes inside this project only."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import tempfile
from pathlib import Path
from urllib.request import urlopen
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parent


def inside(root, path):
    root, path = Path(root).resolve(), Path(path).resolve()
    if not path.is_relative_to(root) or path == root:
        raise ValueError("Runtime path must stay inside the project")
    return path


def file_hash(path):
    checksum = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            checksum.update(chunk)
    return checksum.hexdigest()


def valid_install(path, spec):
    identity = Path(path) / spec['identity_file']
    return ((Path(path) / spec['marker']).is_file() and identity.is_file()
            and spec['identity_text'] in identity.read_text(encoding='utf-8', errors='replace'))


def download(spec, destination):
    if not spec['url'].startswith('https://github.com/') or not re.fullmatch('[a-f0-9]{64}', spec['sha256']):
        raise ValueError('Invalid runtime source/checksum')
    partial = destination.with_suffix('.part')
    print(f"Downloading {spec['name']} ...", flush=True)
    with urlopen(spec['url'], timeout=60) as response, partial.open('wb') as output:
        count = 0
        while chunk := response.read(1024 * 1024):
            count += len(chunk)
            if count > 2 * 1024**3:
                raise ValueError('Runtime download exceeds 2 GiB')
            output.write(chunk)
    if file_hash(partial) != spec['sha256']:
        partial.unlink()
        raise ValueError('Runtime checksum mismatch; archive not installed')
    partial.replace(destination)


def extract_checked(archive, stage):
    with ZipFile(archive) as package:
        members = package.infolist()
        if len(members) > 50000 or sum(m.file_size for m in members) > 3 * 1024**3:
            raise ValueError('Runtime archive exceeds extraction limits')
        for member in members:
            name = member.filename.replace('\\', '/')
            if ':' in name or stat.S_ISLNK(member.external_attr >> 16):
                raise ValueError('Unsupported archive entry')
            inside(stage, Path(stage) / name)
        package.extractall(stage)


def ensure_component(spec, root=ROOT):
    root = Path(root).resolve()
    target = inside(root, root / spec['target'])
    if valid_install(target, spec):
        print(f"Ready: {spec['name']} (project folder)", flush=True)
        return target
    if target.exists():
        raise RuntimeError(f'Incomplete runtime at {target}; rename it before trying again')
    cache = inside(root, root / 'tools/.downloads')
    cache.mkdir(parents=True, exist_ok=True)
    archive = inside(root, cache / (spec['name'] + '-' + spec['sha256'][:12] + '.zip'))
    if not archive.exists() or file_hash(archive) != spec['sha256']:
        download(spec, archive)
    # TemporaryDirectory cleanup is confined to this checked project-owned path.
    with tempfile.TemporaryDirectory(prefix='extract-', dir=cache) as temporary:
        stage = inside(root, temporary)
        extract_checked(archive, stage)
        candidates = [p for p in [stage, *stage.iterdir()] if p.is_dir() and valid_install(p, spec)]
        if len(candidates) != 1:
            raise RuntimeError('Archive does not contain the expected runtime')
        source = inside(root, candidates[0])
        target = inside(root, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(target))
    print(f"Installed: {spec['name']}", flush=True)
    return target


def ensure_runtimes(root=ROOT, java_only=False):
    if os.name != 'nt' or platform.machine().lower() not in {'amd64', 'x86_64'}:
        raise RuntimeError('Bundled runtime setup supports Windows x64; configure Ghidra/JDK manually on other platforms')
    manifest = json.loads((Path(root) / 'tools/runtime-manifest.json').read_text(encoding='utf-8'))
    installed = {}
    for name in (['java'] if java_only else ['java', 'ghidra']):
        installed[name] = ensure_component(manifest[name], root)
    return installed


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-only', action='store_true')
    args = parser.parse_args()
    ensure_runtimes(java_only=args.java_only)
