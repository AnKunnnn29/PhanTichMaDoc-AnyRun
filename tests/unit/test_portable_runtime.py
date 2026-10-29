import hashlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

import ghidra_analyzer as ga
import runtime_setup as setup

pytestmark = pytest.mark.unit


def fake_install(root):
    archive = io.BytesIO()
    with ZipFile(archive, 'w') as package:
        package.writestr('jdk/bin/javac.exe', b'fixture, not executable')
        package.writestr('jdk/release', 'JAVA_VERSION="21.0.test"')
    data = archive.getvalue()
    checksum = hashlib.sha256(data).hexdigest()
    spec = {'name': 'test-jdk', 'target': 'tools/java/jdk-21', 'marker': 'bin/javac.exe',
            'identity_file': 'release', 'identity_text': 'JAVA_VERSION="21.',
            'sha256': checksum, 'url': 'https://github.com/example/test.zip'}
    cache = root / 'tools/.downloads'
    cache.mkdir(parents=True)
    (cache / f'test-jdk-{checksum[:12]}.zip').write_bytes(data)
    return spec


def test_clean_project_extracts_verified_cache_and_reuses_install(tmp_path, monkeypatch):
    spec = fake_install(tmp_path)
    monkeypatch.setattr(setup, 'download', lambda *_: pytest.fail('Cached archive must not download'))
    home = setup.ensure_component(spec, tmp_path)
    assert home == tmp_path / 'tools/java/jdk-21'
    assert setup.valid_install(home, spec)
    assert setup.ensure_component(spec, tmp_path) == home


def test_wrong_checksum_never_installs_download(tmp_path, monkeypatch):
    monkeypatch.setattr(setup, 'urlopen', lambda *_args, **_kwargs: io.BytesIO(b'wrong content'))
    with pytest.raises(ValueError, match='checksum'):
        setup.download({'name': 'test', 'url': 'https://github.com/example/test.zip', 'sha256': 'a' * 64}, tmp_path / 'runtime.zip')
    assert not (tmp_path / 'runtime.zip').exists()
    assert not (tmp_path / 'runtime.part').exists()


def test_archive_cannot_escape_extraction_folder(tmp_path):
    archive = tmp_path / 'unsafe.zip'
    with ZipFile(archive, 'w') as package:
        package.writestr('../outside.txt', 'must not extract')
    stage = tmp_path / 'stage'
    stage.mkdir()
    with pytest.raises(ValueError):
        setup.extract_checked(archive, stage)
    assert not (tmp_path / 'outside.txt').exists()


def test_incomplete_install_is_not_overwritten(tmp_path):
    spec = fake_install(tmp_path)
    target = tmp_path / spec['target']
    target.mkdir(parents=True)
    (target / 'user-file.txt').write_text('keep')
    with pytest.raises(RuntimeError, match='Incomplete'):
        setup.ensure_component(spec, tmp_path)
    assert (target / 'user-file.txt').read_text() == 'keep'


def test_project_ghidra_wins_over_machine_configuration(tmp_path, monkeypatch):
    monkeypatch.setattr(ga, 'PROJECT_ROOT', tmp_path)
    name = 'analyzeHeadless.bat' if os.name == 'nt' else 'analyzeHeadless'
    local = tmp_path / 'tools/ghidra/ghidra_12.1.4_PUBLIC/support' / name
    local.parent.mkdir(parents=True)
    local.write_text('fixture')
    external = tmp_path / 'external' / name
    external.parent.mkdir()
    external.write_text('fixture')
    monkeypatch.setenv('GHIDRA_HEADLESS', str(external))
    assert Path(ga.find_analyze_headless()) == local


def test_project_jdk_wins_and_requires_compiler(tmp_path, monkeypatch):
    monkeypatch.setattr(ga, 'PROJECT_ROOT', tmp_path)
    monkeypatch.setattr(ga.shutil, 'which', lambda _: None)
    monkeypatch.delenv('JAVA_HOME', raising=False)
    monkeypatch.setattr(ga, '_java_major', lambda *_: 21)
    home = tmp_path / 'tools/java/jdk-21'
    (home / 'bin').mkdir(parents=True)
    java = home / 'bin' / ('java.exe' if os.name == 'nt' else 'java')
    compiler = home / 'bin' / ('javac.exe' if os.name == 'nt' else 'javac')
    java.write_text('fixture')
    assert ga.find_java_home() == ''
    compiler.write_text('fixture')
    assert ga.find_java_home() == str(home)


def test_missing_ghidra_still_provides_basic_triage(tmp_path, monkeypatch):
    monkeypatch.setattr(ga, 'find_analyze_headless', lambda: '')
    sample = tmp_path / 'benign.bin'
    sample.write_bytes(b'MZ harmless test https://example.com/ CreateRemoteThread HKCU\\Software\\Test')
    result = ga.analyze_sample(str(sample))
    assert result['ghidra']['status'] == 'not_configured'
    assert result['triage']['sha256'] == hashlib.sha256(sample.read_bytes()).hexdigest()
    assert result['triage']['urls']


def test_headless_uses_project_java_without_shell_and_reads_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(ga, 'PROJECT_ROOT', tmp_path)
    monkeypatch.setattr(ga, 'runtime_path', lambda path: str(path))
    headless = tmp_path / 'tools/ghidra/support/analyzeHeadless.bat'
    java = tmp_path / 'tools/java/jdk-21'
    monkeypatch.setattr(ga, 'find_analyze_headless', lambda: str(headless))
    monkeypatch.setattr(ga, 'find_java_home', lambda: str(java))
    def run(command, **kwargs):
        assert command[0].startswith(str(java))
        assert 'ghidra.Ghidra' in command
        assert kwargs.get('shell', False) is False
        assert kwargs['env']['JAVA_HOME'] == str(java)
        output = Path(command[command.index('-postScript') + 2])
        output.write_text(json.dumps({'function_count': 1}), encoding='utf-8')
        return SimpleNamespace(returncode=0, stdout='done', stderr='')
    monkeypatch.setattr(ga.subprocess, 'run', run)
    result = ga.run_ghidra_headless(str(tmp_path / 'file & name.bin'))
    assert result['status'] == 'ok' and result['summary']['function_count'] == 1
