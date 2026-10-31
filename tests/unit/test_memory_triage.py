from hashlib import sha256
from ir_workspace.integrations.ghidra_analyzer import static_triage_bytes, lightweight_static_triage


def test_memory_triage_matches_file_triage_without_executing(tmp_path):
    data = b'MZ\x00\x01 http://evil.example/test VirtualAlloc user32.dll'
    path = tmp_path / 'fixture.bin'
    path.write_bytes(data)
    memory = static_triage_bytes(data, path.name)
    assert memory == lightweight_static_triage(str(path))
    assert memory['sha256'] == sha256(data).hexdigest()
    assert memory['domains'] == ['evil.example']
    assert memory['file_type'] == 'PE executable'
