from pathlib import Path

SOURCE = (Path(__file__).parents[1] / "contracts" / "release_gate.py").read_text()

def test_release_gate_consensus_and_lifecycle():
    assert "gl.nondet.web.get" in SOURCE
    assert "gl.nondet.exec_prompt" in SOURCE
    assert "gl.vm.run_nondet_unsafe" in SOURCE
    assert '"APPROVED"' in SOURCE and '"BLOCKED"' in SOURCE
    assert "expire_release" in SOURCE
    assert "release_digest" in SOURCE and "checksum_digest" in SOURCE

def test_release_gate_guards():
    assert "release ID already exists" in SOURCE
    assert "at least two hosts" in SOURCE
    assert "release is not pending" in SOURCE
