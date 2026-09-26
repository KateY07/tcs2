"""Validate the shipping CLI restrictions and fixture key preflight without touching real identities."""
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil

exe, harness = map(lambda p: Path(p).resolve(), sys.argv[1:3])


def run(binary, *args, code=0):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=20)
    assert result.returncode == code, (args, result.stdout, result.stderr)
    return result


for option in ("--data", "--host-key", "--authorized-keys", "--client-key", "--server-key", "--known-hosts"):
    for mode in ([], ["--tcsd"], ["pairing", "export"], ["--tcsd", "pairing", "import", "missing.json"]):
        rejected = run(exe, *mode, option, "unused", code=1)
        assert "不再支持" in rejected.stderr and "固定路径" in rejected.stderr
    run(exe, option + "=unused", code=1)
run(exe, "--generate-host-key", "unused", code=1)
run(exe, "--verify-install", code=1)
for mode in ([], ["--tcsd"]):
    help_text = run(exe, *mode, "--help").stdout
    assert "--data" not in help_text and "--client-key" not in help_text
    assert "固定" in help_text
run(exe, "--check-install", "invalid", code=1)
print("PASS shipping CLI refuses all path overrides and key generation; fixed-path help")

with tempfile.TemporaryDirectory(prefix="tcs-preflight-") as directory:
    root = Path(directory)
    renamed = root / "renamed-tcs.exe"
    shutil.copyfile(exe, renamed)
    legacy_attempt = run(renamed, "-i", root, "-p", "10122", code=1)
    assert "参数" in legacy_attempt.stderr
    assert not (root / "tcs-audit.log").exists()
    run(renamed, "--host-key", "unused", code=1)
    key, other = root / "identity", root / "other"
    run(harness, "--validate-pair", key, code=1)
    assert list(root.iterdir()) == [renamed]
    run(harness, "--generate-host-key", key)
    private_bytes = key.read_bytes()
    public_bytes = Path(str(key) + ".pub").read_bytes()
    run(harness, "--validate-pair", key)
    Path(str(key) + ".pub").unlink()
    run(harness, "--validate-pair", key)
    assert not Path(str(key) + ".pub").exists()
    assert key.read_bytes() == private_bytes
    run(harness, "--generate-host-key", other)
    Path(str(key) + ".pub").write_bytes(Path(str(other) + ".pub").read_bytes())
    stale_public = Path(str(key) + ".pub").read_bytes()
    mismatch = run(harness, "--validate-pair", key)
    assert not mismatch.stderr.strip()
    assert key.read_bytes() == private_bytes
    assert Path(str(key) + ".pub").read_bytes() == stale_public
    exported = root / "pair.json"
    run(harness, "pairing", "export", "--client-key", key, "--output", exported)
    import json
    assert json.loads(exported.read_text())["publicKey"].split()[1] == public_bytes.decode().split()[1]
    Path(str(key) + ".pub").write_text("corrupt public copy", encoding="utf-8")
    corrupt_copy = run(harness, "--validate-pair", key)
    assert not corrupt_copy.stderr.strip()
    assert Path(str(key) + ".pub").read_text() == "corrupt public copy"
    Path(str(key) + ".pub").write_bytes(public_bytes)
    key.write_text("not a private key", encoding="utf-8")
    run(harness, "--validate-pair", key, code=1)
    key.write_bytes(private_bytes)
    encrypted = root / "encrypted"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "test-only-passphrase",
                    "-f", str(encrypted)], check=True, capture_output=True, timeout=20)
    run(harness, "--validate-pair", encrypted, code=1)
    for role, name in (("controller", "id_ed25519"), ("server", "tcs_host_key")):
        script = run(harness, "--instructions", role).stdout
        assert f".ssh\\{name}" in script and "ssh-keygen -t ed25519" in script
        assert "Test-Path" in script and "throw" in script
print("PASS private-only identity accepted; stale/corrupt public copies ignored and preserved; export derives actual public key")
print("PASS missing, corrupt and encrypted private keys rejected without replacement")

installer = Path(__file__).with_name("_installer") / "install-user.bat"
source = installer.read_text(encoding="utf-8-sig")
assert source.index("--check-install") < source.index('mkdir "%TARGET%"') < source.index("set-user-path.ps1")
assert "if errorlevel 1 goto prerequisites" in source and ":prerequisites" in source
print("PASS installer preflight precedes target directory, binary copy and PATH changes (static check)")
print("ALL DEPLOYMENT REGRESSION TESTS PASSED")
