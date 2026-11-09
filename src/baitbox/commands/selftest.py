import shutil
import tempfile
import textwrap
from pathlib import Path

from baitbox import analyze
from baitbox.sandbox import box

SELFTEST_JS = textwrap.dedent("""
    const fs = require('fs'), os = require('os'), net = require('net'), dns = require('dns'), cp = require('child_process');
    const h = os.homedir();
    try { fs.readFileSync(h + '/.ssh/id_ed25519'); } catch (e) {}
    try { fs.symlinkSync(h + '/.aws/credentials', 'innocent.txt'); fs.readFileSync('innocent.txt'); } catch (e) {}
    try { fs.mkdirSync(h + '/.config/autostart', { recursive: true }); fs.writeFileSync(h + '/.config/autostart/update.desktop', '[Desktop Entry]'); } catch (e) {}
    try { cp.execSync('sudo -n true', { stdio: 'ignore' }); } catch (e) {}
    for (const fd of fs.readdirSync('/proc/self/fd')) { const n = Number(fd); try { if (n > 2 && fs.fstatSync(n).isFile()) { fs.ftruncateSync(n, 0); fs.writeSync(n, 'BAITBOX-TAMPER\\n'); } } catch (e) {} }
    try { fs.writeFileSync('/logs/x.trace', 'BAITBOX-TAMPER'); } catch (e) {}
    dns.lookup('baitbox-selftest.invalid', () => {});
    net.connect(1224, '216.126.231.70').on('error', () => {});
    setTimeout(() => process.exit(0), 2000);
""").strip()


def add_parser(sub):
    st = sub.add_parser("selftest", help="run a harmless fake attack and confirm it is caught")
    st.add_argument("--keep", action="store_true", help="keep the self-test folder")


def run(a, _parser):
    tmp = Path(tempfile.mkdtemp(prefix="baitbox-selftest-"))
    try:
        src = tmp / "project"
        src.mkdir()
        (src / "attack.js").write_text(SELFTEST_JS + "\n")
        r = box("nonet", src, tmp / "box", 60, "node attack.js")
        if r["exit"] in (2, 3):
            print("FAIL  the sandbox did not run:")
            print(r["stderr"] or r["stdout"])
            return 1
        res = analyze.analyze(tmp / "box")
        whats = [f["what"] for run in res["runs"] for f in run["findings"]]
        traces = list((tmp / "box" / "logs").glob("*.trace"))
        intact = bool(traces) and all("BAITBOX-TAMPER" not in t.read_text(errors="replace")[:4096] for t in traces)
        checks = (
            ("reads a bait SSH key", any("~/.ssh/id_ed25519" in w and "bait" in w for w in whats)),
            ("reads a bait file through a symlink", any("~/.aws/credentials" in w for w in whats)),
            ("writes a startup file", any(".config/autostart" in w for w in whats)),
            ("runs sudo", any(w == "started sudo" for w in whats)),
            ("looks up a domain", any("baitbox-selftest.invalid" in w for w in whats)),
            ("calls a hard-coded address", any("216.126.231.70:1224" in w for w in whats)),
            ("recording survives tampering", intact and any("216.126.231.70:1224" in w for w in whats)),
            ("real home untouched", not (Path.home() / ".config/autostart/update.desktop").exists()),
        )
        bad = 0
        for name, ok in checks:
            print(f"{'ok  ' if ok else 'FAIL'}  {name}")
            bad += 0 if ok else 1
        print()
        print("Self-test passed." if not bad else f"Self-test failed: {bad} check(s). Logs: {tmp}")
        if bad:
            a.keep = True
        return 0 if not bad else 1
    finally:
        if not a.keep:
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            print(f"kept: {tmp}")
