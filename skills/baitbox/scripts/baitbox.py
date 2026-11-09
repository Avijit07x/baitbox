import argparse
import datetime
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import analyze
import deps
import extract
import scan

VERSION = "0.1.0"
BOX = HERE / "box.sh"
SEVERITIES = ("high", "medium", "info")
EXIT_CODES = {"nothing-seen": 0, "review": 0, "suspicious": 1, "malicious": 2, "error": 3}
VERDICT_TEXT = {
    "malicious": "Malware found. Do not open or run this project.",
    "suspicious": "Suspicious. Do not run it until you have read the findings.",
    "review": "Nothing bad happened when it ran, but some files need a look before you trust it.",
    "nothing-seen": "Nothing bad was seen. That is not proof that it is safe.",
    "error": "The check did not finish. Treat the project as unchecked.",
}
PASSTHROUGH = ("scan", "deps", "analyze", "box")
MALWARE_KINDS = {"known-malware", "removed-by-npm-security"}
RUN_SCRIPTS = (("build", 180), ("dev", 60), ("start", 45), ("serve", 30), ("preview", 30))
CONFIG_LOAD_SECONDS = 40
SETTLE_SECONDS = 30
LOADER = (
    "const u=require('url');const f=process.argv[1];"
    "import(u.pathToFileURL(f).href).then(m=>{const v=m&&(m.default!==undefined?m.default:m);"
    "if(typeof v==='function'){try{const r=v({command:'serve',mode:'development'},{});"
    "if(r&&typeof r.then==='function')r.catch(()=>{});}catch(e){}}})"
    ".catch(e=>console.error('load error:',e&&e.message))"
    ".finally(()=>setTimeout(()=>{},20000));"
)
LIMITS = (
    "Malware that waits longer than the run, or waits for a date, a login or a click.",
    "Malware that notices the sandbox and stays quiet.",
    "Code paths that need a real database, account, browser or network.",
    "Windows-only or Mac-only code, and non-Node projects: these get the static scan only.",
    "Sandbox escapes through kernel bugs. Use a VM for projects you have real doubts about.",
)


def say(msg):
    print(msg, file=sys.stderr, flush=True)


def stamp():
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def safe_name(s):
    s = re.sub(r"\.(zip|tar|tgz|gz|bz2|xz|git)$", "", s, flags=re.I)
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-.")[:60]
    return s or "project"


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_text(path, text_):
    path.write_text(text_ + "\n", encoding="utf-8")


def find_package_dirs(root):
    dirs = []
    for dp, dns, fns in os.walk(root, followlinks=False):
        rel = Path(dp).relative_to(root)
        dns[:] = sorted(d for d in dns if d not in ("node_modules", ".git") and not d.startswith("."))
        if len(rel.parts) >= 4:
            dns[:] = []
        if "package.json" in fns and not os.path.islink(os.path.join(dp, "package.json")):
            dirs.append(rel)
    roots = set()
    for d in dirs:
        p = root / d
        if (p / "pnpm-workspace.yaml").exists():
            roots.add(d)
            continue
        try:
            pj = json.loads((p / "package.json").read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if isinstance(pj, dict) and pj.get("workspaces"):
            roots.add(d)
    return [d for d in dirs if not any(w != d and w in d.parents for w in roots)]


def manager_for(p):
    if (p / "pnpm-lock.yaml").exists() or (p / "pnpm-workspace.yaml").exists():
        return "pnpm"
    if (p / "package-lock.json").exists() or (p / "npm-shrinkwrap.json").exists():
        return "npm-ci"
    return "npm"


def install_command(root, dirs):
    parts = []
    notes = []
    for d in dirs:
        p = root / d
        q = shlex.quote(str(d))
        m = manager_for(p)
        if m == "pnpm":
            cmd = (
                "if command -v pnpm >/dev/null 2>&1; then pnpm install --ignore-scripts --ignore-pnpmfile "
                "--config.confirmModulesPurge=false --reporter=append-only; "
                "else npm install --ignore-scripts --no-audit --no-fund; fi"
            )
        elif m == "npm-ci":
            cmd = "npm ci --ignore-scripts --no-audit --no-fund || npm install --ignore-scripts --no-audit --no-fund"
        else:
            cmd = "npm install --ignore-scripts --no-audit --no-fund"
        if (p / "yarn.lock").exists() or (p / ".yarnrc.yml").exists():
            notes.append(f"{d}: used npm instead of yarn so no yarn plugins or yarnPath code could run")
        if (p / "bun.lock").exists() or (p / "bun.lockb").exists():
            notes.append(f"{d}: used npm instead of bun so no bun preload code could run")
        parts.append(f"echo '== install {d}'; (cd {q} && ({cmd})) || echo '== install failed in {d}'")
    return "\n".join(parts), notes


def config_files(scan_result):
    out = []
    for a in scan_result["autorun"]:
        f = a["file"]
        name = os.path.basename(f)
        if (scan.CONFIG_RE.match(name) or scan.RC_JS_RE.match(name) or f.startswith(".storybook/")) and not f.endswith(".json"):
            if re.search(r"\.(c|m)?(j|t)sx?$", f):
                out.append(f)
    return out


def run_command(root, dirs, configs, budget):
    lines = []
    for d in dirs:
        q = shlex.quote(str(d))
        tool = "pnpm" if manager_for(root / d) == "pnpm" else "npm"
        rebuild = "if command -v pnpm >/dev/null 2>&1; then pnpm rebuild; else npm rebuild; fi" if tool == "pnpm" else "npm rebuild"
        lines.append(f"echo '== install scripts {d}'; (cd {q} && timeout 180 sh -c {shlex.quote(rebuild)}) || true")
    for c in configs:
        qc = shlex.quote("/work/" + c)
        flag = "--experimental-strip-types " if re.search(r"\.(c|m)?tsx?$", c) else ""
        lines.append(
            f"echo '== loading {c}'; (cd \"$(dirname {qc})\" && timeout {CONFIG_LOAD_SECONDS} node {flag}-e {shlex.quote(LOADER)} {qc}"
            f" || timeout {CONFIG_LOAD_SECONDS} node -e {shlex.quote(LOADER)} {qc}) || true"
        )
    spent = 0
    for d in dirs:
        try:
            pj = json.loads((root / d / "package.json").read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        sc = pj.get("scripts") if isinstance(pj, dict) and isinstance(pj.get("scripts"), dict) else {}
        q = shlex.quote(str(d))
        for name, secs in RUN_SCRIPTS:
            if name in sc and spent + secs < budget:
                spent += secs
                lines.append(f"echo '== npm run {name} in {d}'; (cd {q} && timeout {secs} npm run {name}) || true")
    lines.append(f"echo '== waiting {SETTLE_SECONDS}s for delayed actions'; sleep {SETTLE_SECONDS}")
    return "\n".join(lines)


def project_npmrcs(root):
    found = []
    for dp, dns, fns in os.walk(root, followlinks=False):
        dns[:] = [d for d in dns if d not in ("node_modules", ".git")]
        if ".npmrc" in fns and not os.path.islink(os.path.join(dp, ".npmrc")):
            found.append(Path(dp) / ".npmrc")
    return found


def disable_npmrcs(root):
    moved = []
    for p in project_npmrcs(root):
        off = p.with_name(".npmrc.baitbox-off")
        if off.exists():
            continue
        p.rename(off)
        moved.append((off, p))
    return moved


def restore_npmrcs(moved):
    for off, orig in moved:
        if off.exists() and not orig.exists():
            off.rename(orig)


def box(mode, root, box_dir, seconds, command):
    p = subprocess.run(
        ["bash", str(BOX), mode, str(root), str(box_dir), str(seconds), command],
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
    )
    return {"mode": mode, "exit": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()[-2000:]}


def nm_package(path):
    p = path.replace(os.sep, "/")
    i = p.rfind("node_modules/")
    if i == -1:
        return None
    parts = p[i + len("node_modules/"):].split("/")
    if parts[0].startswith("@") and len(parts) > 1:
        return f"{parts[0]}/{parts[1]}"
    return parts[0] or None


def flagged_packages(depss):
    names = set()
    for _, d in depss:
        for pk in d["packages"]:
            if pk.get("severity") in ("high", "medium"):
                names.add(pk["name"])
        for f in d["findings"]:
            if f["severity"] in ("high", "medium") and f["kind"] in ("non-registry-source", "name-mismatch", "not-in-lockfile"):
                names.add(f["what"].split(":")[0].split(" ")[0])
    return names


def collect_findings(intake_info, scans, depss, analysis):
    found = []
    flagged = flagged_packages(depss)
    hidden = 0
    for s in intake_info.get("skipped", []):
        found.append({"stage": "unpack", "severity": s["severity"], "kind": "unpack", "what": f"{s['path']}: {s['reason']}"})
    seen = set()
    for label, sres in scans:
        for a in sres["autorun"]:
            if a["severity"] == "info":
                continue
            key = ("autorun", a["file"], a["why"])
            if key in seen:
                continue
            seen.add(key)
            loads = f" (loads {', '.join(a['loads'])})" if a["loads"] else ""
            found.append({"stage": label, "severity": a["severity"], "kind": "runs-code", "what": f"{a['file']}: {a['why']}{loads}"})
        for f in sres["findings"]:
            if f["severity"] == "info":
                continue
            if f["in_node_modules"] and f["kind"] not in MALWARE_KINDS and nm_package(f["file"]) not in flagged:
                hidden += 1
                continue
            where = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            key = ("scan", f["kind"], where)
            if key in seen:
                continue
            seen.add(key)
            snip = f" | {f['snippet'][:160]}" if f["snippet"] else ""
            found.append({"stage": label, "severity": f["severity"], "kind": f["kind"], "what": f"{where}: {f['what']}{snip}"})
    for label, dres in depss:
        for f in dres["findings"]:
            if f["severity"] == "info":
                continue
            key = ("deps", f["kind"], f["what"])
            if key in seen:
                continue
            seen.add(key)
            found.append({"stage": label, "severity": f["severity"], "kind": f["kind"], "what": f["what"]})
    if analysis:
        for r in analysis["runs"]:
            stage = "sandbox install" if r["mode"] == "net" else "sandbox run"
            for f in r["findings"]:
                if f["severity"] == "info":
                    continue
                phase = f.get("phase") or ""
                stage_label = f"{stage}: {phase}" if phase and phase not in ("run", "install") else stage
                by = f" | by {f['process']}" if f["process"] else ""
                cnt = f" (x{f['count']})" if f["count"] > 1 else ""
                found.append({"stage": stage_label, "severity": f["severity"], "kind": f["kind"], "what": f"{f['what']}{cnt}{by}"})
    order = {s: i for i, s in enumerate(SEVERITIES)}
    found.sort(key=lambda f: order[f["severity"]])
    return found, hidden


def decide(findings, scans, depss, analysis, errors):
    malware = []
    for _, s in scans:
        malware += [f for f in s["findings"] if f["kind"] in MALWARE_KINDS]
    for _, d in depss:
        malware += [f for f in d["findings"] if f["kind"] in MALWARE_KINDS]
    if analysis and analysis["verdict"] == "malicious-behaviour":
        return "malicious"
    if malware:
        return "malicious"
    if errors:
        return "error"
    sandbox = [f for f in findings if f["stage"].startswith("sandbox")]
    if any(f["severity"] == "high" for f in findings) or any(f["severity"] == "medium" for f in sandbox):
        return "suspicious"
    if any(f["severity"] == "medium" for f in findings):
        return "review"
    return "nothing-seen"


def render_report(rep):
    v = rep["verdict"]
    out = [f"# BaitBox report: {rep['name']}", ""]
    out.append(f"**Verdict: {VERDICT_TEXT[v]}**")
    out.append("")
    out.append(f"- Source: `{rep['source']}`")
    out.append(f"- Checked: {rep['checked_at']} with BaitBox {rep['version']}")
    out.append(f"- Project folder: `{rep['project_root']}`")
    c = rep["counts"]
    out.append(f"- Findings: {c.get('high', 0)} high, {c.get('medium', 0)} medium")
    if rep["errors"]:
        out.append("")
        out.append("## Errors")
        out.extend(f"- {e}" for e in rep["errors"])
    for sev in ("high", "medium"):
        items = [f for f in rep["findings"] if f["severity"] == sev]
        if not items:
            continue
        out.append("")
        out.append(f"## {sev.capitalize()} ({len(items)})")
        for f in items[:120]:
            out.append(f"- [{f['stage']}] {f['what']}")
        if len(items) > 120:
            out.append(f"- ... and {len(items) - 120} more in report.json")
    if rep["runs"]:
        out.append("")
        out.append("## What ran in the sandbox")
        for r in rep["runs"]:
            label = "Install (online, scripts off)" if r["mode"] == "net" else "Run (offline)"
            t = ", stopped by the time limit" if r.get("timed_out") else ""
            out.append(f"- {label}: exit {r['exit_status']}{t}, {r['seconds']}s. Programs: {', '.join(f'{k} x{n}' for k, n in list(r['programs'].items())[:12]) or 'none'}")
    if rep["notes"]:
        out.append("")
        out.append("## Notes")
        out.extend(f"- {n}" for n in rep["notes"])
    out.append("")
    out.append("## Not covered by this check")
    out.extend(f"- {x}" for x in LIMITS)
    out.append("")
    out.append("## Files")
    for k, p in rep["files"].items():
        out.append(f"- {k}: `{p}`")
    return "\n".join(out)


def cmd_check(a):
    src = a.source
    default = extract.repo_name(src) if extract.is_git_url(src) else Path(src.rstrip("/")).name
    name = safe_name(a.name or default or "project")
    out = Path(a.out).expanduser() if a.out else Path.home() / "baitbox-checks" / f"{name}-{stamp()}"
    if out.exists() and any(out.iterdir()):
        say(f"baitbox: output folder is not empty: {out}")
        return 3
    out.mkdir(parents=True, exist_ok=True)
    say(f"BaitBox {VERSION}: checking {src}")
    say(f"check folder: {out}")
    errors, notes = [], []
    say("[1/5] unpacking safely")
    try:
        info = extract.intake(src, out / "src")
    except (extract.IntakeError, OSError) as e:
        say(f"baitbox: could not unpack: {e}")
        write_json(out / "report.json", {"verdict": "error", "errors": [str(e)]})
        return 3
    write_json(out / "intake.json", info)
    root = Path(info["project_root"])
    say(f"      {info['files']} files, {len(info['skipped'])} entries refused")
    say("[2/5] reading files (nothing runs)")
    s1 = scan.scan(root)
    write_json(out / "scan.json", s1)
    write_text(out / "scan.txt", scan.render(s1))
    say("[3/5] checking packages" + (" (offline)" if a.offline else " against npm and OSV"))
    d1 = deps.check(root, offline=a.offline)
    write_json(out / "deps.json", d1)
    write_text(out / "deps.txt", deps.render(d1))
    scans, depss = [("static scan", s1)], [("packages", d1)]
    notes += d1["notes"]
    analysis = None
    dirs = find_package_dirs(root)
    if a.static_only:
        notes.append("static only: nothing was run in the sandbox")
    elif not shutil.which("bwrap") or not shutil.which("strace") or not shutil.which("node"):
        errors.append("bwrap, strace or node is missing; run 'baitbox doctor'. Only the static checks ran.")
    else:
        box_dir = out / "box"
        if dirs:
            say(f"[4/5] installing in the sandbox (online, install scripts off, up to {a.install_timeout}s)")
            cmd, n = install_command(root, dirs)
            notes += n
            moved = disable_npmrcs(root)
            if moved:
                notes.append(
                    f"{len(moved)} project .npmrc file(s) were switched off during install, so their tokens and "
                    "registries were never used; private packages may be missing from the run"
                )
            try:
                r = box("net", root, box_dir, a.install_timeout, cmd)
            finally:
                restore_npmrcs(moved)
            if r["exit"] in (2, 3):
                errors.append("sandbox install failed: " + (r["stderr"] or r["stdout"])[-400:])
            s2 = scan.scan(root)
            write_json(out / "scan-after-install.json", s2)
            write_text(out / "scan-after-install.txt", scan.render(s2))
            d2 = deps.check(root, offline=a.offline)
            write_json(out / "deps-after-install.json", d2)
            write_text(out / "deps-after-install.txt", deps.render(d2))
            scans.append(("installed files", s2))
            depss.append(("installed packages", d2))
            notes += [x for x in d2["notes"] if x not in notes and "no lockfile" not in x]
        else:
            say("[4/5] no package.json found, skipping install")
            notes.append("no package.json found, so nothing was installed")
        configs = config_files(s1)
        if dirs or configs:
            say(f"[5/5] running it in the sandbox (offline, up to {a.run_timeout}s)")
            cmd = run_command(root, dirs, configs, max(60, a.run_timeout - SETTLE_SECONDS - 60))
            r = box("nonet", root, box_dir, a.run_timeout, cmd)
            if r["exit"] in (2, 3):
                errors.append("sandbox run failed: " + (r["stderr"] or r["stdout"])[-400:])
        else:
            notes.append("nothing to run: no package.json and no config files")
        if box_dir.exists():
            analysis = analyze.analyze(box_dir)
            write_json(out / "sandbox.json", analysis)
            write_text(out / "sandbox.txt", analyze.render(analysis))
            for run in analysis["runs"]:
                if run["error"]:
                    errors.append(f"{run['run']}: {run['error']}")
    findings, hidden = collect_findings(info, scans, depss, analysis)
    if hidden:
        notes.append(f"{hidden} scan hit(s) inside node_modules were left out because their packages passed the package check; they are listed in scan.txt")
    verdict = decide(findings, scans, depss, analysis, errors)
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    files = {"report": str(out / "report.md"), "static scan": str(out / "scan.txt"), "packages": str(out / "deps.txt")}
    if analysis:
        files["sandbox"] = str(out / "sandbox.txt")
        files["sandbox logs"] = str(out / "box" / "logs")
    rep = {
        "name": name, "version": VERSION, "source": src, "checked_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "check_folder": str(out), "project_root": str(root), "verdict": verdict, "verdict_text": VERDICT_TEXT[verdict],
        "counts": counts, "errors": errors, "notes": notes, "findings": findings,
        "runs": [
            {k: r[k] for k in ("run", "mode", "exit_status", "seconds", "timed_out", "programs")} for r in (analysis or {}).get("runs", [])
        ],
        "files": files,
    }
    write_json(out / "report.json", rep)
    write_text(out / "report.md", render_report(rep))
    if a.json:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
    else:
        print()
        print(f"Verdict: {VERDICT_TEXT[verdict]}")
        print(f"Findings: {counts['high']} high, {counts['medium']} medium")
        for f in [x for x in findings if x["severity"] == "high"][:10]:
            print(f"  - [{f['stage']}] {f['what'][:200]}")
        for e in errors:
            print(f"Error: {e[:300]}")
        print(f"Report: {out / 'report.md'}")
    return EXIT_CODES[verdict]


def probe(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)


def first_line(s):
    return s.splitlines()[0] if s else ""


def cmd_doctor(_a):
    rows = []

    def row(name, ok, detail, fix="", required=True):
        rows.append((name, ok, detail, fix, required))

    row("python 3.10+", sys.version_info >= (3, 10), sys.version.split()[0], "install Python 3.10 or newer")
    for tool, fix in (("bwrap", "sudo apt install bubblewrap"), ("strace", "sudo apt install strace")):
        path = shutil.which(tool)
        ok, outp = probe([tool, "--version"]) if path else (False, "")
        row(tool, bool(path), first_line(outp) or "not installed", fix)
    for tool in ("timeout", "sha256sum", "realpath", "find", "diff"):
        row(tool, bool(shutil.which(tool)), "found" if shutil.which(tool) else "not installed", "install coreutils, findutils and diffutils")
    node = shutil.which("node")
    ok, outp = probe(["node", "--version"]) if node else (False, "")
    row("node", bool(node), outp or "not installed", "install Node.js 18 or newer")
    row("npm", bool(shutil.which("npm")), "found" if shutil.which("npm") else "not installed", "install npm")
    row("git", bool(shutil.which("git")), "found" if shutil.which("git") else "not installed", "needed only for git links", False)
    row("pnpm", bool(shutil.which("pnpm")), "found" if shutil.which("pnpm") else "not installed (npm is used instead)", "", False)
    if shutil.which("bwrap"):
        ok, outp = probe(["bwrap", "--ro-bind", "/", "/", "--unshare-all", "--die-with-parent", "true"])
        hint = "unprivileged user namespaces are blocked"
        sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        if sysctl.exists() and sysctl.read_text().strip() == "1":
            hint += "; AppArmor blocks them: see the README troubleshooting section"
        row("sandbox starts", ok, "ok" if ok else first_line(outp), hint)
    ys = Path("/proc/sys/kernel/yama/ptrace_scope")
    scope = ys.read_text().strip() if ys.exists() else "0"
    if scope == "2":
        row("ptrace allowed", True, "kernel.yama.ptrace_scope=2: each run asks for your sudo password and sets it to 1 until the run ends")
    else:
        row("ptrace allowed", scope in ("0", "1"), f"kernel.yama.ptrace_scope={scope}", "strace needs ptrace_scope 0, 1 or 2; 3 turns ptrace off until reboot")
    if shutil.which("bwrap") and shutil.which("strace") and scope in ("0", "1"):
        ok, outp = probe(["strace", "-f", "-o", "/dev/null", "bwrap", "--ro-bind", "/", "/", "--unshare-all", "--die-with-parent", "true"])
        row("strace can follow the sandbox", ok, "ok" if ok else first_line(outp), "bwrap may be setuid on this system; BaitBox needs the non-setuid build")
    width = max(len(r[0]) for r in rows)
    bad = 0
    for name, ok, detail, fix, required in rows:
        mark = "ok  " if ok else ("FAIL" if required else "warn")
        print(f"{mark}  {name.ljust(width)}  {detail}")
        if not ok and fix:
            print(f"      {' ' * width}  fix: {fix}")
        if not ok and required:
            bad += 1
    print()
    print("Ready." if not bad else f"{bad} required check(s) failed.")
    return 0 if not bad else 1


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


def cmd_selftest(a):
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


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    if argv and argv[0] in PASSTHROUGH:
        rest = argv[1:]
        if argv[0] == "box":
            return subprocess.call(["bash", str(BOX), *rest])
        return {"scan": scan.main, "deps": deps.main, "analyze": analyze.main}[argv[0]](rest)
    p = argparse.ArgumentParser(prog="baitbox", description="Check a project for malware before you open it.")
    p.add_argument("--version", action="version", version=f"baitbox {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="unpack, scan, install and run a project in the sandbox, then report")
    c.add_argument("source", help="zip, tar, folder, single file, or git URL (https://, ssh://, git@)")
    c.add_argument("--out", help="check folder (default: ~/baitbox-checks/<name>-<time>)")
    c.add_argument("--name", help="name for the check folder")
    c.add_argument("--static-only", action="store_true", help="read and check packages only; run nothing")
    c.add_argument("--offline", action="store_true", help="skip npm and OSV lookups")
    c.add_argument("--install-timeout", type=int, default=900, help="seconds for the install step (default 900)")
    c.add_argument("--run-timeout", type=int, default=600, help="seconds for the run step (default 600)")
    c.add_argument("--json", action="store_true", help="print the report as JSON")
    sub.add_parser("doctor", help="check that this machine can run the sandbox")
    st = sub.add_parser("selftest", help="run a harmless fake attack and confirm it is caught")
    st.add_argument("--keep", action="store_true", help="keep the self-test folder")
    sub.add_parser("scan", help="static scan only: baitbox scan <folder> [--json]")
    sub.add_parser("deps", help="package check only: baitbox deps <folder> [--json] [--offline]")
    sub.add_parser("analyze", help="summarise sandbox recordings: baitbox analyze <box folder> [--json]")
    sub.add_parser("box", help="run one command in the sandbox: baitbox box <net|nonet> <project> <box> <seconds> <command>")
    a = p.parse_args(argv)
    if a.cmd == "check":
        if not 30 <= a.install_timeout <= 86400 or not 60 <= a.run_timeout <= 86400:
            p.error("--install-timeout must be 30-86400 and --run-timeout 60-86400")
        return cmd_check(a)
    if a.cmd == "doctor":
        return cmd_doctor(a)
    if a.cmd == "selftest":
        return cmd_selftest(a)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        say("baitbox: stopped")
        sys.exit(130)
