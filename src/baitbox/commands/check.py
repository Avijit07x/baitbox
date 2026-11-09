import datetime
import json
import re
import shutil
from pathlib import Path

from baitbox import SEVERITIES, VERSION, analyze, deps, scan, unpack
from baitbox.console import say
from baitbox.report import EXIT_CODES, VERDICT_TEXT, collect_findings, decide, render_report
from baitbox.sandbox import SETTLE_SECONDS, box, config_files, disable_npmrcs, find_package_dirs, install_command, restore_npmrcs, run_command


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


def add_parser(sub):
    c = sub.add_parser("check", help="unpack, scan, install and run a project in the sandbox, then report")
    c.add_argument("source", help="zip, tar, folder, single file, or git URL (https://, ssh://, git@)")
    c.add_argument("--out", help="check folder (default: ~/baitbox-checks/<name>-<time>)")
    c.add_argument("--name", help="name for the check folder")
    c.add_argument("--static-only", action="store_true", help="read and check packages only; run nothing")
    c.add_argument("--offline", action="store_true", help="skip npm and OSV lookups")
    c.add_argument("--install-timeout", type=int, default=900, help="seconds for the install step (default 900)")
    c.add_argument("--run-timeout", type=int, default=600, help="seconds for the run step (default 600)")
    c.add_argument("--json", action="store_true", help="print the report as JSON")


def run(a, parser):
    if not 30 <= a.install_timeout <= 86400 or not 60 <= a.run_timeout <= 86400:
        parser.error("--install-timeout must be 30-86400 and --run-timeout 60-86400")
    src = a.source
    default = unpack.repo_name(src) if unpack.is_git_url(src) else Path(src.rstrip("/")).name
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
        info = unpack.intake(src, out / "src")
    except (unpack.IntakeError, OSError) as e:
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
