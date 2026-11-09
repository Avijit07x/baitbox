import json
import os
import re
import shlex
from pathlib import Path

from baitbox.scan import CONFIG_RE, RC_JS_RE

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
        if (CONFIG_RE.match(name) or RC_JS_RE.match(name) or f.startswith(".storybook/")) and not f.endswith(".json"):
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
