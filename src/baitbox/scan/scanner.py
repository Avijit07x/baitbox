import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path

from baitbox import SEVERITIES
from baitbox.scan.helpers import code_like, magic, mask_tokens, package_of, public_ip, snippet
from baitbox.scan.rules import (
    CAP_NM,
    CAP_PER_FILE,
    CAP_PROJECT,
    CODE_EXT,
    CONFIG_RE,
    IMPORT_RE,
    KNOWN_HASHES,
    LIFECYCLE,
    MAX_FILE,
    OTHER_AUTORUN,
    PACKED_DIRS,
    PKG_TOOL_KEYS,
    PREBUILT_OK,
    PY_AUTORUN,
    RC_JS_RE,
    SOURCE_ONLY,
    STRONG,
    TEXT_EXT,
    VSCODE_RISKY_KEYS,
    WIN_EXT,
)


class Scan:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.findings = []
        self.autorun = []
        self.scripts = []
        self.npmrc = []
        self.stats = Counter()
        self.kind_count = Counter()
        self.agent_files = []

    def add(self, severity, kind, file, what, line=0, snip="", in_nm=False):
        cap = CAP_NM if in_nm else CAP_PROJECT
        key = (kind, in_nm)
        self.kind_count[key] += 1
        if self.kind_count[key] > cap and severity != "high":
            return
        self.findings.append({
            "severity": severity, "kind": kind, "file": file, "line": line, "what": what, "snippet": snip,
            "in_node_modules": in_nm,
        })

    def rel(self, path):
        return os.path.relpath(path, self.root)

    def walk(self):
        for dp, dns, fns in os.walk(self.root, followlinks=False, onerror=lambda e: None):
            dns.sort()
            fns.sort()
            rel_dir = self.rel(dp)
            parts = Path(rel_dir).parts
            if ".git" in parts:
                gi = parts.index(".git")
                if parts[gi + 1:] == ("hooks",):
                    for f in fns:
                        if not f.endswith(".sample"):
                            self.add_autorun(os.path.join(rel_dir, f), "medium", "git hook: runs on git commands")
                dns[:] = ["hooks"] if len(parts) == gi + 1 and "hooks" in dns else []
                continue
            for d in list(dns):
                full = os.path.join(dp, d)
                if os.path.islink(full):
                    self.on_symlink(full)
                    dns.remove(d)
            in_nm = "node_modules" in parts
            for f in fns:
                full = os.path.join(dp, f)
                if os.path.islink(full):
                    self.on_symlink(full)
                    continue
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if not os.path.isfile(full):
                    self.add("high", "special-file", self.rel(full), "special file (socket, device or pipe)")
                    continue
                self.stats["node_modules files" if in_nm else "project files"] += 1
                self.stats["bytes"] += st.st_size
                self.on_file(full, f, in_nm, st.st_size)

    def on_symlink(self, full):
        try:
            target = os.readlink(full)
        except OSError:
            target = "?"
        rel = self.rel(full)
        in_nm = "node_modules" in Path(rel).parts
        resolved = os.path.normpath(os.path.join(os.path.dirname(full), target))
        escapes = target.startswith("/") or not (resolved == str(self.root) or resolved.startswith(str(self.root) + os.sep))
        if escapes and not in_nm:
            self.add("high", "symlink", rel, f"link points outside the project: {target}")
        elif escapes:
            self.add("medium", "symlink", rel, f"link points outside the project: {target}", in_nm=True)
        elif not in_nm:
            self.add("info", "symlink", rel, f"link to {target}")

    def add_autorun(self, rel, severity, why, loads=None):
        self.autorun.append({"file": rel, "severity": severity, "why": why, "loads": sorted(loads or [])})

    def on_file(self, full, name, in_nm, size):
        rel = self.rel(full)
        relp = rel.replace(os.sep, "/")
        ext = os.path.splitext(name)[1].lower()
        kind = magic(full)
        if kind:
            if ext in TEXT_EXT and kind != "WebAssembly module":
                self.add("high", "disguised-program", rel, f"{kind} with a {ext} name", in_nm=in_nm)
            elif not in_nm:
                self.add("medium", "program", rel, kind)
            elif not PREBUILT_OK.search(relp) and kind != "WebAssembly module":
                self.add("info" if kind.startswith("Windows") else "medium", "program", rel, kind, in_nm=True)
        if not in_nm and ext in WIN_EXT:
            self.add("medium", "windows-file", rel, f"Windows {ext} file in the project")
        if not in_nm:
            self.check_autorun(full, rel, relp, name, ext)
        if name == "package.json":
            self.on_package_json(full, rel, in_nm)
        if size > MAX_FILE:
            self.add("info", "large-file", rel, f"{size} bytes, not scanned", in_nm=in_nm)
            return
        if ext not in TEXT_EXT and not (name.startswith(".") or "." not in name):
            return
        try:
            data = Path(full).read_bytes()
        except OSError:
            return
        if b"\0" in data[:8192]:
            return
        if ext in (".js", ".cjs", ".mjs") and size < 6_000_000:
            h = hashlib.sha256(data).hexdigest()
            if h in KNOWN_HASHES:
                self.add("high", "known-malware", rel, f"file matches {KNOWN_HASHES[h]}", in_nm=in_nm)
        content = data.decode("utf-8", errors="replace")
        lines = content.split("\n")
        longest = max((len(x) for x in lines), default=0)
        packed_path = ".min." in name or any(d in "/" + relp for d in PACKED_DIRS)
        if ext in (".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx"):
            if not in_nm and longest > 1500 and not packed_path:
                long_line = max(lines, key=len)
                self.add("medium" if code_like(long_line) else "info", "packed-code", rel, f"longest line {longest} chars in {len(lines)} lines")
            elif in_nm and not packed_path and longest > 20000 and len(lines) < 30:
                self.add("medium", "packed-code", rel, f"{size} bytes, longest line {longest} chars in {len(lines)} lines", in_nm=True)
        is_auto = any(a["file"] == rel for a in self.autorun)
        code = ext in CODE_EXT or name.startswith(".") or "." not in name
        for kind_name, rx, sev_proj, sev_nm in STRONG:
            if kind_name in ("bidi-control", "invisible-code", "hidden-after-spaces") and not code:
                continue
            if in_nm and ext == ".json" and kind_name != "known-malware":
                continue
            if ext in (".md", ".mdx", ".txt") and (in_nm or kind_name not in ("known-malware", "download-and-run", "bidi-control", "invisible-code")):
                if not (in_nm and kind_name == "known-malware"):
                    continue
            sev = sev_nm if in_nm else sev_proj
            if is_auto and sev != "high":
                sev = "high" if sev == "medium" else "medium"
            self.match(rx, kind_name, sev, rel, content, lines, in_nm)
        if not in_nm and code:
            for kind_name, rx, sev in SOURCE_ONLY:
                if is_auto and sev != "high":
                    sev = "high" if sev == "medium" else "medium"
                self.match(rx, kind_name, sev, rel, content, lines, False)

    def match(self, rx, kind, sev, rel, content, lines, in_nm):
        if not rx.search(content):
            return
        n = 0
        for i, line in enumerate(lines, 1):
            for m in rx.finditer(line):
                if kind == "public-ip" and not public_ip(m.group(0)):
                    continue
                self.add(sev, kind, rel, kind.replace("-", " "), i, snippet(line, m)[:240], in_nm)
                n += 1
                break
            if n >= CAP_PER_FILE:
                break

    def read_text(self, full, limit=2_000_000):
        try:
            with open(full, "rb") as f:
                return f.read(limit).decode("utf-8", errors="replace")
        except OSError:
            return ""

    def imports_of(self, full):
        return {p for p in (package_of(s) for s in IMPORT_RE.findall(self.read_text(full))) if p}

    def check_autorun(self, full, rel, relp, name, ext):
        parts = relp.split("/")
        top = parts[0]
        if CONFIG_RE.match(name) or RC_JS_RE.match(name):
            self.add_autorun(rel, "info", "runs when tools or editor extensions load it", self.imports_of(full))
            return
        if name in (".pnpmfile.cjs", "pnpmfile.js", ".pnpmfile.mjs"):
            self.add_autorun(rel, "medium", "runs on every pnpm install", self.imports_of(full))
            return
        if name == ".npmrc":
            self.on_npmrc(full, rel)
            return
        if name == ".yarnrc":
            t = self.read_text(full)
            sev = "high" if re.search(r"^\s*yarn-path\s", t, re.M) else "info"
            self.add_autorun(rel, sev, "yarn-path runs a JS file every time yarn starts" if sev == "high" else "yarn settings")
            self.npmrc.append({"file": rel, "content": mask_tokens(t)[:3000]})
            return
        if name == ".yarnrc.yml":
            t = self.read_text(full)
            m = re.search(r"^\s*yarnPath:\s*(\S+)", t, re.M)
            if m:
                normal = m.group(1).strip("'\"").startswith(".yarn/releases/")
                self.add_autorun(rel, "medium" if normal else "high", f"yarnPath runs {m.group(1)} every time yarn starts")
            if re.search(r"^\s*plugins:", t, re.M):
                self.add_autorun(rel, "medium", "yarn plugins run on every yarn command")
            if not m and not re.search(r"^\s*plugins:", t, re.M):
                self.add_autorun(rel, "info", "yarn settings")
            self.npmrc.append({"file": rel, "content": mask_tokens(t)[:3000]})
            return
        if name == "bunfig.toml":
            t = self.read_text(full)
            self.add_autorun(rel, "high" if re.search(r"^\s*preload\s*=", t, re.M) else "info", "bun preload scripts run before every bun command")
            return
        if name == ".envrc":
            self.add_autorun(rel, "medium", "direnv runs this when you enter the folder")
            return
        if name in PY_AUTORUN or ext == ".pth":
            sev = PY_AUTORUN.get(name, "high")
            self.add_autorun(rel, sev, "Python runs this automatically" if sev == "high" else "runs on Python install or test")
            return
        if name in OTHER_AUTORUN:
            sev = "info"
            if name in ("tsconfig.json", "jsconfig.json"):
                if not re.search(r'"plugins"\s*:', self.read_text(full)):
                    return
                sev = "medium"
            self.add_autorun(rel, sev, OTHER_AUTORUN[name])
            return
        if top == ".vscode" or top == ".cursor" or top == ".windsurf":
            self.on_vscode(full, rel, name)
            return
        if top == ".devcontainer" or name == ".devcontainer.json":
            t = self.read_text(full)
            if re.search(r'"initializeCommand"\s*:', t):
                self.add_autorun(rel, "high", "initializeCommand runs on your real machine when the container opens")
            elif re.search(r'"(postCreateCommand|postStartCommand|postAttachCommand|onCreateCommand|updateContentCommand)"\s*:', t):
                self.add_autorun(rel, "medium", "runs commands when the dev container starts")
            else:
                self.add_autorun(rel, "info", "dev container settings")
            return
        if top == ".husky" and not name.startswith("."):
            self.add_autorun(rel, "medium", "git hook: runs on git commit or push")
            return
        if top == ".claude" or name in ("CLAUDE.md", "AGENTS.md", ".mcp.json", "GEMINI.md", ".cursorrules", ".windsurfrules"):
            self.on_agent_file(full, rel, name)
            return
        if relp.startswith(".github/workflows/"):
            self.add_autorun(rel, "info", "runs on GitHub, not on your machine")
            return
        if relp.startswith(".idea/") and name in ("workspace.xml", "runConfigurations.xml"):
            self.add_autorun(rel, "info", "JetBrains run settings")
            return
        if relp.startswith(".storybook/") and ext in (".js", ".cjs", ".mjs", ".ts"):
            self.add_autorun(rel, "info", "runs when storybook starts", self.imports_of(full))

    def on_agent_file(self, full, rel, name):
        t = self.read_text(full)
        if name in ("settings.json", "settings.local.json") and re.search(r'"hooks"\s*:', t):
            self.add_autorun(rel, "high", "Claude Code hooks run shell commands when an agent works here")
        elif name == ".mcp.json" or name.endswith("mcp.json"):
            self.add_autorun(rel, "medium" if re.search(r'"command"\s*:', t) else "info", "starts MCP servers (programs) for AI agents")
        elif name.endswith(".md") or name in (".cursorrules", ".windsurfrules"):
            self.agent_files.append(rel)
            self.add_autorun(rel, "info", "instructions for AI agents: read before letting an agent work here")
        else:
            self.add_autorun(rel, "info", "AI agent settings")

    def on_vscode(self, full, rel, name):
        t = self.read_text(full)
        if name == "tasks.json":
            if re.search(r'"runOn"\s*:\s*"folderOpen"', t):
                self.add_autorun(rel, "high", "a task runs as soon as the folder opens")
            else:
                self.add_autorun(rel, "medium", "tasks you might run from the editor")
        elif name == "settings.json":
            keys = sorted(set(VSCODE_RISKY_KEYS.findall(t)))
            if keys:
                self.add_autorun(rel, "medium", "changes how the editor runs programs: " + ", ".join(keys[:8]))
            else:
                self.add_autorun(rel, "info", "editor settings")
        elif name == "extensions.json":
            recs = re.findall(r'"([\w-]+\.[\w.-]+)"', t)
            self.add_autorun(rel, "info", "asks you to install extensions: " + ", ".join(recs[:12]))
        elif name.endswith("mcp.json"):
            self.add_autorun(rel, "medium" if re.search(r'"command"\s*:', t) else "info", "starts MCP servers (programs) for AI agents")
        elif name == "launch.json":
            self.add_autorun(rel, "info", "debug launch settings")
        else:
            self.add_autorun(rel, "info", "editor files")

    def on_npmrc(self, full, rel):
        t = self.read_text(full)
        self.npmrc.append({"file": rel, "content": mask_tokens(t)[:3000]})
        issues = []
        sev = "info"
        if re.search(r"_authToken|_auth\s*=|_password\s*=", t):
            issues.append("contains an npm login token; projects rarely need to ship one")
            sev = "medium"
        for m in re.finditer(r"^\s*(@[\w.-]+:)?registry\s*=\s*(\S+)", t, re.M):
            if "registry.npmjs.org" not in m.group(2):
                issues.append(f"uses another registry: {(m.group(1) or '')}{m.group(2)}")
                sev = "medium"
        if re.search(r"^\s*script-shell\s*=", t, re.M):
            issues.append("script-shell changes which program runs every npm script")
            sev = "high"
        if re.search(r"^\s*node-options\s*=", t, re.M):
            issues.append("node-options changes how node runs scripts")
            sev = "high" if sev == "high" else "medium"
        if re.search(r"^\s*(globalconfig|userconfig|prefix|cache|init-module)\s*=", t, re.M):
            issues.append("moves npm config or cache folders")
            sev = "high" if sev == "high" else "medium"
        self.add_autorun(rel, sev, "; ".join(issues) or "npm settings")

    def on_package_json(self, full, rel, in_nm):
        try:
            pj = json.loads(self.read_text(full, 5_000_000))
        except ValueError:
            if not in_nm:
                self.add("medium", "package-json", rel, "package.json is not valid JSON")
            return
        if not isinstance(pj, dict):
            return
        sc = pj.get("scripts")
        sc = {str(k): str(v) for k, v in sc.items()} if isinstance(sc, dict) else {}
        life = {k: v for k, v in sc.items() if k in LIFECYCLE}
        if in_nm:
            self.stats["packages in node_modules"] += 1
            if life:
                self.scripts.append({"file": rel, "scripts": life, "in_node_modules": True})
            return
        self.scripts.append({"file": rel, "scripts": sc, "in_node_modules": False})
        for k, v in life.items():
            self.add("medium", "install-script", rel, f"{k} script runs on install: {v[:200]}")
        tools = [k for k in PKG_TOOL_KEYS if k in pj]
        if tools:
            self.add_autorun(rel, "info", "package.json configures tools that load plugins: " + ", ".join(tools))
        if isinstance(pj.get("bin"), (str, dict)):
            self.add("info", "package-json", rel, "declares command-line programs (bin)")

    def result(self):
        order = {s: i for i, s in enumerate(SEVERITIES)}
        findings = sorted(self.findings, key=lambda f: (order[f["severity"]], f["in_node_modules"], f["kind"], f["file"], f["line"]))
        autorun = sorted(self.autorun, key=lambda a: (order[a["severity"]], a["file"]))
        counts = Counter(f["severity"] for f in findings) + Counter(a["severity"] for a in autorun)
        return {
            "root": str(self.root), "stats": dict(self.stats), "counts": {s: counts.get(s, 0) for s in SEVERITIES},
            "autorun": autorun, "findings": findings, "scripts": self.scripts, "npmrc": self.npmrc,
            "agent_files": self.agent_files,
        }


def scan(root):
    s = Scan(root)
    if not s.root.is_dir():
        raise NotADirectoryError(str(root))
    s.walk()
    return s.result()
