import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

SEVERITIES = ("high", "medium", "info")
KNOWN_HASHES = {
    "5c0d263e6decfa6d4db3da32eec9ec3f5c83b717d55390f49110cb8d04f55fd6": "tw-motion-css backdoor (runtime.js)",
    "cddec7017154aebf01b317099add0b2d0adc2d1a964f601816f03782db00a743": "@codentra/postcss-kinetix loader (config.js)",
}
KNOWN_STRINGS = (
    "DEERGS42", "216.126.231.70", "153.75.88.215", "tw-motion-css", "postcss-kinetix", "@codentra/", "carybernal",
    "gvfs-network-boot", "gvfs-network-activate",
)
CONFIG_RE = re.compile(
    r"^(tailwind|postcss|vite|vitest|next|nuxt|astro|svelte|webpack|rollup|babel|jest|eslint|prettier|tsup|esbuild"
    r"|remix|gatsby|metro|playwright|cypress|stylelint|commitlint|lint-staged|electron-builder|electron\.vite|quasar"
    r"|vue|angular|unocss|uno|panda|drizzle|knip|turbo|wrangler|react-router|rspack|rsbuild|farm|storybook|histoire"
    r"|vuepress|docusaurus|tsdown|rolldown|unbuild|webpack\.dev|webpack\.prod|craco|karma|mocha|ava|c8|nyc"
    r"|graphql|codegen|orval|kubb|sanity|payload|keystatic|contentlayer|velite|i18next-parser|svgo|size-limit)"
    r"\.config\.(js|cjs|mjs|ts|cts|mts|json|jsx|tsx)$"
)
RC_JS_RE = re.compile(r"^\.(babelrc|eslintrc|prettierrc|stylelintrc|lintstagedrc|mocharc|postcssrc|swcrc|ncurc|releaserc)\.(js|cjs|mjs|ts)$")
OTHER_AUTORUN = {
    "gulpfile.js": "runs when gulp starts", "Gruntfile.js": "runs when grunt starts", "Makefile": "runs on make",
    "Dockerfile": "runs on docker build", "docker-compose.yml": "runs on docker compose",
    "docker-compose.yaml": "runs on docker compose", "compose.yml": "runs on docker compose",
    "compose.yaml": "runs on docker compose", "Procfile": "runs on deploy", "justfile": "runs on just",
    "build.rs": "runs on cargo build", "nodemon.json": "configures nodemon", "deno.json": "configures deno tasks",
    "tsconfig.json": "editors load TypeScript plugins listed here", "jsconfig.json": "editors load plugins listed here",
}
PY_AUTORUN = {"setup.py": "medium", "conftest.py": "medium", "sitecustomize.py": "high", "usercustomize.py": "high", "noxfile.py": "info", "tasks.py": "info"}
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish", "prepack", "postpack", "dependencies")
PKG_TOOL_KEYS = ("eslintConfig", "prettier", "babel", "jest", "stylelint", "postcss", "lint-staged", "husky", "simple-git-hooks", "ava", "mocha", "nyc", "c8", "xo")
VSCODE_RISKY_KEYS = re.compile(
    r'"(terminal\.integrated\.(?:shell|profiles|env|automationProfile|defaultProfile)[^"]*|typescript\.tsdk|'
    r'js/ts\.tsdk|eslint\.runtime|eslint\.nodePath|eslint\.execArgv|prettier\.prettierPath|npm\.packageManager|'
    r'npm\.scriptRunner|python\.defaultInterpreterPath|python\.pythonPath|git\.path|[\w.]*executablePath|'
    r'[\w.]*\.serverPath|[\w.]*\.binPath|[\w.]*\.command|task\.allowAutomaticTasks|security\.workspace\.trust[^"]*)"\s*:'
)

STRONG = (
    ("known-malware", re.compile("|".join(re.escape(s) for s in KNOWN_STRINGS)), "high", "high"),
    ("obfuscated-code", re.compile(r"\b_0x[0-9a-f]{4,6}\b"), "high", "medium"),
    ("exfil-endpoint", re.compile(r"api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks|pastebin\.com/raw|hastebin|transfer\.sh|webhook\.site|requestbin|pipedream\.net|ngrok-free\.app|\.ngrok\.io|interact\.sh|\boast\.(?:fun|live|me|site|online|pro)|burpcollaborator|canarytokens|ipinfo\.io|ip-api\.com|ifconfig\.me|icanhazip|api\.ipify\.org"), "high", "medium"),
    ("wallet-extension-id", re.compile(r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|ibnejdfjmmkpcnlpebklmnkoeoihofec|fhbohimaelbohpjbbldcngcnapndodjp|aholpfdialjgjfhomihkjbmgjidlcdno|ejbalbakoplchlghecdalmeeeajnimhm|egjidjbpglichdcondbcbdnbeeppgdph|dmkamcknogkgcdfhhbddcghachkejeap|aeachknmefphepccionboohckonoeemg"), "high", "high"),
    ("browser-secrets", re.compile(r"Login Data|Local State|Local Extension Settings|Web Data|/Cookies\b|\\\\Cookies\b|BraveSoftware|google-chrome|Opera Software|\.mozilla/firefox|key4\.db|logins\.json|Chrome/User Data"), "high", "medium"),
    ("app-secrets", re.compile(r"\.ssh/id_|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|\.config/solana|Exodus|Electrum|\.gnupg|\.docker/config\.json|\.kube/config|\.config/gh/hosts|\.git-credentials|Keychains|login\.keychain|\.netrc\b"), "high", "info"),
    ("download-and-run", re.compile(r"curl[^\n]{0,120}\|\s*(?:ba|z)?sh|wget[^\n]{0,120}\|\s*(?:ba|z)?sh|Invoke-WebRequest|Invoke-Expression|\bIEX\s*\(|powershell(?:\.exe)?\s+-(?:e|enc|encodedcommand|nop|w|windowstyle|ExecutionPolicy)\b|DownloadString|certutil(?:\.exe)?\s+-urlcache|\bmshta\b|bitsadmin|/dev/tcp/"), "high", "medium"),
    ("starts-at-login", re.compile(r"systemctl\s+--user|\.config/autostart|\.config/systemd/user|crontab\s+-|\bLaunchAgents\b|\bLaunchDaemons\b|CurrentVersion\\\\Run|\bschtasks\b|Start Menu\\\\Programs\\\\Startup|reg(?:\.exe)?\s+add\s+HKCU"), "high", "medium"),
    ("bidi-control", re.compile("[‪-‮⁦-⁩]"), "high", "high"),
    ("invisible-code", re.compile("(?:[​-‏⁠-⁤︀-️\U000e0000-\U000e007f\U000e0100-\U000e01ef]){8,}"), "high", "high"),
    ("hidden-after-spaces", re.compile(r"\S[ \t]{150,}\S"), "medium", "info"),
    ("dumps-env", re.compile(r"JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:entries|keys)\(\s*process\.env\s*\)|os\.environ\.copy\(\)|dict\(os\.environ\)"), "medium", "info"),
    ("public-ip", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?(?![\w.])"), "medium", "info"),
)
SOURCE_ONLY = (
    ("eval", re.compile(r"(?<![\w.$])eval\s*\("), "medium"),
    ("new-function", re.compile(r"new\s+Function\s*\("), "medium"),
    ("shell-commands", re.compile(r"child_process|\bexecSync\b|\bspawnSync\b|\bexecFile(?:Sync)?\b|\bspawn\s*\(|\bsubprocess\.|\bos\.system\("), "medium"),
    ("decodes-base64", re.compile(r"\batob\s*\(|Buffer\.from\([^)]{0,200}['\"](?:base64|hex)['\"]|b64decode|String\.fromCharCode\s*\(|\.charCodeAt\([^)]*\)\s*\^"), "info"),
    ("base64-blob", re.compile(r"[A-Za-z0-9+/]{400,}={0,2}"), "medium"),
    ("hex-blob", re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}|(?:0x[0-9a-fA-F]{2},\s*){60,}"), "medium"),
    ("home-folder", re.compile(r"os\.homedir\(\)|\bhomedir\(\)|process\.env\.(?:HOME|USERPROFILE|APPDATA|LOCALAPPDATA)\b|expanduser\("), "info"),
    ("network-call", re.compile(r"\bfetch\s*\(|\baxios\b|https?\.(?:get|request)\s*\(|new\s+WebSocket|net\.(?:connect|createConnection|Socket)|dgram\.|XMLHttpRequest|require\(['\"](?:node:)?(?:http|https|net|dgram|tls)['\"]\)|\brequests\.(?:get|post)\(|urllib\.request|socket\.socket\("), "info"),
    ("dynamic-load", re.compile(r"require\(\s*(?![\'\"`)\s])[^)]{1,80}\)|import\(\s*(?![\'\"`)\s])[^)]{1,80}\)|__import__\(|importlib\.import_module\("), "info"),
    ("self-hiding", re.compile(r"unlinkSync\(\s*__filename|fs\.rm(?:Sync)?\(\s*__dirname|detached\s*:\s*true|\.unref\(\)\s*;?\s*$|windowsHide\s*:\s*true"), "medium"),
)
IMPORT_RE = re.compile(r"""(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|^\s*import\s+)['"]([^'"\s]+)['"]""", re.M)
TEXT_EXT = {
    ".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx", ".json", ".jsonc", ".json5", ".sh", ".bash", ".zsh",
    ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".py", ".pth", ".rb", ".php", ".pl", ".yml", ".yaml", ".toml", ".ini",
    ".cfg", ".html", ".htm", ".vue", ".svelte", ".astro", ".css", ".scss", ".sass", ".less", ".env", ".lua", ".go", ".rs",
    ".java", ".kt", ".swift", ".c", ".h", ".cpp", ".cs", ".sql", ".graphql", ".gql", ".xml", ".svg", ".md", ".mdx", ".txt",
}
CODE_EXT = TEXT_EXT - {".md", ".mdx", ".txt", ".svg", ".xml", ".css", ".scss", ".sass", ".less"}
WIN_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".msi", ".msp", ".reg", ".com", ".pif", ".cpl", ".jar"}
PREBUILT_OK = re.compile(
    r"node_modules/(?:\.pnpm/[^/]+/node_modules/)?(?:@esbuild|esbuild|@next/swc|@swc|lightningcss|@rollup|@img|sharp|turbo|"
    r"@biomejs|@oxc|oxc|@tailwindcss/oxide|@parcel/watcher|fsevents|@unrs|unrs|@napi-rs|@rspack|@rolldown|rolldown|"
    r"@ast-grep|bufferutil|utf-8-validate|canvas|better-sqlite3|bcrypt|argon2|@prisma|prisma|@node-rs|node-gyp|"
    r"playwright-core|puppeteer|@playwright|electron|7zip-bin|@ngrok|cypress|workerd|@cloudflare|@oven|bun|lefthook|"
    r"@lefthook|@sentry/cli|@sentry|@vercel/nft|@ffmpeg-installer|ffmpeg-static|@esbuild-kit|@dprint|dprint|"
    r"@lancedb|onnxruntime-node|@tensorflow|re2|@mapbox/node-pre-gyp|deasync|nodejieba|@resvg|@sveltejs|@vscode|"
    r"@ampproject|@lmdb|lmdb|msgpackr-extract|@msgpackr-extract|cpu-features|ssh2|@serialport|serialport|usb|"
    r"keytar|node-pty|@homebridge|sqlite3|@libsql|libsql|@duckdb|duckdb|@tauri-apps|@astrojs/compiler|svelte|"
    r"@typescript/native-preview|typescript-go|@rolldown/binding|@oxlint|oxlint|nodemon|@esbuild/[\w-]+|@swc/core-[\w-]+)"
)
PACKED_DIRS = ("/dist/", "/build/", "/umd/", "/cjs/", "/esm/", "/lib/", "/bundle/", "/min/", "/vendor/", "/public/", "/static/", "/out/", "/.next/")
MAX_FILE = 15_000_000
CAP_PER_FILE = 3
CAP_PROJECT = 80
CAP_NM = 40


def magic(path):
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return None
    if head == b"\x7fELF":
        return "Linux program (ELF)"
    if head[:2] == b"MZ":
        return "Windows program (PE)"
    if head in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"):
        return "Mac program (Mach-O)"
    if head == b"\x00asm":
        return "WebAssembly module"
    return None


def snippet(line, m):
    s = max(0, m.start() - 60)
    e = min(len(line), m.end() + 60)
    t = line[s:e].replace("\t", " ")
    t = "".join(ch if ch.isprintable() else f"\\u{ord(ch):04x}" for ch in t)
    return ("..." if s else "") + t + ("..." if e < len(line) else "")


def code_like(line):
    if re.search(r"_0x[0-9a-f]{4}|\beval\s*\(|new Function|\\x[0-9a-f]{2}\\x|atob\(|fromCharCode|require\(|import\(", line):
        return True
    marks = line.count(";") + line.count("{") + line.count("=>") + line.count("function")
    return marks * 120 > len(line)


def public_ip(token):
    ip = token.split(":")[0]
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_loopback or a.is_private or a.is_unspecified or a.is_multicast or a.is_reserved or a.is_link_local:
        return False
    parts = [int(x) for x in ip.split(".")]
    return not (parts[0] == 0 or all(p < 10 for p in parts) or parts == [255, 255, 255, 255])


def mask_tokens(s):
    return re.sub(r"(_authToken\s*=\s*|_auth\s*=\s*|_password\s*=\s*|npmAuthToken:\s*|//[^\s:]+:_authToken=)(\S{4})\S+", r"\1\2****", s)


def package_of(spec):
    if spec.startswith((".", "/", "node:", "#", "~", "@/", "virtual:", "data:", "http:", "https:", "bun:")):
        return None
    if spec.startswith("@"):
        parts = spec.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    return spec.split("/")[0] or None


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
            issues.append("contains an npm login token (a client project should not need one)")
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


def render(r):
    out = [f"# Static scan of {r['root']}"]
    st = r["stats"]
    out.append(
        f"files: {st.get('project files', 0)} in the project, {st.get('node_modules files', 0)} in node_modules "
        f"({st.get('packages in node_modules', 0)} packages)"
    )
    out.append("findings: " + ", ".join(f"{r['counts'][s]} {s}" for s in SEVERITIES))
    out.append("")
    out.append("## Files that can run code without you starting them")
    if not r["autorun"]:
        out.append("  none")
    for a in r["autorun"]:
        loads = f" | loads: {', '.join(a['loads'])}" if a["loads"] else ""
        out.append(f"  [{a['severity']}] {a['file']}: {a['why']}{loads}")
    if r["npmrc"]:
        out.append("")
        out.append("## Package manager settings (tokens masked)")
        for n in r["npmrc"]:
            out.append(f"  --- {n['file']}")
            out.extend(f"      {line}" for line in n["content"].splitlines()[:25])
    out.append("")
    out.append("## Project scripts")
    proj = [s for s in r["scripts"] if not s["in_node_modules"]]
    if not proj:
        out.append("  none")
    for s in proj:
        out.append(f"  --- {s['file']}")
        for k, v in s["scripts"].items():
            mark = " (runs on install)" if k in LIFECYCLE else ""
            out.append(f"     {k}{mark}: {v[:200]}")
    nm = [s for s in r["scripts"] if s["in_node_modules"]]
    if nm:
        out.append(f"  install scripts inside node_modules: {len(nm)}")
        for s in nm[:40]:
            out.append(f"     {s['file']}: " + "; ".join(f"{k}={v[:120]}" for k, v in s["scripts"].items()))
    by = defaultdict(list)
    for f in r["findings"]:
        by[f["severity"]].append(f)
    for sev in SEVERITIES:
        if not by[sev]:
            continue
        out.append("")
        out.append(f"## {sev.upper()} ({len(by[sev])})")
        for f in by[sev]:
            where = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            nm_tag = " [node_modules]" if f["in_node_modules"] else ""
            snip = f"  {f['snippet']}" if f["snippet"] else ""
            what = f["what"] if not f["snippet"] else f["kind"]
            out.append(f"  - {where}{nm_tag}: {what}{snip}")
    out.append("")
    out.append("Read every file under 'Files that can run code' before running anything.")
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(prog="scan.py", description="Static scan of a project. Runs nothing.")
    p.add_argument("project", help="project folder")
    p.add_argument("--json", action="store_true", help="print JSON")
    a = p.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    try:
        r = scan(a.project)
    except NotADirectoryError:
        print(f"scan.py: not a folder: {a.project}", file=sys.stderr)
        return 2
    print(json.dumps(r, indent=2) if a.json else render(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
