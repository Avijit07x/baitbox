import argparse
import concurrent.futures
import datetime
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

VERSION = "0.1.0"
UA = f"baitbox/{VERSION} (+https://github.com/Avijit07x/baitbox)"
REGISTRY = "https://registry.npmjs.org"
DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
SEVERITIES = ("high", "medium", "info")
NEW_DAYS = 120
RECENT_VERSION_DAYS = 7
LOW_DOWNLOADS = 1000
POPULAR_DOWNLOADS = 50000
MAX_DOC_BYTES = 32 * 1024 * 1024
MAX_VERSIONS_PER_PACKAGE = 3
NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-zA-Z0-9_][a-zA-Z0-9._~-]*$")
SKIP_DIRS = {".git", ".hg", ".svn"}
POPULAR = (
    "react", "react-dom", "next", "vue", "nuxt", "vite", "tailwindcss", "postcss", "autoprefixer", "axios", "lodash",
    "express", "typescript", "eslint", "prettier", "webpack", "moment", "dayjs", "chalk", "commander", "dotenv", "zod",
    "jsonwebtoken", "bcrypt", "bcryptjs", "mongoose", "prisma", "nodemon", "jest", "vitest", "framer-motion", "motion",
    "clsx", "uuid", "socket.io", "cors", "body-parser", "sharp", "styled-components", "redux", "react-router-dom",
    "react-router", "tailwind-merge", "lucide-react", "date-fns", "classnames", "react-icons", "swr", "zustand",
    "recharts", "three", "gsap", "nanoid", "cookie-parser", "multer", "nodemailer", "stripe", "openai", "firebase",
    "sass", "less", "esbuild", "rollup", "daisyui", "react-hook-form", "yup", "formik", "i18next", "graphql", "pg",
    "mysql2", "redis", "ioredis", "debug", "colors", "request", "node-fetch", "cross-env", "concurrently", "rimraf",
    "glob", "minimist", "yargs", "inquirer", "ws", "helmet", "morgan", "passport", "sequelize", "typeorm", "knex",
    "puppeteer", "playwright", "cheerio", "marked", "highlight.js", "chart.js", "antd", "electron", "ethers", "web3",
)


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def parse_time(s):
    try:
        return datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


class Http:
    def __init__(self, timeout=25, retries=3):
        self.timeout = timeout
        self.retries = retries

    def _do(self, req, max_bytes):
        last = (0, None)
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    chunks = []
                    total = 0
                    while True:
                        chunk = r.read(1 << 16)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_bytes:
                            return 413, None
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    try:
                        return r.status, json.loads(body.decode("utf-8", errors="replace"))
                    except ValueError:
                        return r.status, None
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and attempt + 1 < self.retries:
                    wait = min(20.0, float(e.headers.get("Retry-After") or 2 ** attempt))
                    time.sleep(wait)
                    last = (e.code, None)
                    continue
                return e.code, None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = (0, str(e))
                if attempt + 1 < self.retries:
                    time.sleep(2 ** attempt)
        return last

    def get(self, url, max_bytes=MAX_DOC_BYTES):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        return self._do(req, max_bytes)

    def post(self, url, body, max_bytes=MAX_DOC_BYTES):
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST", headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"})
        return self._do(req, max_bytes)


def valid_name(name):
    return isinstance(name, str) and 0 < len(name) <= 214 and bool(NAME_RE.match(name)) and ".." not in name


def split_name_version(s):
    s = s.strip().strip("'\"")
    i = s.rfind("@")
    if i <= 0:
        return s, ""
    return s[:i], s[i + 1:]


def split_first(s):
    s = s.strip().strip("'\"")
    i = s.find("@", 1)
    if i <= 0:
        return s, ""
    return s[:i], s[i + 1:]


def classify_spec(spec):
    s = str(spec).strip()
    if s.startswith("npm:"):
        real, rng = split_name_version(s[4:])
        return "alias", real, rng
    if s.startswith("workspace:"):
        return "workspace", None, s
    if s.startswith(("link:", "portal:")):
        return "link", None, s.split(":", 1)[1]
    if s.startswith("file:") or s.startswith(("./", "../", "/", "~/")):
        return "file", None, s[5:] if s.startswith("file:") else s
    if s.startswith("exec:"):
        return "exec", None, s
    if s.startswith(("git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "gist:")):
        return "git", None, s
    if s.startswith(("http://", "https://")):
        return "url", None, s
    if s.startswith("patch:"):
        inner = urllib.parse.unquote(s[6:].split("#")[0])
        real, rng = split_name_version(inner)
        return "registry", real, rng
    if re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", s) and not s.startswith("@"):
        return "git", None, s
    return "registry", None, s


class Collector:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.packages = {}
        self.direct = {}
        self.local = set()
        self.sources = []
        self.invalid = []
        self.mismatch = []
        self.lockfiles = []
        self.nm_names = set()
        self.nm_top_names = set()
        self.lock_names = set()
        self.registries = {}
        self.aliases = set()
        self.notes = []

    def add(self, name, version, origin):
        if not valid_name(name):
            self.invalid.append({"name": str(name)[:200], "origin": origin})
            return
        entry = self.packages.setdefault(name, set())
        if version and re.match(r"^[0-9][\w.+-]*$", version):
            entry.add(version)

    def source(self, name, kind, value, origin, severity="medium"):
        self.sources.append({"name": name, "kind": kind, "source": str(value)[:300], "origin": origin, "severity": severity})

    def rel(self, p):
        return os.path.relpath(p, self.root)

    def walk(self):
        for dp, dns, fns in os.walk(self.root, followlinks=False, onerror=lambda e: None):
            dns[:] = sorted(d for d in dns if d not in SKIP_DIRS)
            parts = Path(self.rel(dp)).parts
            if "node_modules" in parts:
                self.on_node_modules_dir(dp, dns)
                continue
            for f in sorted(fns):
                full = os.path.join(dp, f)
                if os.path.islink(full):
                    continue
                if f == "package.json":
                    self.on_manifest(full)
                elif f in ("package-lock.json", "npm-shrinkwrap.json"):
                    self.lockfiles.append(self.rel(full))
                    self.on_npm_lock(full)
                elif f == "pnpm-lock.yaml":
                    self.lockfiles.append(self.rel(full))
                    self.on_pnpm_lock(full)
                elif f == "yarn.lock":
                    self.lockfiles.append(self.rel(full))
                    self.on_yarn_lock(full)
                elif f == "bun.lock":
                    self.lockfiles.append(self.rel(full))
                    self.on_bun_lock(full)
                elif f == "bun.lockb":
                    self.lockfiles.append(self.rel(full))
                    self.notes.append(f"{self.rel(full)} is a binary Bun lockfile and was not read")
                elif f == ".npmrc":
                    self.on_npmrc(full)

    def read(self, full, limit=64 * 1024 * 1024):
        try:
            with open(full, "rb") as f:
                return f.read(limit).decode("utf-8", errors="replace")
        except OSError:
            return ""

    def on_npmrc(self, full):
        for m in re.finditer(r"^\s*(@[\w.-]+:)?registry\s*=\s*(\S+)", self.read(full, 1_000_000), re.M):
            scope = (m.group(1) or "").rstrip(":")
            self.registries[scope] = m.group(2)

    def on_manifest(self, full):
        try:
            pj = json.loads(self.read(full, 5_000_000))
        except ValueError:
            return
        if not isinstance(pj, dict):
            return
        origin = self.rel(full)
        if isinstance(pj.get("name"), str):
            self.local.add(pj["name"])
        for sec in ("overrides", "resolutions", "pnpm"):
            pins = pj.get(sec)
            if sec == "pnpm":
                pins = pins.get("overrides") if isinstance(pins, dict) else None
            stack = [pins] if isinstance(pins, dict) else []
            while stack:
                cur = stack.pop()
                for key, spec in cur.items():
                    if isinstance(spec, dict):
                        stack.append(spec)
                        continue
                    if not isinstance(spec, str):
                        continue
                    kind, _, _ = classify_spec(spec)
                    if kind in ("git", "url", "exec"):
                        self.source(str(key)[:120], kind, spec, origin, "high" if kind == "exec" else "medium")
        for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = pj.get(sec)
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                if not isinstance(spec, str):
                    continue
                kind, real, rng = classify_spec(spec)
                rec = self.direct.setdefault(name, [])
                rec.append({"spec": spec[:200], "section": sec, "file": origin})
                if kind == "alias":
                    self.add(real, None, origin)
                    self.aliases.add(name)
                    self.source(name, "alias", f"{name} is really {real}", origin, "info")
                elif kind == "registry":
                    self.add(real or name, None, origin)
                elif kind == "workspace":
                    self.local.add(name)
                elif kind in ("file", "link"):
                    self.local.add(name)
                    target = (Path(full).parent / rng).resolve() if not rng.startswith("~") else None
                    if target is None or not (target == self.root or self.root in target.parents):
                        self.source(name, kind, f"{spec} points outside the project", origin, "medium")
                elif kind == "exec":
                    self.source(name, kind, spec, origin, "high")
                else:
                    self.source(name, kind, spec, origin, "medium")

    def on_npm_lock(self, full):
        origin = self.rel(full)
        try:
            data = json.loads(self.read(full))
        except ValueError:
            self.notes.append(f"{origin} is not valid JSON")
            return
        if not isinstance(data, dict):
            return
        pk = data.get("packages")
        if isinstance(pk, dict) and pk:
            for key, meta in pk.items():
                if not key or not isinstance(meta, dict):
                    continue
                if "node_modules/" not in key:
                    if isinstance(meta.get("name"), str):
                        self.local.add(meta["name"])
                    continue
                folder = key.rsplit("node_modules/", 1)[1]
                name = meta.get("name") if isinstance(meta.get("name"), str) else folder
                if name != folder:
                    self.aliases.add(folder)
                if meta.get("link"):
                    self.local.add(name)
                    continue
                self.lock_entry(name, meta.get("version"), meta.get("resolved"), origin)
            return
        stack = [data.get("dependencies") or {}]
        while stack:
            deps = stack.pop()
            if not isinstance(deps, dict):
                continue
            for name, meta in deps.items():
                if not isinstance(meta, dict):
                    continue
                self.lock_entry(name, meta.get("version"), meta.get("resolved"), origin)
                stack.append(meta.get("dependencies") or {})

    def lock_entry(self, name, version, resolved, origin):
        self.lock_names.add(name)
        version = version if isinstance(version, str) else ""
        resolved = resolved if isinstance(resolved, str) else ""
        if version.startswith("npm:"):
            real, ver = split_name_version(version[4:])
            self.add(real, ver, origin)
            return
        if ":" in version or "/" in version:
            kind, _, _ = classify_spec(version)
            if kind in ("file", "link", "workspace"):
                self.local.add(name)
                return
            self.source(name, kind, version, origin, "high" if kind == "exec" else "medium")
            return
        self.add(name, version, origin)
        if resolved and not resolved.startswith(("https://registry.npmjs.org/", "https://registry.yarnpkg.com/")):
            kind, _, _ = classify_spec(resolved)
            if kind not in ("file", "link", "workspace"):
                self.source(name, "lockfile", resolved, origin, "medium")

    def on_pnpm_lock(self, full):
        origin = self.rel(full)
        section = None
        current = None
        for line in self.read(full).splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if not line.startswith(" "):
                section = line.rstrip(":").strip()
                current = None
                continue
            if section not in ("packages", "snapshots"):
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent == 2 and line.rstrip().endswith(":"):
                key = line.strip()[:-1].strip("'\"")
                key = re.sub(r"\(.*$", "", key)
                if key.startswith("/"):
                    key = key[1:]
                m = re.match(r"^((?:@[^/]+/)?[^/@]+)/(\d[^/_]*)(?:_.*)?$", key)
                if m:
                    name, version = m.group(1), m.group(2)
                else:
                    name, version = split_first(key)
                    version = re.sub(r"_.*$", "", version)
                current = name
                if ":" in version or "/" in version:
                    kind, _, _ = classify_spec(version)
                    if kind in ("file", "link", "workspace"):
                        self.local.add(name)
                    else:
                        self.lock_names.add(name)
                        self.source(name, kind, version, origin, "high" if kind == "exec" else "medium")
                    continue
                self.lock_names.add(name)
                self.add(name, version, origin)
                continue
            if current and section == "packages":
                t = re.search(r"tarball:\s*['\"]?([^,'\"}\s]+)", line)
                if t and "registry.npmjs.org" not in t.group(1):
                    self.source(current, "lockfile", t.group(1), origin)
                r = re.search(r"repo:\s*['\"]?([^,'\"}\s]+)", line)
                if r:
                    self.source(current, "git", r.group(1), origin)

    def on_yarn_lock(self, full):
        origin = self.rel(full)
        names = []
        for line in self.read(full).splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            if not line.startswith(" ") and line.rstrip().endswith(":"):
                names = []
                header = line.rstrip()[:-1]
                if header.strip("\"") == "__metadata":
                    continue
                for spec in header.split(","):
                    spec = spec.strip().strip("\"")
                    name, rest = split_first(spec)
                    if not name or "@" not in spec[1:]:
                        continue
                    if rest.startswith("npm:") and "@" in rest[5:]:
                        real, _ = split_name_version(rest[4:])
                        self.aliases.add(name)
                        name = real
                        rest = "npm:"
                    if rest.startswith(("workspace:", "file:", "link:", "portal:")):
                        self.local.add(name)
                        continue
                    if rest.startswith("exec:"):
                        self.source(name, "exec", rest, origin, "high")
                        continue
                    if rest.startswith(("git", "http", "github:", "gitlab:", "bitbucket:")) or re.match(r"^[\w.-]+/[\w.-]+", rest):
                        self.lock_names.add(name)
                        self.source(name, "git" if not rest.startswith("http") else "url", rest, origin)
                        continue
                    names.append(name)
                    self.lock_names.add(name)
                continue
            m = re.match(r'^ {2}version:?\s+"?([^"\s]+)"?', line)
            if m and names:
                for n in dict.fromkeys(names):
                    self.add(n, m.group(1), origin)
                continue
            m = re.match(r'^ {2}resolved:?\s+"?([^"\s]+)"?', line)
            if m and names and not m.group(1).startswith(("https://registry.yarnpkg.com/", "https://registry.npmjs.org/")):
                for n in dict.fromkeys(names):
                    self.source(n, "lockfile", m.group(1), origin)

    def on_bun_lock(self, full):
        origin = self.rel(full)
        inside = False
        for line in self.read(full).splitlines():
            if re.match(r'^\s*"packages"\s*:\s*\{', line):
                inside = True
                continue
            if not inside:
                continue
            m = re.match(r'^\s*"([^"]+)"\s*:\s*\[\s*"([^"]+)"', line)
            if not m:
                continue
            name, version = split_first(m.group(2))
            if m.group(1).split("/")[-1] != name.split("/")[-1]:
                self.aliases.add(m.group(1).split("/")[-1])
            if version.startswith("npm:"):
                name, version = split_name_version(version[4:])
            if ":" in version or "/" in version:
                kind, _, _ = classify_spec(version)
                if kind in ("file", "link", "workspace"):
                    self.local.add(name)
                else:
                    self.lock_names.add(name)
                    self.source(name, kind, version, origin, "high" if kind == "exec" else "medium")
                continue
            self.lock_names.add(name)
            self.add(name, version, origin)

    def on_node_modules_dir(self, nm_dir, _dns):
        if os.path.basename(nm_dir) != "node_modules":
            return
        try:
            entries = sorted(os.scandir(nm_dir), key=lambda e: e.name)
        except OSError:
            return
        for e in entries:
            if e.name.startswith(".") or e.is_symlink() or not e.is_dir(follow_symlinks=False):
                continue
            if e.name.startswith("@"):
                try:
                    subs = sorted(os.scandir(e.path), key=lambda x: x.name)
                except OSError:
                    continue
                for s in subs:
                    if not s.is_symlink() and s.is_dir(follow_symlinks=False):
                        self.on_installed(s.path, f"{e.name}/{s.name}")
            else:
                self.on_installed(e.path, e.name)

    def on_installed(self, pkg_dir, dir_name):
        pj_path = os.path.join(pkg_dir, "package.json")
        if not os.path.isfile(pj_path) or os.path.islink(pj_path):
            return
        try:
            pj = json.loads(self.read(pj_path, 2_000_000))
        except ValueError:
            return
        if not isinstance(pj, dict):
            return
        name = pj.get("name") if isinstance(pj.get("name"), str) else dir_name
        version = pj.get("version") if isinstance(pj.get("version"), str) else ""
        if name != dir_name and dir_name not in self.direct and dir_name not in self.aliases:
            self.mismatch.append({"folder": self.rel(pkg_dir), "name": name})
        self.nm_names.add(name)
        if "/.pnpm/" not in pkg_dir.replace(os.sep, "/"):
            self.nm_top_names.add(name)
        self.add(name, version, "node_modules")


def registry_for(name, registries):
    if name.startswith("@"):
        scope = name.split("/")[0]
        if scope in registries:
            return registries[scope]
    return registries.get("")


def lev(a, b):
    if abs(len(a) - len(b)) > 2:
        return 9
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def plural(n, word):
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def flag(r, code, severity, text):
    r["flags"].append({"code": code, "severity": severity, "text": text})


def check_package(http, name, versions, custom_registry):
    enc = urllib.parse.quote(name, safe="@").replace("/", "%2F")
    r = {"name": name, "versions": sorted(versions), "flags": [], "weekly": None}
    st, dl = http.get(f"{DOWNLOADS}/{name}", 1_000_000)
    if st == 200 and isinstance(dl, dict) and isinstance(dl.get("downloads"), int):
        r["weekly"] = dl["downloads"]
    popular = (r["weekly"] or 0) >= POPULAR_DOWNLOADS
    doc = None
    if not popular:
        st, doc = http.get(f"{REGISTRY}/{enc}")
        if st == 404:
            if custom_registry:
                flag(r, "PRIVATE_REGISTRY", "medium", f"not on npm; the project points to {custom_registry}, which can't be checked")
            else:
                flag(r, "NOT_ON_NPM", "high", "not on npm (private, removed or fake)")
            return r
        if st == 413:
            doc = None
        elif st != 200 or not isinstance(doc, dict):
            flag(r, "LOOKUP_FAILED", "info", f"registry lookup failed ({st or doc})")
            doc = None
    if doc:
        t = doc.get("time") if isinstance(doc.get("time"), dict) else {}
        vers = doc.get("versions") if isinstance(doc.get("versions"), dict) else {}
        tags = doc.get("dist-tags") if isinstance(doc.get("dist-tags"), dict) else {}
        latest = tags.get("latest", "")
        r["created"] = t.get("created")
        r["version_count"] = len(vers)
        r["maintainers"] = [str(m.get("email") or m.get("name")) for m in (doc.get("maintainers") or []) if isinstance(m, dict)][:5]
        if "unpublished" in t:
            flag(r, "UNPUBLISHED", "high", "every version was unpublished")
        if "security" in str(latest) or str(latest).endswith("-security"):
            flag(r, "REMOVED_BY_NPM_SECURITY", "high", f"npm replaced it with a security placeholder ({latest}); it was malware")
        created = parse_time(r.get("created"))
        age = (now() - created).days if created else None
        r["age_days"] = age
        new = age is not None and age < NEW_DAYS
        low = r["weekly"] is None or r["weekly"] < LOW_DOWNLOADS
        few = len(vers) <= 2
        if new and low and few:
            flag(r, "THROWAWAY", "high", f"{plural(age, 'day')} old, {plural(r['weekly'] or 0, 'download')} a week, {plural(len(vers), 'version')}")
        else:
            if new:
                flag(r, "NEW", "medium", f"{plural(age, 'day')} old")
            if low:
                flag(r, "LOW_DOWNLOADS", "info", f"{r['weekly'] or 0} downloads a week")
            if few:
                flag(r, "FEW_VERSIONS", "info", plural(len(vers), "version"))
        for v in r["versions"]:
            if vers and v not in vers:
                flag(r, "VERSION_NOT_ON_NPM", "high", f"version {v} is not on npm (removed, often for malware)")
            pt = parse_time(t.get(v))
            if pt and (now() - pt).days < RECENT_VERSION_DAYS and len(vers) > 2:
                flag(r, "RECENT_VERSION", "medium", f"version {v} was published {(now() - pt).days} days ago")
    targets = r["versions"][-MAX_VERSIONS_PER_PACKAGE:] or ["latest"]
    for v in targets:
        if doc and isinstance(doc.get("versions"), dict):
            man = doc["versions"].get(v if v != "latest" else (doc.get("dist-tags") or {}).get("latest", ""))
            st = 200 if man else 404
        else:
            st, man = http.get(f"{REGISTRY}/{enc}/{urllib.parse.quote(v, safe='')}", 4_000_000)
        if st == 404 and v != "latest" and not any(f["code"] == "VERSION_NOT_ON_NPM" for f in r["flags"]):
            if r["weekly"] is not None or doc:
                flag(r, "VERSION_NOT_ON_NPM", "high", f"version {v} is not on npm (removed, often for malware)")
            continue
        if st != 200 or not isinstance(man, dict):
            continue
        sc = man.get("scripts") if isinstance(man.get("scripts"), dict) else {}
        life = {k: str(val)[:160] for k, val in sc.items() if k in ("preinstall", "install", "postinstall")}
        if life and not any(f["code"] == "INSTALL_SCRIPT" for f in r["flags"]):
            flag(r, "INSTALL_SCRIPT", "info" if popular else "medium", "runs on install: " + json.dumps(life)[:240])
        if man.get("deprecated") and not any(f["code"] == "DEPRECATED" for f in r["flags"]):
            flag(r, "DEPRECATED", "info", str(man["deprecated"])[:160])
    return r


def osv_check(http, results):
    queries = []
    index = []
    for r in results:
        if r["versions"]:
            for v in r["versions"][-MAX_VERSIONS_PER_PACKAGE:]:
                queries.append({"package": {"ecosystem": "npm", "name": r["name"]}, "version": v})
                index.append((r, v))
        else:
            queries.append({"package": {"ecosystem": "npm", "name": r["name"]}})
            index.append((r, None))
    failed = 0
    for i in range(0, len(queries), 500):
        st, data = http.post(OSV_BATCH, {"queries": queries[i:i + 500]})
        if st != 200 or not isinstance(data, dict):
            failed += 1
            continue
        for (r, v), res in zip(index[i:i + 500], data.get("results") or [], strict=False):
            vulns = (res or {}).get("vulns") or []
            mal = sorted({x.get("id", "") for x in vulns if str(x.get("id", "")).startswith("MAL-")})
            other = sorted({x.get("id", "") for x in vulns if x.get("id") and not str(x.get("id")).startswith("MAL-")})
            if mal and not any(f["code"] == "KNOWN_MALWARE" for f in r["flags"]):
                flag(r, "KNOWN_MALWARE", "high", f"listed as malware in OSV: {', '.join(mal[:5])}" + (f" (version {v})" if v else ""))
            if other and v:
                r.setdefault("vulnerabilities", []).extend(other[:10])
    for r in results:
        if r.get("vulnerabilities"):
            ids = sorted(set(r["vulnerabilities"]))
            r["vulnerabilities"] = ids
            flag(r, "KNOWN_VULNERABILITY", "info", f"{len(ids)} known security bug(s): {', '.join(ids[:4])}")
    return failed


def severity_of(r):
    if not r["flags"]:
        return None
    return min((f["severity"] for f in r["flags"]), key=SEVERITIES.index)


def check(root, offline=False, workers=16, http=None):
    c = Collector(root)
    if not c.root.is_dir():
        raise NotADirectoryError(str(root))
    c.walk()
    names = sorted(n for n in c.packages if n not in c.local)
    results = []
    osv_failed = 0
    if not offline:
        http = http or Http()
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            futs = [ex.submit(check_package, http, n, c.packages[n], registry_for(n, c.registries)) for n in names]
            for f in futs:
                results.append(f.result())
        osv_failed = osv_check(http, results)
    else:
        results = [{"name": n, "versions": sorted(c.packages[n]), "flags": [], "weekly": None} for n in names]
    weekly = {r["name"]: r["weekly"] for r in results}
    lookalikes = []
    for r in results:
        n = r["name"]
        if (weekly.get(n) or 0) >= POPULAR_DOWNLOADS:
            continue
        base = n.split("/")[-1]
        for p in POPULAR:
            if n == p or base == p or len(p) <= 4 or n.startswith(("@types/", f"@{p}/")):
                continue
            if lev(base, p) <= (1 if len(p) <= 6 else 2) or base in (p + "js", p + "-js", p + ".js", "node-" + p, p + "-node") and n not in POPULAR:
                flag(r, "LOOKALIKE", "medium", f"name looks like the popular package {p}")
                lookalikes.append({"name": n, "looks_like": p})
                break
    for r in results:
        r["direct"] = r["name"] in c.direct
        r["severity"] = severity_of(r)
    extras = []
    if c.lock_names and c.nm_top_names:
        extras = sorted(n for n in c.nm_top_names - c.lock_names - c.local - c.aliases if n not in c.direct)[:100]
    findings = []
    for s in c.sources:
        findings.append({"severity": s["severity"], "kind": "non-registry-source", "what": f"{s['name']}: {s['kind']} {s['source']}", "file": s["origin"]})
    for i in c.invalid:
        findings.append({"severity": "high", "kind": "invalid-name", "what": f"invalid package name {i['name']!r}", "file": i["origin"]})
    for m in c.mismatch:
        findings.append({"severity": "medium", "kind": "name-mismatch", "what": f"folder {m['folder']} holds a package named {m['name']}", "file": m["folder"]})
    for n in extras:
        findings.append({"severity": "medium", "kind": "not-in-lockfile", "what": f"{n} is in node_modules but not in any lockfile", "file": "node_modules"})
    for r in results:
        for f in r["flags"]:
            findings.append({"severity": f["severity"], "kind": f["code"].lower().replace("_", "-"), "what": f"{r['name']}: {f['text']}", "file": "direct dependency" if r["direct"] else "nested dependency"})
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f["severity"]], f["kind"], f["what"]))
    counts = Counter(f["severity"] for f in findings)
    notes = list(c.notes)
    failed = sum(1 for r in results if any(f["code"] == "LOOKUP_FAILED" for f in r["flags"]))
    if failed:
        notes.append(f"{failed} registry lookups failed; run again before trusting the package list")
    if osv_failed:
        notes.append("the OSV malware database could not be reached; known-malware checks are incomplete")
    if offline:
        notes.append("offline mode: packages were listed but not checked against npm or OSV")
    if not c.lockfiles:
        notes.append("no lockfile found; nested packages are only known after an install")
    return {
        "root": str(c.root), "offline": offline, "lockfiles": c.lockfiles, "registries": c.registries,
        "direct_count": len(c.direct), "package_count": len(names), "local_packages": sorted(c.local),
        "counts": {s: counts.get(s, 0) for s in SEVERITIES}, "findings": findings,
        "packages": sorted(results, key=lambda r: (order.get(r["severity"] or "zz", 9), r["name"])),
        "lookalikes": lookalikes, "notes": notes,
    }


def render(r):
    out = [f"# Package check for {r['root']}"]
    out.append(f"direct dependencies: {r['direct_count']}, packages checked: {r['package_count']}, lockfiles: {', '.join(r['lockfiles']) or 'none'}")
    if r["registries"]:
        out.append("custom registries: " + ", ".join(f"{k or 'default'}={v}" for k, v in r["registries"].items()))
    out.append("findings: " + ", ".join(f"{r['counts'][s]} {s}" for s in SEVERITIES))
    for sev in SEVERITIES:
        items = [f for f in r["findings"] if f["severity"] == sev]
        if not items:
            continue
        out.append("")
        out.append(f"## {sev.upper()} ({len(items)})")
        for f in items[:150]:
            out.append(f"  - {f['what']} [{f['file']}]")
        if len(items) > 150:
            out.append(f"  ... and {len(items) - 150} more")
    risky = [p for p in r["packages"] if p["severity"] in ("high", "medium")]
    if risky:
        out.append("")
        out.append("## Details for risky packages")
        for p in risky[:60]:
            bits = []
            if p.get("created"):
                bits.append(f"created {p['created'][:10]}")
            if p.get("weekly") is not None:
                bits.append(f"{p['weekly']}/week")
            if p.get("version_count") is not None:
                bits.append(f"{p['version_count']} versions")
            if p.get("maintainers"):
                bits.append("by " + ", ".join(p["maintainers"]))
            if p["versions"]:
                bits.append("installs " + ", ".join(p["versions"]))
            tag = "direct" if p["direct"] else "nested"
            out.append(f"  {p['name']} [{tag}]: " + "; ".join(bits))
    for n in r["notes"]:
        out.append(f"note: {n}")
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(prog="deps.py", description="Check every npm package in a project against the registry and OSV.")
    p.add_argument("project", help="project folder")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--offline", action="store_true", help="list packages without network checks")
    p.add_argument("--workers", type=int, default=16, help="parallel registry requests (default 16)")
    a = p.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    try:
        r = check(a.project, offline=a.offline, workers=a.workers)
    except NotADirectoryError:
        print(f"deps.py: not a folder: {a.project}", file=sys.stderr)
        return 2
    print(json.dumps(r, indent=2) if a.json else render(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
