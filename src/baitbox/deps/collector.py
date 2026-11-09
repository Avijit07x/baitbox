import json
import os
import re
from pathlib import Path

from baitbox.deps.specs import classify_spec, split_first, split_name_version, valid_name

SKIP_DIRS = {".git", ".hg", ".svn"}


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
