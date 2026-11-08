import os
import re
import shutil
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path

MAX_FILES = 200_000
MAX_TOTAL_BYTES = 4 * 1024 ** 3
MAX_RATIO = 200
RATIO_MIN_BYTES = 20 * 1024 * 1024
GIT_TIMEOUT = 900
GIT_URL_RE = re.compile(
    r"^(?:https://[A-Za-z0-9][A-Za-z0-9.-]*(?::\d{1,5})?/[A-Za-z0-9._~%+][A-Za-z0-9._~%+/-]*"
    r"|ssh://(?:[A-Za-z0-9][A-Za-z0-9._-]*@)?[A-Za-z0-9][A-Za-z0-9.-]*(?::\d{1,5})?/[A-Za-z0-9._~%+][A-Za-z0-9._~%+/-]*"
    r"|git@[A-Za-z0-9][A-Za-z0-9.-]*:[A-Za-z0-9._~%+][A-Za-z0-9._~%+/-]*)$"
)
GIT_SAFE_CONFIG = (
    "core.hooksPath=/dev/null", "core.symlinks=false", "core.fsmonitor=false", "core.protectNTFS=true",
    "core.protectHFS=true", "protocol.file.allow=never", "protocol.ext.allow=never", "protocol.allow=user",
    "filter.lfs.smudge=", "filter.lfs.process=", "filter.lfs.required=false", "submodule.recurse=false",
    "transfer.fsckObjects=true", "fetch.fsckObjects=true", "receive.fsckObjects=true", "advice.detachedHead=false",
)
IGNORED_TOP = {"__MACOSX"}
HOSTED_RE = re.compile(r"^(?:https?://)?(?:www\.)?(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)/([^?#]+?)/?(?:[?#].*)?$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._/-]{0,200}$")
AUTH_HINT = (
    "If this is a private repo, sign in first (for GitHub: gh auth login, then gh auth setup-git), "
    "or use an ssh link such as git@github.com:user/repo.git"
)
GIT_RISKY = {
    "core": {"fsmonitor", "hookspath", "sshcommand", "askpass", "gitproxy", "pager", "editor", "worktree"},
    "credential": {"helper"},
    "sequence": {"editor"},
    "gpg": {"program"},
    "uploadpack": {"packobjectshook"},
    "include": {"path"},
    "includeif": {"path"},
    "diff": {"textconv", "command"},
    "filter": {"clean", "smudge", "process"},
    "merge": {"driver"},
    "difftool": {"cmd"},
    "mergetool": {"cmd"},
    "pager": None,
}
GIT_BOOL = {"", "true", "false", "yes", "no", "on", "off", "0", "1"}


class IntakeError(Exception):
    pass


class Intake:
    def __init__(self, dest):
        self.dest = Path(dest)
        self.files = 0
        self.bytes = 0
        self.skipped = []

    def skip(self, path, reason, severity="high"):
        self.skipped.append({"path": str(path)[:300], "reason": reason, "severity": severity})

    def count(self, size):
        self.files += 1
        self.bytes += max(0, size)
        if self.files > MAX_FILES:
            raise IntakeError(f"more than {MAX_FILES} files; refusing to unpack")
        if self.bytes > MAX_TOTAL_BYTES:
            raise IntakeError(f"more than {MAX_TOTAL_BYTES // 1024 ** 3} GB once unpacked; refusing to unpack")

    def mkdir(self, rel):
        self.target(rel + "/.d").parent.mkdir(parents=True, exist_ok=True)

    def target(self, rel):
        t = self.dest.joinpath(*rel.split("/"))
        parent = t.parent
        parent.mkdir(parents=True, exist_ok=True)
        real_parent = parent.resolve()
        root = self.dest.resolve()
        if real_parent != root and root not in real_parent.parents:
            raise IntakeError(f"path escapes the check folder: {rel}")
        return t

    def write_stream(self, rel, src, declared, executable):
        t = self.target(rel)
        written = 0
        limit = declared + 1024 * 1024
        try:
            with open(t, "xb") as out:
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > limit:
                        raise IntakeError(f"{rel} is larger than the archive says; possible zip bomb")
                    out.write(chunk)
        except FileExistsError:
            self.skip(rel, "duplicate entry; the first copy was kept", "medium")
            return
        os.chmod(t, 0o755 if executable else 0o644)


def safe_rel(name):
    n = name.replace("\\", "/")
    if "\0" in n or n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        return None
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    if any(len(p.encode("utf-8", "surrogateescape")) > 255 for p in parts):
        return None
    return "/".join(parts)


def link_inside(rel, target):
    if target.startswith("/") or "\0" in target:
        return False
    base = Path(rel).parent
    joined = os.path.normpath(os.path.join(str(base), target))
    return not (joined == ".." or joined.startswith("../") or joined.startswith("/"))


def detect(path):
    with open(path, "rb") as f:
        head = f.read(262)
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:4] == b"Rar!":
        return "rar"
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    try:
        if tarfile.is_tarfile(path):
            return "tar"
    except (OSError, tarfile.TarError):
        pass
    return "file"


def unzip(path, it):
    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        raise IntakeError(f"not a valid zip file: {e}") from e
    with z:
        infos = z.infolist()
        if len(infos) > MAX_FILES:
            raise IntakeError(f"more than {MAX_FILES} entries; refusing to unpack")
        if sum(i.file_size for i in infos) > MAX_TOTAL_BYTES:
            raise IntakeError("archive is too large once unpacked; refusing to unpack")
        for i in infos:
            rel = safe_rel(i.filename)
            if rel is None:
                it.skip(i.filename, "unsafe path (absolute, '..' or too long); not unpacked")
                continue
            if rel.split("/")[0] in IGNORED_TOP:
                continue
            mode = (i.external_attr >> 16) & 0xFFFF
            kind = stat.S_IFMT(mode)
            if kind == stat.S_IFLNK:
                it.skip(rel, "symlink inside the zip; not unpacked")
                continue
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                it.skip(rel, "special file inside the zip; not unpacked")
                continue
            if i.is_dir():
                it.mkdir(rel)
                continue
            if i.flag_bits & 0x1:
                it.skip(rel, "encrypted entry; not unpacked", "medium")
                continue
            if i.file_size > RATIO_MIN_BYTES and i.compress_size and i.file_size / i.compress_size > MAX_RATIO:
                raise IntakeError(f"{rel} expands {i.file_size // max(1, i.compress_size)}x; possible zip bomb")
            it.count(i.file_size)
            try:
                with z.open(i) as src:
                    it.write_stream(rel, src, i.file_size, bool(mode & 0o111))
            except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError) as e:
                it.skip(rel, f"could not unpack: {e}", "medium")


def untar(path, it):
    try:
        t = tarfile.open(path, "r:*")
    except tarfile.TarError as e:
        raise IntakeError(f"not a valid tar file: {e}") from e
    links = []
    with t:
        for m in t:
            rel = safe_rel(m.name)
            if rel is None:
                it.skip(m.name, "unsafe path (absolute, '..' or too long); not unpacked")
                continue
            if rel.split("/")[0] in IGNORED_TOP:
                continue
            if m.issym() or m.islnk():
                if m.issym() and link_inside(rel, m.linkname):
                    links.append((rel, m.linkname))
                else:
                    it.skip(rel, f"link to {m.linkname} points outside the project; not unpacked")
                continue
            if m.isdir():
                it.mkdir(rel)
                continue
            if not m.isreg():
                it.skip(rel, "device, pipe or other special file; not unpacked")
                continue
            it.count(m.size)
            f = t.extractfile(m)
            if f is None:
                it.skip(rel, "could not read entry", "medium")
                continue
            with f:
                it.write_stream(rel, f, m.size, bool(m.mode & 0o111))
    for rel, target in links:
        dst = it.target(rel)
        if dst.exists() or dst.is_symlink():
            it.skip(rel, "duplicate entry; the first copy was kept", "medium")
            continue
        os.symlink(target, dst)
        it.count(0)


def refuse_home(src):
    home = Path(os.environ.get("HOME") or Path.home()).resolve()
    if src == Path("/") or src == home or src in home.parents:
        raise IntakeError(f"refusing to copy a folder that contains your home folder: {src}")


def copy_tree(src, it):
    src = Path(src).resolve(strict=True)
    refuse_home(src)
    for dp, dns, fns in os.walk(src, followlinks=False):
        rel_dir = os.path.relpath(dp, src)
        dns.sort()
        for name in list(dns) + sorted(fns):
            full = os.path.join(dp, name)
            rel = os.path.normpath(os.path.join(rel_dir, name)).replace(os.sep, "/")
            try:
                st = os.lstat(full)
            except OSError as e:
                it.skip(rel, f"could not read: {e}", "medium")
                continue
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(full)
                if name in dns:
                    dns.remove(name)
                if link_inside(rel, target):
                    dst = it.target(rel)
                    os.symlink(target, dst)
                    it.count(0)
                else:
                    it.skip(rel, f"link to {target} points outside the project; not copied")
                continue
            if stat.S_ISDIR(st.st_mode):
                it.mkdir(rel)
                continue
            if not stat.S_ISREG(st.st_mode):
                it.skip(rel, "socket, device or pipe; not copied")
                continue
            it.count(st.st_size)
            try:
                with open(full, "rb") as fsrc:
                    it.write_stream(rel, fsrc, st.st_size, bool(st.st_mode & 0o111))
            except OSError as e:
                it.skip(rel, f"could not copy: {e}", "medium")


def is_git_url(source):
    if not isinstance(source, str) or os.path.exists(source):
        return False
    return source.startswith(("https://", "ssh://", "git@")) or bool(HOSTED_RE.match(source))


def normalize_git_url(source):
    s = source.strip()
    m = HOSTED_RE.match(s)
    if not m:
        return s, None
    host, path = m.group(1), m.group(2)
    branch = None
    if "/-/" in path:
        repo_path, rest = path.split("/-/", 1)
        rest_parts = rest.split("/")
        if rest_parts[0] in ("tree", "blob") and len(rest_parts) > 1:
            branch = rest_parts[1]
    else:
        parts = [p for p in path.split("/") if p]
        if host == "gitlab.com":
            repo_path = "/".join(parts)
        else:
            repo_path = "/".join(parts[:2])
            if len(parts) > 3 and parts[2] in ("tree", "blob"):
                branch = parts[3]
            elif len(parts) > 3 and parts[2] == "src":
                branch = parts[4] if parts[3] == "branch" and len(parts) > 4 else parts[3]
    repo_path = re.sub(r"\.git$", "", repo_path)
    return f"https://{host}/{repo_path}.git", branch


def repo_name(source):
    url, _ = normalize_git_url(source)
    tail = re.split(r"[/:]", url.rstrip("/"))[-1]
    return re.sub(r"\.git$", "", tail) or "repo"


def clone(source, it):
    url, branch = normalize_git_url(source)
    if url.startswith("-") or not GIT_URL_RE.match(url) or "::" in url:
        raise IntakeError("unsupported git URL; use https://, ssh:// or git@host:path")
    if branch is not None and (branch.startswith("-") or not BRANCH_RE.match(branch)):
        raise IntakeError(f"unsupported branch name in the link: {branch}")
    if not shutil.which("git"):
        raise IntakeError("git is not installed")
    cmd = ["git"]
    for c in GIT_SAFE_CONFIG:
        cmd += ["-c", c]
    target = it.dest / "repo"
    cmd += ["clone", "--depth", "1", "--single-branch", "--no-recurse-submodules"]
    if branch:
        cmd += ["--branch", branch]
    cmd += ["--", url, str(target)]
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false", "SSH_ASKPASS": "/bin/false", "GIT_LFS_SKIP_SMUDGE": "1"})
    try:
        p = subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=GIT_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        raise IntakeError("git clone took too long") from e
    if p.returncode != 0:
        msg = (p.stderr or p.stdout).strip()[-500:]
        hint = f" {AUTH_HINT}" if re.search(r"Username|Authentication|not found|Permission denied|could not read", msg, re.I) else ""
        raise IntakeError(f"git clone failed: {msg}{hint}")
    for dp, dns, fns in os.walk(target):
        if ".git" in dns:
            dns.remove(".git")
        for f in fns:
            try:
                it.count(os.lstat(os.path.join(dp, f)).st_size)
            except OSError:
                pass
    return {"url": url, "branch": branch}


def git_config_risks(text_):
    risks = []
    section = ""
    for raw in text_.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        h = re.match(r'^\[\s*([A-Za-z0-9.-]+)(?:\s+"[^"]*")?\s*\]', line)
        if h:
            section = h.group(1).split(".")[0].lower()
            line = line[h.end():].strip()
            if not line:
                continue
        kv = re.match(r"^([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*))?$", line)
        if not kv:
            continue
        key = kv.group(1).lower()
        value = (kv.group(2) or "").strip().strip('"')
        if section == "alias" and value.startswith("!"):
            risks.append(f"alias.{key}")
            continue
        if section not in GIT_RISKY:
            continue
        keys = GIT_RISKY[section]
        if keys is not None and key not in keys:
            continue
        if section == "core" and key == "fsmonitor" and value.lower() in GIT_BOOL:
            continue
        risks.append(f"{section}.{key}")
    return sorted(set(risks))


def read_small(path, limit=1_000_000):
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""


def neutralize_git(it):
    root = it.dest
    for dp, dns, fns in os.walk(root, followlinks=False):
        here = Path(dp)
        rel_dir = os.path.relpath(dp, root)
        dns[:] = [d for d in dns if d != "node_modules"]
        configs = []
        if ".git" in dns:
            configs.append(here / ".git" / "config")
            dns.remove(".git")
        if ".git" in fns and (here / ".git").is_file() and not (here / ".git").is_symlink():
            m = re.match(r"^gitdir:\s*(.+)$", read_small(here / ".git", 10_000).strip())
            if m:
                target = (here / m.group(1).strip()).resolve()
                if target != root.resolve() and root.resolve() not in target.parents:
                    os.rename(here / ".git", here / ".git.baitbox-off")
                    it.skip(os.path.join(rel_dir, ".git"), f"points git at a folder outside the project ({m.group(1).strip()}); switched off in this copy")
        if rel_dir != "." and {"HEAD", "config"} <= set(fns) and "objects" in dns and "refs" in dns:
            it.skip(rel_dir, "a hidden bare git repository; git commands run inside it would use its settings", "medium")
            configs.append(here / "config")
            dns[:] = []
        for cfg in configs:
            if not cfg.is_file() or cfg.is_symlink():
                continue
            risks = git_config_risks(read_small(cfg))
            if risks:
                os.rename(cfg, cfg.with_name("config.baitbox-off"))
                mild = all(r in ("core.pager", "core.editor", "sequence.editor", "core.worktree") or r.startswith("pager.") for r in risks)
                it.skip(
                    os.path.relpath(cfg, root),
                    "git settings that run commands (" + ", ".join(risks) + "); switched off in this copy",
                    "medium" if mild else "high",
                )


def project_root(dest):
    entries = [e for e in Path(dest).iterdir() if e.name not in IGNORED_TOP]
    if len(entries) == 1 and entries[0].is_dir() and not entries[0].is_symlink():
        return entries[0]
    return Path(dest)


def intake(source, dest):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=False)
    it = Intake(dest)
    git = None
    if is_git_url(source):
        kind = "git"
        git = clone(source, it)
    else:
        p = Path(source).expanduser()
        if not p.exists():
            raise IntakeError(f"not found: {source}")
        if p.is_dir():
            kind = "folder"
            real_src = p.resolve()
            real_dest = dest.resolve()
            refuse_home(real_src)
            if real_dest == real_src or real_src in real_dest.parents:
                raise IntakeError("the check folder must not be inside the project folder")
            copy_tree(p, it)
        elif p.is_file():
            kind = detect(p)
            if kind == "zip":
                unzip(p, it)
            elif kind == "tar":
                untar(p, it)
            elif kind in ("7z", "rar", "zstd"):
                raise IntakeError(f"{kind} archives are not supported; unpack it with care and pass the folder, or convert it to zip")
            else:
                it.count(p.stat().st_size)
                with open(p, "rb") as f:
                    it.write_stream(safe_rel(p.name) or "file", f, p.stat().st_size, False)
        else:
            raise IntakeError(f"not a file or folder: {source}")
    neutralize_git(it)
    root = project_root(dest)
    return {
        "source": str(source), "kind": kind, "dest": str(dest), "project_root": str(root), "files": it.files,
        "bytes": it.bytes, "skipped": it.skipped, "git": git,
    }
