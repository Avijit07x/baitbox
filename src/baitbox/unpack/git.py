import os
import re
import shutil
import subprocess
from pathlib import Path

from baitbox.unpack.archive import IntakeError

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
