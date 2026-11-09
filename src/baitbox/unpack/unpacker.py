from pathlib import Path

from baitbox.unpack.archive import IGNORED_TOP, Intake, IntakeError, copy_tree, detect, refuse_home, safe_rel, untar, unzip
from baitbox.unpack.git import clone, is_git_url, neutralize_git


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
