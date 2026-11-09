import os
import re
import stat
import tarfile
import zipfile
from pathlib import Path

MAX_FILES = 200_000
MAX_TOTAL_BYTES = 4 * 1024 ** 3
MAX_RATIO = 200
RATIO_MIN_BYTES = 20 * 1024 * 1024

IGNORED_TOP = {"__MACOSX"}


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
