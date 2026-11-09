import io
import os
import stat
import tarfile
import zipfile

import pytest

from baitbox import unpack
from baitbox.unpack import archive, git
from conftest import write


def make_zip(path, entries):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            info.external_attr = (mode & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)


def make_tar(path, members):
    with tarfile.open(path, "w:gz") as t:
        for m, data in members:
            t.addfile(m, io.BytesIO(data) if data is not None else None)


def tar_member(name, kind=tarfile.REGTYPE, data=b"", linkname="", mode=0o644):
    m = tarfile.TarInfo(name)
    m.type = kind
    m.mode = mode
    m.size = len(data) if kind == tarfile.REGTYPE else 0
    m.linkname = linkname
    return m, (data if kind == tarfile.REGTYPE else None)


def test_zip_normal_files_and_permissions(tmp_path):
    z = tmp_path / "p.zip"
    make_zip(z, [
        ("proj/package.json", b"{}", stat.S_IFREG | 0o644),
        ("proj/run.sh", b"echo hi", stat.S_IFREG | 0o4755),
        ("proj/src/", b"", stat.S_IFDIR | 0o755),
    ])
    info = unpack.intake(str(z), tmp_path / "out")
    root = tmp_path / "out" / "proj"
    assert info["project_root"] == str(root)
    assert (root / "package.json").read_text() == "{}"
    mode = (root / "run.sh").stat().st_mode
    assert mode & 0o111
    assert not mode & (stat.S_ISUID | stat.S_ISGID)
    assert (root / "src").is_dir()
    assert info["skipped"] == []


@pytest.mark.parametrize("name", ["../evil.txt", "/etc/evil", "a/../../evil", "..\\..\\evil.txt", "C:/Windows/evil"])
def test_zip_rejects_unsafe_paths(tmp_path, name):
    z = tmp_path / "p.zip"
    make_zip(z, [(name, b"x", stat.S_IFREG | 0o644), ("ok.txt", b"ok", stat.S_IFREG | 0o644)])
    info = unpack.intake(str(z), tmp_path / "out")
    assert (tmp_path / "out" / "ok.txt").exists()
    assert not (tmp_path / "evil.txt").exists()
    assert any("unsafe path" in s["reason"] for s in info["skipped"])


def test_zip_symlink_entry_is_not_created(tmp_path):
    z = tmp_path / "p.zip"
    make_zip(z, [("link", b"/home/user/.ssh/id_ed25519", stat.S_IFLNK | 0o777)])
    info = unpack.intake(str(z), tmp_path / "out")
    assert not os.path.lexists(tmp_path / "out" / "link")
    assert info["skipped"][0]["reason"].startswith("symlink")


def test_zip_duplicate_entries_keep_first(tmp_path):
    import warnings

    z = tmp_path / "p.zip"
    with zipfile.ZipFile(z, "w") as zf, warnings.catch_warnings():
        warnings.simplefilter("ignore")
        zf.writestr("a.txt", "first")
        zf.writestr("a.txt", "second")
    info = unpack.intake(str(z), tmp_path / "out")
    assert (tmp_path / "out" / "a.txt").read_text() == "first"
    assert any("duplicate" in s["reason"] for s in info["skipped"])


def test_zip_bomb_ratio_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "RATIO_MIN_BYTES", 1000)
    z = tmp_path / "bomb.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", b"\0" * 5_000_000)
    with pytest.raises(unpack.IntakeError, match="zip bomb"):
        unpack.intake(str(z), tmp_path / "out")


def test_zip_total_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "MAX_TOTAL_BYTES", 10)
    z = tmp_path / "big.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a.txt", "0123456789abcdef")
    with pytest.raises(unpack.IntakeError):
        unpack.intake(str(z), tmp_path / "out")


def test_zip_ignores_macosx_folder(tmp_path):
    z = tmp_path / "p.zip"
    make_zip(z, [("__MACOSX/._a", b"x", stat.S_IFREG | 0o644), ("proj/a.js", b"1", stat.S_IFREG | 0o644)])
    info = unpack.intake(str(z), tmp_path / "out")
    assert info["project_root"].endswith("proj")
    assert not (tmp_path / "out" / "__MACOSX").exists()


def test_tar_rejects_links_devices_and_traversal(tmp_path):
    t = tmp_path / "p.tgz"
    make_tar(t, [
        tar_member("proj/a.js", data=b"1"),
        tar_member("proj/inside", tarfile.SYMTYPE, linkname="a.js"),
        tar_member("proj/outside", tarfile.SYMTYPE, linkname="/etc/passwd"),
        tar_member("proj/up", tarfile.SYMTYPE, linkname="../../x"),
        tar_member("proj/hard", tarfile.LNKTYPE, linkname="proj/a.js"),
        tar_member("proj/dev", tarfile.CHRTYPE),
        tar_member("../escape.txt", data=b"x"),
    ])
    info = unpack.intake(str(t), tmp_path / "out")
    root = tmp_path / "out" / "proj"
    assert (root / "a.js").read_text() == "1"
    assert os.readlink(root / "inside") == "a.js"
    for name in ("outside", "up", "hard", "dev"):
        assert not os.path.lexists(root / name)
    assert not (tmp_path / "escape.txt").exists()
    reasons = " ".join(s["reason"] for s in info["skipped"])
    assert "outside the project" in reasons and "special file" in reasons and "unsafe path" in reasons


def test_folder_copy_skips_outside_links_and_sockets(tmp_path):
    import socket

    src = tmp_path / "src"
    write(src, "a.js", "1")
    os.symlink("/etc/passwd", src / "passwd")
    os.symlink("a.js", src / "alias.js")
    sock_path = src / "s.sock"
    s = socket.socket(socket.AF_UNIX)
    s.bind(str(sock_path))
    try:
        info = unpack.intake(str(src), tmp_path / "out")
    finally:
        s.close()
    out = tmp_path / "out"
    assert (out / "a.js").exists()
    assert os.readlink(out / "alias.js") == "a.js"
    assert not os.path.lexists(out / "passwd")
    assert not os.path.lexists(out / "s.sock")
    assert len(info["skipped"]) == 2


def test_folder_copy_refuses_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(unpack.IntakeError, match="home folder"):
        unpack.intake(str(tmp_path), tmp_path / "x" / "out")


def test_folder_copy_refuses_output_inside_source(tmp_path):
    src = tmp_path / "src"
    write(src, "a.js", "1")
    with pytest.raises(unpack.IntakeError, match="inside the project"):
        unpack.intake(str(src), src / "check" / "out")


def test_single_file(tmp_path):
    f = write(tmp_path, "payload.js", "console.log(1)")
    info = unpack.intake(str(f), tmp_path / "out")
    assert (tmp_path / "out" / "payload.js").exists()
    assert info["kind"] == "file"


def test_unsupported_archive(tmp_path):
    f = write(tmp_path, "a.7z", b"7z\xbc\xaf\x27\x1c" + b"\0" * 32)
    with pytest.raises(unpack.IntakeError, match="not supported"):
        unpack.intake(str(f), tmp_path / "out")


@pytest.mark.parametrize("url", [
    "--upload-pack=touch /tmp/x", "ext::sh -c touch% /tmp/x", "file:///etc", "https://host/repo; rm -rf /",
    "https://host/repo with space", "git://host/repo", "ssh://-oProxyCommand=x/repo",
])
def test_git_url_validation_rejects(tmp_path, url):
    it = archive.Intake(tmp_path)
    with pytest.raises(unpack.IntakeError):
        git.clone(url, it)


@pytest.mark.parametrize("url", ["https://github.com/a/b.git", "git@github.com:a/b.git", "ssh://git@github.com/a/b"])
def test_git_url_validation_accepts(url):
    assert git.GIT_URL_RE.match(url)


@pytest.mark.parametrize("source,url,branch", [
    ("https://github.com/a/b", "https://github.com/a/b.git", None),
    ("github.com/a/b/", "https://github.com/a/b.git", None),
    ("https://github.com/a/b.git", "https://github.com/a/b.git", None),
    ("https://github.com/a/b/tree/dev/src/x", "https://github.com/a/b.git", "dev"),
    ("https://www.github.com/a/b/blob/main/README.md", "https://github.com/a/b.git", "main"),
    ("https://github.com/a/b/pulls", "https://github.com/a/b.git", None),
    ("http://github.com/a/b", "https://github.com/a/b.git", None),
    ("https://gitlab.com/g/sub/repo/-/tree/feature", "https://gitlab.com/g/sub/repo.git", "feature"),
    ("https://gitlab.com/g/sub/repo", "https://gitlab.com/g/sub/repo.git", None),
    ("https://bitbucket.org/a/b/src/main/", "https://bitbucket.org/a/b.git", "main"),
    ("https://codeberg.org/a/b/src/branch/dev", "https://codeberg.org/a/b.git", "dev"),
    ("git@github.com:a/b.git", "git@github.com:a/b.git", None),
    ("https://git.example.com/a/b.git", "https://git.example.com/a/b.git", None),
])
def test_normalize_git_url(source, url, branch):
    assert git.normalize_git_url(source) == (url, branch)


def test_is_git_url(tmp_path):
    assert unpack.is_git_url("github.com/a/b")
    assert unpack.is_git_url("git@github.com:a/b.git")
    assert not unpack.is_git_url(str(tmp_path))
    assert not unpack.is_git_url("project.zip")
    assert unpack.repo_name("https://github.com/a/my-app/tree/dev") == "my-app"


def test_clone_command_is_locked_down(tmp_path, monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        seen["env"] = kw["env"]
        (tmp_path / "repo").mkdir()
        (tmp_path / "repo" / "a.js").write_text("1")

        class P:
            returncode = 0
            stdout = stderr = ""
        return P()

    monkeypatch.setattr(git.subprocess, "run", fake_run)
    monkeypatch.setattr(git.shutil, "which", lambda x: "/usr/bin/git")
    info = git.clone("https://github.com/a/b/tree/dev", archive.Intake(tmp_path))
    cmd = seen["cmd"]
    assert info == {"url": "https://github.com/a/b.git", "branch": "dev"}
    assert cmd[cmd.index("--") + 1] == "https://github.com/a/b.git"
    assert cmd[cmd.index("--branch") + 1] == "dev"
    for c in ("core.hooksPath=/dev/null", "core.symlinks=false", "protocol.ext.allow=never", "core.fsmonitor=false"):
        assert c in cmd
    assert seen["env"]["GIT_TERMINAL_PROMPT"] == "0"


def test_clone_failure_mentions_login(tmp_path, monkeypatch):
    class P:
        returncode = 128
        stdout = ""
        stderr = "fatal: could not read Username for 'https://github.com'"

    monkeypatch.setattr(git.subprocess, "run", lambda cmd, **kw: P())
    monkeypatch.setattr(git.shutil, "which", lambda x: "/usr/bin/git")
    with pytest.raises(unpack.IntakeError, match="gh auth login"):
        git.clone("https://github.com/a/private", archive.Intake(tmp_path))


def test_bad_branch_is_refused(tmp_path):
    with pytest.raises(unpack.IntakeError, match="branch"):
        git.clone("https://github.com/a/b/tree/--upload-pack=x", archive.Intake(tmp_path))


def test_git_config_risks():
    cfg = (
        '[core]\n\trepositoryformatversion = 0\n\tfsmonitor = "./.git/x.sh"\n\tfilemode = true\n'
        '[remote "origin"]\n\turl = https://github.com/a/b\n'
        '[alias]\n\tst = status\n\tpwn = "!sh -c id"\n'
        '[filter "lfs"]\n\tprocess = git-lfs filter-process\n'
        '[submodule "lib"]\n\tpath = lib\n'
        '[includeIf "gitdir:~/"]\n\tpath = /tmp/evil\n'
    )
    assert git.git_config_risks(cfg) == ["alias.pwn", "core.fsmonitor", "filter.process", "includeif.path"]
    assert git.git_config_risks("[core]\n\tfsmonitor = true\n\tbare = false\n") == []


def test_zip_with_dangerous_git_config_is_neutralized(tmp_path):
    z = tmp_path / "p.zip"
    make_zip(z, [
        ("proj/.git/config", b"[core]\n\tfsmonitor = touch /tmp/pwned\n", stat.S_IFREG | 0o644),
        ("proj/.git/HEAD", b"ref: refs/heads/main\n", stat.S_IFREG | 0o644),
        ("proj/index.js", b"1", stat.S_IFREG | 0o644),
        ("proj/vendor/x/HEAD", b"ref: refs/heads/main\n", stat.S_IFREG | 0o644),
        ("proj/vendor/x/config", b"[core]\n\tsshCommand = sh -c id\n", stat.S_IFREG | 0o644),
        ("proj/vendor/x/objects/", b"", stat.S_IFDIR | 0o755),
        ("proj/vendor/x/refs/", b"", stat.S_IFDIR | 0o755),
        ("proj/sub/.git", b"gitdir: /home/user/.secret-repo\n", stat.S_IFREG | 0o644),
    ])
    info = unpack.intake(str(z), tmp_path / "out")
    root = tmp_path / "out" / "proj"
    assert not (root / ".git" / "config").exists() and (root / ".git" / "config.baitbox-off").exists()
    assert not (root / "vendor/x/config").exists()
    assert not (root / "sub/.git").exists()
    reasons = " ".join(s["reason"] for s in info["skipped"])
    assert "core.fsmonitor" in reasons and "core.sshcommand" in reasons and "bare git repository" in reasons and "outside the project" in reasons


def test_normal_git_config_is_kept(tmp_path):
    src = tmp_path / "src"
    write(src, ".git/config", '[core]\n\tbare = false\n[remote "origin"]\n\turl = git@github.com:a/b.git\n[branch "main"]\n\tremote = origin\n')
    write(src, ".git/HEAD", "ref: refs/heads/main\n")
    write(src, "a.js", "1")
    info = unpack.intake(str(src), tmp_path / "out")
    assert (tmp_path / "out" / ".git" / "config").exists()
    assert info["skipped"] == []
