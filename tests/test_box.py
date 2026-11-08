import subprocess

import analyze
from conftest import SCRIPTS, needs_sandbox, write

BOX = SCRIPTS / "box.sh"


def run_box(*args, env=None):
    return subprocess.run(["bash", str(BOX), *map(str, args)], capture_output=True, text=True, env=env, timeout=180)


def test_usage_errors(tmp_path):
    assert run_box().returncode == 2
    assert run_box("bad", tmp_path, tmp_path / "b", 5, "true").returncode == 2
    assert run_box("nonet", tmp_path, tmp_path / "b", "x", "true").returncode == 2
    assert run_box("nonet", tmp_path, tmp_path / "b", 0, "true").returncode == 2
    assert run_box("nonet", tmp_path, tmp_path / "b", 5, "").returncode == 2
    assert run_box("nonet", tmp_path / "missing", tmp_path / "b", 5, "true").returncode == 2


def test_refuses_dangerous_mounts(tmp_path):
    import os

    env = dict(os.environ, HOME=str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    r = run_box("nonet", tmp_path, tmp_path / "x", 5, "true", env=env)
    assert r.returncode == 2 and "home folder" in r.stderr
    r = run_box("nonet", "/", tmp_path / "x", 5, "true")
    assert r.returncode == 2
    r = run_box("nonet", "/tmp", tmp_path / "x", 5, "true")
    assert r.returncode == 2
    proj = tmp_path / "proj"
    proj.mkdir()
    r = run_box("nonet", proj, proj / "box", 5, "true")
    assert r.returncode == 2 and "contain each other" in r.stderr


def test_refuses_socket_in_project(tmp_path):
    import socket

    proj = tmp_path / "proj"
    proj.mkdir()
    s = socket.socket(socket.AF_UNIX)
    s.bind(str(proj / "x.sock"))
    try:
        r = run_box("nonet", proj, tmp_path / "box", 5, "true")
    finally:
        s.close()
    assert r.returncode == 2 and "socket" in r.stderr


@needs_sandbox
def test_box_isolation(tmp_path):
    proj = tmp_path / "proj"
    write(proj, "probe.sh", "\n".join([
        "echo HOME=$HOME USER=$USER HOST=$(cat /proc/sys/kernel/hostname)",
        "ls /home",
        "test -e /logs && echo LOGS_VISIBLE",
        "test -e /run/user/$(id -u)/bus && echo BUS_VISIBLE",
        "touch /usr/x 2>/dev/null && echo USR_WRITABLE",
        "touch /work/made-inside && echo WORK_WRITABLE",
        "cat ~/.ssh/id_ed25519 | head -1",
        "timeout 3 bash -c 'echo > /dev/tcp/1.1.1.1/80' 2>/dev/null && echo NET_OPEN",
        "true",
    ]))
    r = run_box("nonet", proj, tmp_path / "box", 30, "bash probe.sh")
    assert r.returncode == 0, r.stderr
    out = (next((tmp_path / "box" / "logs").glob("*.out"))).read_text()
    assert "HOME=/home/alex USER=alex HOST=alex-thinkpad" in out
    assert "OPENSSH PRIVATE KEY" in out
    for bad in ("LOGS_VISIBLE", "BUS_VISIBLE", "USR_WRITABLE", "NET_OPEN"):
        assert bad not in out
    assert "WORK_WRITABLE" in out and (proj / "made-inside").exists()
    res = analyze.analyze(tmp_path / "box")
    run = res["runs"][0]
    assert run["sandbox_started"]
    assert any("~/.ssh/id_ed25519" in f["what"] for f in run["findings"])


@needs_sandbox
def test_time_limit_kills_everything(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    r = run_box("nonet", proj, tmp_path / "box", 3, "(sleep 300 &) ; nohup sleep 300 & sleep 300")
    assert r.returncode == 0
    assert "time limit" in r.stdout
    left = subprocess.run(["pgrep", "-f", "sleep 300"], capture_output=True, text=True)
    assert left.stdout.strip() == ""


@needs_sandbox
def test_fake_home_reused_and_changes_recorded(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    run_box("nonet", proj, tmp_path / "box", 10, "echo x >> ~/.bashrc")
    run_box("nonet", proj, tmp_path / "box", 10, "true")
    diffs = sorted((tmp_path / "box" / "logs").glob("*.homediff"))
    assert len(diffs) == 2
    assert ".bashrc" in diffs[0].read_text()
    assert diffs[1].read_text().strip() == ""
