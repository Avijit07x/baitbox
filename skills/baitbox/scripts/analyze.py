import argparse
import ipaddress
import json
import posixpath
import re
import sys
from collections import Counter
from pathlib import Path

DEFAULT_FAKE_HOME = "/home/alex"
SEVERITIES = ("high", "medium", "info")
MAX_ITEMS = 60

HIGH_BINS = {
    "sudo", "su", "pkexec", "doas", "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp",
    "sftp", "systemctl", "crontab", "at", "usermod", "useradd", "passwd", "chpasswd", "xdotool", "xclip",
    "xsel", "wl-copy", "wl-paste", "secret-tool", "powershell", "pwsh", "osascript", "security", "insmod",
    "modprobe", "mount", "nsenter", "unshare", "gsettings", "dconf",
}
MEDIUM_BINS = {
    "python", "python2", "python3", "perl", "ruby", "php", "lua", "base64", "openssl", "gpg", "xxd", "dd",
    "zip", "7z", "7za", "rar", "tar", "scrot", "import", "gnome-screenshot", "ps", "pgrep", "pkill", "kill",
    "killall", "ip", "ifconfig", "netstat", "ss", "arp", "lsblk", "whoami", "hostnamectl", "lscpu", "lspci",
    "dmidecode", "chattr", "chmod", "chown", "ln", "screen", "tmux", "xdg-open", "find", "nohup", "setsid",
}
QUIET_BINS = {"timeout", "bwrap"}
EARLY_PHASES = ("config load", "install scripts", "install")
BAD_DNS = (
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "duckdns.org", "no-ip.org", "no-ip.biz", "ddns.net",
    "hopto.org", "serveo.net", "localtunnel.me", "loca.lt", "pastebin.com", "paste.ee", "transfer.sh", "webhook.site",
    "requestbin.net", "pipedream.net", "api.telegram.org", "interact.sh", "oast.fun", "oast.live", "oast.me",
    "burpcollaborator.net", "canarytokens.com", "ipinfo.io", "ip-api.com", "ifconfig.me", "icanhazip.com",
    "api.ipify.org", "checkip.amazonaws.com", "ipwho.is", "geolocation-db.com",
)
PKG_TOOLS = {"npm", "npx", "pnpm", "pnpx", "yarn", "yarnpkg", "corepack", "bun", "bunx"}
PKG_TOOL_MARKERS = ("npm-cli.js", "npx-cli.js", "pnpm.cjs", "pnpm.mjs", "yarn.js", "corepack")
REGISTRY_NETS = [ipaddress.ip_network(n) for n in ("104.16.0.0/12", "172.64.0.0/13", "2606:4700::/32")]
NET_DNS_OK = (
    "registry.npmjs.org", "registry.yarnpkg.com", "npm.pkg.github.com", "codeload.github.com", "github.com",
    "api.github.com", "objects.githubusercontent.com", "nodejs.org", "registry.npmmirror.com",
)
NONET_DNS_INFO = (
    "registry.npmjs.org", "registry.yarnpkg.com", "telemetry.nextjs.org", "fonts.googleapis.com",
    "fonts.gstatic.com", "localhost",
)
SANDBOX_PROBES = (
    "/.dockerenv", "/run/.containerenv", "/proc/1/cgroup", "/proc/1/sched", "/proc/scsi/scsi", "/sys/hypervisor",
    "/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/board_vendor",
)
WRITE_OK_SYSTEM = (
    "/work", "/tmp", "/dev/shm", "/dev/null", "/dev/tty", "/dev/pts", "/dev/zero", "/dev/urandom", "/dev/random",
    "/dev/full", "/proc/self", "/proc/thread-self", "/run/user",
)
HOME_CACHES = (
    ".npm", ".cache", ".local/share/pnpm", ".local/state", ".pnpm-store", ".yarn", ".yarnrc", ".node_repl_history",
    ".node-gyp", ".config/yarn", ".config/configstore", ".config/nextjs-nodejs", ".config/pnpm", ".bun",
    ".config/turborepo", ".config/vercel", ".config/astro", ".config/ngrok", ".lesshst",
)
HOME_EXEC_OK = (".cache/ms-playwright", ".cache/puppeteer", ".cache/node-gyp", ".npm/_npx", ".local/share/pnpm", ".bun")
PERSIST_HOME = (
    ".config/systemd", ".config/autostart", ".local/share/applications", ".config/environment.d", ".bashrc",
    ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zlogin", ".zshenv",
    ".xprofile", ".xinitrc", ".xsessionrc", ".config/fish", ".local/bin", ".ssh/authorized_keys", ".ssh/rc",
    ".ssh/config", ".config/Code/User", ".vscode/extensions", ".gitconfig", ".config/git", ".npmrc", ".pam_environment",
    ".config/plasma-workspace", ".config/lxsession", ".config/openbox", ".config/i3", ".config/hypr",
)
PERSIST_SYSTEM = ("/etc", "/usr", "/var/spool/cron", "/var/lib", "/lib", "/bin", "/sbin", "/boot", "/root")
SENSITIVE_HOME = (
    ".ssh", ".aws", ".gnupg", ".config/google-chrome", ".config/BraveSoftware", ".config/chromium",
    ".config/microsoft-edge", ".config/opera", ".config/vivaldi", ".config/discord", ".config/solana", ".config/gh",
    ".mozilla", ".local/share/keyrings", ".docker/config.json", ".kube", ".git-credentials", ".netrc",
    ".config/Exodus", ".electrum", ".ethereum", ".bitcoin", ".config/Signal", ".config/Slack", ".config/telegram-desktop",
    ".local/share/TelegramDesktop", "Projects", "Documents", "Downloads", ".config/filezilla", ".config/rclone",
    ".pgpass", ".my.cnf", ".config/op", ".password-store",
)
SENSITIVE_SYSTEM = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/dev/input", "/dev/uinput", "/dev/mem", "/dev/kmem")

LINE_RE = re.compile(r"^(\d+)\s+(.*)$")
NAME_RE = re.compile(r"^(\w+)\(")
RESUMED_RE = re.compile(r"^<\.\.\. (\w+) resumed>(.*)$")
STR = r'"((?:[^"\\]|\\.)*)"'
STRING_RE = re.compile(STR + r"(\.\.\.)?")
DIRFD_STR_RE = re.compile(r"(?:(?:AT_FDCWD|-?\d+)<((?:[^>\\]|\\.)*)>,\s*)?" + STR)
RESULT_RE = re.compile(r"\)\s+=\s+(-?\d+|\?|0x[0-9a-f]+)(?:<((?:[^>\\]|\\.)*)>)?(?:\s+(E[A-Z0-9]+))?")
EXEC_RE = re.compile(r"^execve(?:at)?\((?:-?\d+(?:<[^>]*>)?, )?" + STR + r", \[(.*?)\](?:\.\.\.)?, (?:0x|\[|NULL)")
PIDNS_RE = re.compile(r"/\* (\d+) in strace's PID NS \*/")
CLONE_CALLS = ("clone", "clone3", "fork", "vfork")
FD_DECOR_RE = re.compile(r"^\s*-?\d+<((?:[^>\\]|\\.)*)>")
IN4_RE = re.compile(r'sa_family=AF_INET, sin_port=htons\((\d+)\), sin_addr=inet_addr\("([\d.]+)"\)')
IN6_RE = re.compile(r'sa_family=AF_INET6, sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([^"]+)"')
UNIX_RE = re.compile(r'sa_family=AF_UNIX, sun_path=(@?)' + STR)
MODE_RE = re.compile(r",\s*0([0-7]{3,4})\b")
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
SIMPLE_ESC = {"n": 10, "t": 9, "r": 13, "v": 11, "f": 12, "a": 7, "b": 8, '"': 34, "\\": 92, "'": 39}


def c_unescape(s):
    out = bytearray()
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c != "\\":
            out += c.encode("utf-8", "surrogateescape")
            i += 1
            continue
        i += 1
        if i >= n:
            out.append(92)
            break
        c = s[i]
        if c in SIMPLE_ESC:
            out.append(SIMPLE_ESC[c])
            i += 1
        elif c == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", s[i + 1:i + 3]):
            out.append(int(s[i + 1:i + 3], 16))
            i += 3
        elif c in "01234567":
            j = i
            while j < n and j - i < 3 and s[j] in "01234567":
                j += 1
            out.append(int(s[i:j], 8) & 0xFF)
            i = j
        else:
            out += ("\\" + c).encode("utf-8", "surrogateescape")
            i += 1
    return bytes(out)


def text(s):
    return c_unescape(s).decode("utf-8", "replace")


def dns_query_name(b):
    if len(b) < 17 or b[2] & 0x80 or int.from_bytes(b[4:6], "big") != 1 or b[6:8] != b"\0\0":
        return None
    i = 12
    labels = []
    while i < len(b):
        ln = b[i]
        if ln == 0:
            i += 1
            break
        if ln > 63 or i + 1 + ln > len(b):
            return None
        label = b[i + 1:i + 1 + ln]
        if not re.fullmatch(rb"[A-Za-z0-9_-]+", label):
            return None
        labels.append(label.decode("ascii"))
        i += 1 + ln
    else:
        return None
    if not labels or len(b) < i + 4:
        return None
    return ".".join(labels).lower()


def norm_ip(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return None
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        return a.ipv4_mapped
    return a


def under(path, prefix):
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def under_any(path, prefixes):
    return any(under(path, p) for p in prefixes)


class Findings:
    def __init__(self):
        self.items = {}
        self.current_phase = ""

    def add(self, severity, kind, what, process="", detail="", phase=None):
        phase = self.current_phase if phase is None else phase
        key = (kind, what, phase)
        item = self.items.get(key)
        if item:
            item["count"] += 1
            if SEVERITIES.index(severity) < SEVERITIES.index(item["severity"]):
                item["severity"] = severity
            return
        self.items[key] = {
            "severity": severity, "kind": kind, "what": what, "process": process, "detail": detail, "phase": phase,
            "count": 1,
        }

    def sorted(self):
        return sorted(self.items.values(), key=lambda f: (SEVERITIES.index(f["severity"]), f["kind"], f["what"]))


class TraceReader:
    def __init__(self, fake_home, decoys, mode):
        self.fh = fake_home
        self.decoys = set(decoys)
        self.mode = mode
        self.procs = {}
        self.pending = {}
        self.programs = Counter()
        self.inner_started = False
        self.f = Findings()
        self.lines = 0
        self.last_cloner = None
        self.phase = {}

    def who(self, pid):
        exe, argv = self.procs.get(pid, ("?", []))
        return exe, argv

    def label(self, pid):
        exe, argv = self.who(pid)
        shown = " ".join(argv[:6])
        if len(shown) > 160:
            shown = shown[:157] + "..."
        return f"{posixpath.basename(exe)}: {shown}" if shown else posixpath.basename(exe)

    def add(self, pid, severity, kind, what, detail=""):
        self.f.add(severity, kind, what, self.label(pid), detail, self.phase.get(pid, "run"))

    def phase_for(self, pid, exe, argv):
        cur = self.phase.get(pid, "run")
        base = posixpath.basename(exe)
        tool = base in PKG_TOOLS or any(posixpath.basename(a) in PKG_TOOLS for a in argv[:2]) or any(m in a for a in argv[:3] for m in PKG_TOOL_MARKERS)
        if tool:
            words = argv[1:7]
            if "rebuild" in words:
                return "install scripts"
            if any(w in ("install", "i", "ci", "add") for w in words):
                return "install"
            if "run" in words:
                i = words.index("run")
                return f"npm run {words[i + 1]}" if i + 1 < len(words) else cur
            return cur
        if base == "node" and "-e" in argv and any("pathToFileURL" in a for a in argv):
            return "config load"
        return cur

    def is_pkg_tool(self, pid):
        exe, argv = self.who(pid)
        names = {posixpath.basename(exe)} | {posixpath.basename(a) for a in argv[:2]}
        return bool(names & PKG_TOOLS) or any(m in a for a in argv[:3] for m in PKG_TOOL_MARKERS)

    def home_rel(self, path):
        if under(path, self.fh):
            return path[len(self.fh):].lstrip("/")
        return None

    def feed(self, raw):
        self.lines += 1
        m = LINE_RE.match(raw)
        if not m:
            return
        pid, body = m.group(1), m.group(2)
        if pid not in self.procs and self.last_cloner in self.procs:
            self.procs[pid] = self.procs[self.last_cloner]
            self.phase[pid] = self.phase.get(self.last_cloner, "run")
        if body.startswith(("+++", "---")):
            return
        if body.endswith("<unfinished ...>"):
            self.pending[pid] = body[: -len("<unfinished ...>")].rstrip()
            if body.startswith(tuple(c + "(" for c in CLONE_CALLS)):
                self.last_cloner = pid
            return
        r = RESUMED_RE.match(body)
        if r:
            head = self.pending.pop(pid, r.group(1) + "(")
            body = head + r.group(2)
        n = NAME_RE.match(body)
        if not n:
            return
        name = n.group(1)
        results = list(RESULT_RE.finditer(body))
        res = results[-1] if results else None
        ret = res.group(1) if res else "?"
        ret_path = text(res.group(2)) if res and res.group(2) else None
        err = res.group(3) if res and res.group(3) else ""
        failed = ret.startswith("-")
        status = ("failed " + err) if failed else "ok"
        if err == "EINPROGRESS":
            status = "attempted"
        if name in CLONE_CALLS:
            self.last_cloner = pid
            if not failed:
                t = PIDNS_RE.search(body)
                child = t.group(1) if t else (ret if ret.isdigit() else None)
                if child:
                    self.procs[child] = self.procs.get(pid, ("?", []))
                    self.phase[child] = self.phase.get(pid, "run")
            return
        if name in ("execve", "execveat"):
            self.on_exec(pid, body, failed)
            return
        exe, _ = self.who(pid)
        if posixpath.basename(exe) == "bwrap":
            return
        self.f.current_phase = self.phase.get(pid, "run")
        if name in ("open", "openat", "openat2", "creat"):
            self.on_open(pid, name, body, ret_path, failed, status)
        elif name in ("connect", "sendto", "sendmsg", "sendmmsg", "bind"):
            self.on_net(pid, name, body, status)
        elif name in ("rename", "renameat", "renameat2", "unlink", "unlinkat", "mkdir", "mkdirat", "symlink",
                      "symlinkat", "link", "linkat", "chmod", "fchmod", "fchmodat", "truncate"):
            self.on_change(pid, name, body, failed, status)
        elif name == "ptrace":
            self.f.add("medium", "anti-debugging", "used ptrace, often a check for debuggers", self.label(pid))

    def on_exec(self, pid, body, failed):
        if failed:
            return
        m = EXEC_RE.match(body)
        if not m:
            return
        exe = text(m.group(1))
        argv = [text(s[0]) + ("..." if s[1] else "") for s in STRING_RE.findall(m.group(2))]
        parent_exe, _ = self.who(pid)
        parent_phase = self.phase.get(pid, "run")
        self.procs[pid] = (exe, argv)
        base = posixpath.basename(exe)
        if base == "bwrap":
            return
        if base == "timeout" and (posixpath.basename(parent_exe) == "bwrap" or (not self.inner_started and argv[1:3] == ["-k", "5"])):
            self.inner_started = True
            return
        self.phase[pid] = self.phase_for(pid, exe, argv)
        self.programs[base] += 1
        joined = " ".join(argv)
        in_config = parent_phase == "config load"
        if base in HIGH_BINS:
            self.add(pid, "high", "program", f"started {base}")
        elif in_config and base != "node":
            self.add(pid, "medium", "program", f"a config file started a program: {base}")
        elif base in MEDIUM_BINS:
            self.add(pid, "info", "program", f"started {base}")
        if under_any(exe, ("/tmp", "/dev/shm", "/run", "/var/tmp")):
            self.add(pid, "high", "program", f"started a program from a temp folder: {exe}")
        rel = self.home_rel(exe)
        if rel is not None and not under_any(rel, HOME_EXEC_OK):
            self.add(pid, "medium", "program", f"started a program from the home folder: {exe}")
        if "/dev/tcp/" in joined or "/dev/udp/" in joined:
            self.add(pid, "high", "program", "opened a raw network connection from the shell")
        if base in ("sh", "bash", "dash", "zsh") and re.search(r"\b(curl|wget|base64\s+-d|nc|ncat|python3?\s+-c)\b", joined):
            self.add(pid, "high", "program", "ran a shell command that downloads or decodes code")
        if base == "node" and "-e" in argv[:-1] and self.phase[pid] != "config load":
            code = argv[argv.index("-e") + 1]
            if len(code) > 400:
                self.add(pid, "medium", "program", "ran a long inline node script")

    def resolve(self, base, path):
        if path.startswith("/"):
            return posixpath.normpath(path)
        if base:
            return posixpath.normpath(posixpath.join(base, path))
        return None

    def on_open(self, pid, name, body, ret_path, failed, status):
        m = DIRFD_STR_RE.search(body)
        if not m:
            return
        base = text(m.group(1)) if m.group(1) else None
        asked = self.resolve(base, text(m.group(2)))
        real = ret_path if (ret_path and ret_path.startswith("/")) else asked
        if real is None:
            return
        flags = body[m.end():]
        if name == "creat":
            writing = True
        else:
            writing = any(f in flags for f in WRITE_FLAGS)
        is_dir = "O_DIRECTORY" in flags
        label = self.label(pid)
        for path in dict.fromkeys(p for p in (real, asked) if p):
            if self.classify_access(pid, path, writing, is_dir, failed, status, label):
                break

    def classify_access(self, pid, path, writing, is_dir, failed, status, label):
        rel = self.home_rel(path)
        exe, _ = self.who(pid)
        base = posixpath.basename(exe)
        if rel is not None and rel in self.decoys:
            if rel == ".npmrc" and self.is_pkg_tool(pid) and not writing:
                return True
            if rel == ".gitconfig" and (base == "git" or self.is_pkg_tool(pid)) and not writing:
                return True
            if not failed:
                verb = "changed" if writing else "read"
                self.f.add("high", "bait", f"{verb} a bait secret: ~/{rel}", label)
            return True
        if any(under(path, p) for p in SANDBOX_PROBES):
            self.f.add("info", "sandbox-check", f"looked for signs of a VM or container: {path}", label)
            return True
        if under_any(path, SENSITIVE_SYSTEM):
            self.f.add("high", "secrets", f"opened {path}", label, status)
            return True
        if re.match(r"^/proc/\d+/(environ|mem)$", path):
            self.f.add("info", "secrets", "read a process's memory or environment (only sandbox processes are visible)", label, status, self.phase.get(pid, "run"))
            return True
        if rel is not None and rel and under_any(rel, SENSITIVE_HOME):
            if is_dir and not failed:
                self.f.add("high", "secrets", f"listed a secrets folder: ~/{rel}", label)
            elif not failed and not writing:
                self.f.add("high", "secrets", f"read ~/{rel}", label)
            elif writing:
                self.f.add("high", "persistence", f"wrote to ~/{rel}", label, status)
            return True
        if rel == "" and is_dir and not failed:
            self.f.add("medium", "secrets", "listed the home folder", label)
            return True
        if not writing:
            return False
        if rel is not None:
            if under_any(rel, PERSIST_HOME):
                self.f.add("high", "persistence", f"wrote to a startup location: ~/{rel}", label, status)
            elif under_any(rel, HOME_CACHES):
                return True
            elif under(rel, ".config"):
                self.f.add("info", "files", f"wrote app settings: ~/{rel}", label, status)
            else:
                self.f.add("medium", "files", f"wrote a file in the home folder: ~/{rel}", label, status)
            return True
        if under_any(path, WRITE_OK_SYSTEM):
            return True
        if under_any(path, PERSIST_SYSTEM):
            self.f.add("high", "persistence", f"tried to change system files: {path}", label, status)
        elif re.match(r"^/proc/\d+/", path):
            self.f.add("high", "tamper", f"tried to write into another process: {path}", label, status)
        else:
            self.f.add("medium", "files", f"wrote outside the project folder: {path}", label, status)
        return True

    def on_net(self, pid, name, body, status):
        label = self.label(pid)
        for rx in (IN4_RE, IN6_RE):
            for m in rx.finditer(body):
                port, ip = m.group(1), m.group(2)
                if port == "0" or name == "bind":
                    continue
                self.on_addr(norm_ip(ip), port, status, label)
        for m in UNIX_RE.finditer(body):
            if name == "bind":
                continue
            path = ("@" if m.group(1) else "") + text(m.group(2))
            self.on_unix(path, status, label)
        if name in ("sendto", "sendmsg", "sendmmsg"):
            seen = set()
            for s, _ in STRING_RE.findall(body):
                q = dns_query_name(c_unescape(s))
                if q and q not in seen:
                    seen.add(q)
                    self.on_dns(pid, q)

    def on_addr(self, addr, port, status, label):
        if addr is None:
            return
        where = f"{addr}:{port}" if addr.version == 4 else f"[{addr}]:{port}"
        if addr.is_loopback:
            if port != "53":
                self.f.add("info", "network", f"used a local port {where}", label)
            return
        if addr.is_unspecified or addr.is_multicast:
            return
        if addr.is_private or addr.is_link_local:
            self.f.add("medium", "network", f"tried to reach a local network address {where}", label, status)
            return
        if self.mode == "net":
            if port == "443" and any(addr in n for n in REGISTRY_NETS if n.version == addr.version):
                self.f.add("info", "network", f"connected to the npm registry (Cloudflare) {where}", label, status)
            else:
                self.f.add("medium", "network", f"connected to {where} during install", label, status)
            return
        self.f.add("high", "network", f"tried to connect to a hard-coded address {where}", label, status)

    def on_unix(self, path, status, label):
        p = path.lstrip("@")
        if "nscd" in p or p.startswith("/var/run/nscd") or p.startswith("/run/nscd"):
            return
        if re.search(r"docker\.sock|containerd|podman|libvirt|snapd\.socket|systemd/private", p):
            self.f.add("high", "local-service", f"tried to reach a privileged service: {path}", label, status)
        elif re.search(r"\.X11-unix|/bus$|dbus|wayland|pulse|pipewire|keyring|gcr|ssh-agent|gpg-agent|S\.gpg", p):
            self.f.add("medium", "local-service", f"tried to reach a desktop service: {path}", label, status)
        else:
            self.f.add("info", "local-service", f"used a local socket: {path}", label, status)

    def on_dns(self, pid, name):
        if any(name == d or name.endswith("." + d) for d in BAD_DNS):
            self.add(pid, "high", "dns", f"looked up {name}, a service often used to leak data or hide servers")
            return
        if self.mode == "net":
            if any(name == d or name.endswith("." + d) for d in NET_DNS_OK):
                self.add(pid, "info", "dns", f"looked up {name}")
            else:
                self.add(pid, "medium", "dns", f"looked up {name} during install")
            return
        if name in NONET_DNS_INFO or name.endswith(".local") or "." not in name:
            self.add(pid, "info", "dns", f"looked up {name} (no network in this run)")
        elif self.phase.get(pid, "run") in EARLY_PHASES:
            self.add(pid, "medium", "dns", f"looked up {name} while loading config or running install scripts")
        else:
            self.add(pid, "info", "dns", f"the app looked up {name} (no network in this run)")

    def on_change(self, pid, name, body, failed, status):
        label = self.label(pid)
        pairs = DIRFD_STR_RE.findall(body)
        if name in ("symlink", "symlinkat"):
            if len(pairs) < 2:
                return
            target = text(pairs[0][1])
            raw_link = text(pairs[-1][1])
            linkpath = self.resolve(text(pairs[-1][0]) if pairs[-1][0] else None, raw_link) or raw_link
            if target.startswith("/") and (self.home_rel(target) is not None or under_any(target, ("/etc", "/proc", "/run", "/dev", "/home"))):
                self.f.add("medium", "files", f"made a link to {target} at {linkpath}", label, status)
            pairs = pairs[-1:]
        paths = []
        for base, s in pairs:
            p = self.resolve(text(base) if base else None, text(s))
            if p:
                paths.append(p)
        if name == "fchmod":
            d = FD_DECOR_RE.search(body[len(name) + 1:])
            if d:
                paths.append(text(d.group(1)))
        exec_bit = False
        if name in ("chmod", "fchmod", "fchmodat"):
            mm = MODE_RE.search(body)
            exec_bit = bool(mm and int(mm.group(1), 8) & 0o111)
        for path in paths:
            rel = self.home_rel(path)
            if rel is not None and rel in self.decoys:
                if not failed:
                    self.f.add("high", "bait", f"{name} on a bait secret: ~/{rel}", label)
                continue
            if exec_bit and not failed and not under(path, "/work") and not under(path, "/tmp"):
                self.f.add("medium", "files", f"made a file executable: {path}", label)
            if exec_bit and not failed and under_any(path, ("/tmp", "/dev/shm")):
                self.f.add("medium", "files", f"made a temp file executable: {path}", label)
            if rel is not None:
                if under_any(rel, PERSIST_HOME) or under_any(rel, SENSITIVE_HOME):
                    self.f.add("high", "persistence", f"{name} in a startup or secrets location: ~/{rel}", label, status)
                continue
            if under_any(path, WRITE_OK_SYSTEM):
                continue
            if under_any(path, PERSIST_SYSTEM):
                self.f.add("high", "persistence", f"tried to change system files ({name}): {path}", label, status)


def read_lines(path):
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as fh:
        for line in fh:
            yield line.rstrip("\n")


def home_changes(path, decoys, findings):
    if not path.exists():
        return 0
    old, new = {}, {}
    for line in read_lines(path):
        if line[:2] not in ("< ", "> "):
            continue
        body = line[2:]
        if body.startswith("symlink  "):
            name = body[len("symlink  "):].split(" -> ")[0]
        else:
            parts = body.split("  ", 1)
            if len(parts) != 2:
                continue
            name = parts[1]
        name = name[2:] if name.startswith("./") else name
        (old if line[0] == "<" else new)[name] = body
    count = 0
    for name in sorted(set(old) | set(new)):
        if name in old and name in new:
            what = "changed"
        elif name in new:
            what = "added"
        else:
            what = "removed"
        count += 1
        if name in decoys:
            findings.add("high", "bait", f"bait secret {what}: ~/{name}")
        elif under_any(name, PERSIST_HOME) or under_any(name, SENSITIVE_HOME):
            findings.add("high", "persistence", f"file {what} in a startup or secrets location: ~/{name}")
        elif under(name, ".config"):
            findings.add("info", "files", f"app settings {what}: ~/{name}")
        else:
            findings.add("medium", "files", f"file {what} in the home folder: ~/{name}")
    return count


def read_small(path, default=""):
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return default


def analyze(box):
    box = Path(box)
    logs = box / "logs"
    meta = {}
    try:
        meta = json.loads((box / "meta.json").read_text())
    except (OSError, ValueError):
        pass
    fake_home = meta.get("fake_home") or DEFAULT_FAKE_HOME
    decoys = [d for d in read_small(box / "decoys.txt").splitlines() if d]
    runs = []
    for trace in sorted(logs.glob("*.trace")) if logs.is_dir() else []:
        tag = trace.stem
        mm = re.search(r"-(net|nonet)-", tag)
        mode = mm.group(1) if mm else "nonet"
        reader = TraceReader(fake_home, decoys, mode)
        for line in read_lines(trace):
            reader.feed(line)
        changed = home_changes(logs / f"{tag}.homediff", set(decoys), reader.f)
        status = read_small(logs / f"{tag}.status", "?")
        run = {
            "run": tag,
            "mode": mode,
            "command": read_small(logs / f"{tag}.cmd"),
            "time_limit_seconds": read_small(logs / f"{tag}.limit", "?"),
            "seconds": read_small(logs / f"{tag}.seconds", "?"),
            "exit_status": status,
            "timed_out": status == "124",
            "sandbox_started": reader.inner_started,
            "trace_lines": reader.lines,
            "programs": dict(reader.programs.most_common(25)),
            "fake_home_changes": changed,
            "output_file": str(logs / f"{tag}.out"),
            "trace_file": str(trace),
            "findings": reader.f.sorted()[: MAX_ITEMS * 3],
            "error": "" if reader.inner_started else "the sandbox did not start, so nothing ran",
        }
        runs.append(run)
    counts = Counter(f["severity"] for r in runs for f in r["findings"])
    if counts["high"]:
        verdict = "malicious-behaviour"
    elif not runs or any(r["error"] for r in runs):
        verdict = "error"
    elif counts["medium"]:
        verdict = "suspicious"
    else:
        verdict = "nothing-seen"
    return {"box": str(box), "fake_home": fake_home, "verdict": verdict, "counts": dict(counts), "runs": runs}


def render(result):
    out = [f"# Sandbox runs in {result['box']}", f"verdict: {result['verdict']}", ""]
    if not result["runs"]:
        out.append("No recordings found. Run box.sh first.")
    for r in result["runs"]:
        out.append(f"## {r['run']} ({r['mode']})")
        cmd = r["command"].replace("\n", " ")
        out.append(f"command: {cmd[:300]}{'...' if len(cmd) > 300 else ''}")
        extra = ", stopped by the time limit" if r["timed_out"] else ""
        out.append(f"exit: {r['exit_status']}{extra}; ran {r['seconds']}s of {r['time_limit_seconds']}s")
        if r["error"]:
            out.append(f"ERROR: {r['error']}")
        if r["programs"]:
            out.append("programs: " + ", ".join(f"{k} x{v}" for k, v in r["programs"].items()))
        if not r["findings"]:
            out.append("findings: none")
        for sev in SEVERITIES:
            items = [f for f in r["findings"] if f["severity"] == sev]
            if not items:
                continue
            out.append(f"{sev.upper()} ({len(items)})")
            for f in items[:MAX_ITEMS]:
                count = f" x{f['count']}" if f["count"] > 1 else ""
                by = f" | {f['phase']}" if f.get("phase") else ""
                by += f" | by {f['process']}" if f["process"] else ""
                detail = f" ({f['detail']})" if f["detail"] and f["detail"] != "ok" else ""
                out.append(f"  - {f['what']}{detail}{count}{by}")
            if len(items) > MAX_ITEMS:
                out.append(f"  ... and {len(items) - MAX_ITEMS} more")
        out.append(f"output: {r['output_file']}")
        out.append("")
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(prog="analyze.py", description="Summarise BaitBox sandbox recordings.")
    p.add_argument("box", help="box folder given to box.sh")
    p.add_argument("--json", action="store_true", help="print JSON")
    a = p.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    result = analyze(a.box)
    print(json.dumps(result, indent=2) if a.json else render(result))
    return {"nothing-seen": 0, "suspicious": 1, "malicious-behaviour": 2}.get(result["verdict"], 3)


if __name__ == "__main__":
    sys.exit(main())
