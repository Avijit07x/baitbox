import shutil
import subprocess
import sys
from pathlib import Path


def add_parser(sub):
    sub.add_parser("doctor", help="check that this machine can run the sandbox")


def probe(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)


def first_line(s):
    return s.splitlines()[0] if s else ""


def run(_a, _parser):
    rows = []

    def row(name, ok, detail, fix="", required=True):
        rows.append((name, ok, detail, fix, required))

    row("python 3.10+", sys.version_info >= (3, 10), sys.version.split()[0], "install Python 3.10 or newer")
    for tool, fix in (("bwrap", "sudo apt install bubblewrap"), ("strace", "sudo apt install strace")):
        path = shutil.which(tool)
        ok, outp = probe([tool, "--version"]) if path else (False, "")
        row(tool, bool(path), first_line(outp) or "not installed", fix)
    for tool in ("timeout", "sha256sum", "realpath", "find", "diff"):
        row(tool, bool(shutil.which(tool)), "found" if shutil.which(tool) else "not installed", "install coreutils, findutils and diffutils")
    node = shutil.which("node")
    ok, outp = probe(["node", "--version"]) if node else (False, "")
    row("node", bool(node), outp or "not installed", "install Node.js 18 or newer")
    row("npm", bool(shutil.which("npm")), "found" if shutil.which("npm") else "not installed", "install npm")
    row("git", bool(shutil.which("git")), "found" if shutil.which("git") else "not installed", "needed only for git links", False)
    row("pnpm", bool(shutil.which("pnpm")), "found" if shutil.which("pnpm") else "not installed (npm is used instead)", "", False)
    if shutil.which("bwrap"):
        ok, outp = probe(["bwrap", "--ro-bind", "/", "/", "--unshare-all", "--die-with-parent", "true"])
        hint = "unprivileged user namespaces are blocked"
        sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        if sysctl.exists() and sysctl.read_text().strip() == "1":
            hint += "; AppArmor blocks them: see the README troubleshooting section"
        row("sandbox starts", ok, "ok" if ok else first_line(outp), hint)
    ys = Path("/proc/sys/kernel/yama/ptrace_scope")
    scope = ys.read_text().strip() if ys.exists() else "0"
    if scope == "2":
        row("ptrace allowed", True, "kernel.yama.ptrace_scope=2: each run asks for your sudo password and sets it to 1 until the run ends")
    else:
        row("ptrace allowed", scope in ("0", "1"), f"kernel.yama.ptrace_scope={scope}", "strace needs ptrace_scope 0, 1 or 2; 3 turns ptrace off until reboot")
    if shutil.which("bwrap") and shutil.which("strace") and scope in ("0", "1"):
        ok, outp = probe(["strace", "-f", "-o", "/dev/null", "bwrap", "--ro-bind", "/", "/", "--unshare-all", "--die-with-parent", "true"])
        row("strace can follow the sandbox", ok, "ok" if ok else first_line(outp), "bwrap may be setuid on this system; BaitBox needs the non-setuid build")
    width = max(len(r[0]) for r in rows)
    bad = 0
    for name, ok, detail, fix, required in rows:
        mark = "ok  " if ok else ("FAIL" if required else "warn")
        print(f"{mark}  {name.ljust(width)}  {detail}")
        if not ok and fix:
            print(f"      {' ' * width}  fix: {fix}")
        if not ok and required:
            bad += 1
    print()
    print("Ready." if not bad else f"{bad} required check(s) failed.")
    return 0 if not bad else 1
