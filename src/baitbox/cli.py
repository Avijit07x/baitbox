import argparse
import sys

from baitbox import VERSION
from baitbox.commands import analyze, box, check, deps, doctor, scan, selftest
from baitbox.console import say

COMMANDS = {"check": check, "doctor": doctor, "selftest": selftest}
TOOLS = {"scan": scan, "deps": deps, "analyze": analyze, "box": box}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    if argv and argv[0] in TOOLS:
        return TOOLS[argv[0]].main(argv[1:])
    p = argparse.ArgumentParser(prog="baitbox", description="Check a project for malware before you open it.")
    p.add_argument("--version", action="version", version=f"baitbox {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)
    for command in COMMANDS.values():
        command.add_parser(sub)
    for name, tool in TOOLS.items():
        sub.add_parser(name, help=tool.HELP)
    a = p.parse_args(argv)
    command = COMMANDS.get(a.cmd)
    return command.run(a, p) if command else 2


def run():
    try:
        return main()
    except KeyboardInterrupt:
        say("baitbox: stopped")
        return 130
