import argparse
import json
import sys

from baitbox.scan import render, scan

HELP = "static scan only: baitbox scan <folder> [--json]"


def main(argv=None):
    p = argparse.ArgumentParser(prog="baitbox scan", description="Static scan of a project. Runs nothing.")
    p.add_argument("project", help="project folder")
    p.add_argument("--json", action="store_true", help="print JSON")
    a = p.parse_args(argv)
    try:
        r = scan(a.project)
    except NotADirectoryError:
        print(f"baitbox scan: not a folder: {a.project}", file=sys.stderr)
        return 2
    print(json.dumps(r, indent=2) if a.json else render(r))
    return 0
