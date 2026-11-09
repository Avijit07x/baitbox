import argparse
import json
import sys

from baitbox.deps import check, render

HELP = "package check only: baitbox deps <folder> [--json] [--offline]"


def main(argv=None):
    p = argparse.ArgumentParser(prog="baitbox deps", description="Check every npm package in a project against the registry and OSV.")
    p.add_argument("project", help="project folder")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--offline", action="store_true", help="list packages without network checks")
    p.add_argument("--workers", type=int, default=16, help="parallel registry requests (default 16)")
    a = p.parse_args(argv)
    try:
        r = check(a.project, offline=a.offline, workers=a.workers)
    except NotADirectoryError:
        print(f"baitbox deps: not a folder: {a.project}", file=sys.stderr)
        return 2
    print(json.dumps(r, indent=2) if a.json else render(r))
    return 0
