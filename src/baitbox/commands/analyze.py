import argparse
import json

from baitbox.analyze import analyze, render

HELP = "summarise sandbox recordings: baitbox analyze <box folder> [--json]"


def main(argv=None):
    p = argparse.ArgumentParser(prog="baitbox analyze", description="Summarise BaitBox sandbox recordings.")
    p.add_argument("box", help="box folder given to box.sh")
    p.add_argument("--json", action="store_true", help="print JSON")
    a = p.parse_args(argv)
    result = analyze(a.box)
    print(json.dumps(result, indent=2) if a.json else render(result))
    return {"nothing-seen": 0, "suspicious": 1, "malicious-behaviour": 2}.get(result["verdict"], 3)
