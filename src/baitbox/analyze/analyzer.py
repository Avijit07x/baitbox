import json
import re
from collections import Counter
from pathlib import Path

from baitbox.analyze.reader import TraceReader, under, under_any
from baitbox.analyze.rules import DEFAULT_FAKE_HOME, MAX_ITEMS, PERSIST_HOME, SENSITIVE_HOME


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
