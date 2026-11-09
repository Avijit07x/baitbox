import os

from baitbox import SEVERITIES

MALWARE_KINDS = {"known-malware", "removed-by-npm-security"}


def nm_package(path):
    p = path.replace(os.sep, "/")
    i = p.rfind("node_modules/")
    if i == -1:
        return None
    parts = p[i + len("node_modules/"):].split("/")
    if parts[0].startswith("@") and len(parts) > 1:
        return f"{parts[0]}/{parts[1]}"
    return parts[0] or None


def flagged_packages(depss):
    names = set()
    for _, d in depss:
        for pk in d["packages"]:
            if pk.get("severity") in ("high", "medium"):
                names.add(pk["name"])
        for f in d["findings"]:
            if f["severity"] in ("high", "medium") and f["kind"] in ("non-registry-source", "name-mismatch", "not-in-lockfile"):
                names.add(f["what"].split(":")[0].split(" ")[0])
    return names


def collect_findings(intake_info, scans, depss, analysis):
    found = []
    flagged = flagged_packages(depss)
    hidden = 0
    for s in intake_info.get("skipped", []):
        found.append({"stage": "unpack", "severity": s["severity"], "kind": "unpack", "what": f"{s['path']}: {s['reason']}"})
    seen = set()
    for label, sres in scans:
        for a in sres["autorun"]:
            if a["severity"] == "info":
                continue
            key = ("autorun", a["file"], a["why"])
            if key in seen:
                continue
            seen.add(key)
            loads = f" (loads {', '.join(a['loads'])})" if a["loads"] else ""
            found.append({"stage": label, "severity": a["severity"], "kind": "runs-code", "what": f"{a['file']}: {a['why']}{loads}"})
        for f in sres["findings"]:
            if f["severity"] == "info":
                continue
            if f["in_node_modules"] and f["kind"] not in MALWARE_KINDS and nm_package(f["file"]) not in flagged:
                hidden += 1
                continue
            where = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            key = ("scan", f["kind"], where)
            if key in seen:
                continue
            seen.add(key)
            snip = f" | {f['snippet'][:160]}" if f["snippet"] else ""
            found.append({"stage": label, "severity": f["severity"], "kind": f["kind"], "what": f"{where}: {f['what']}{snip}"})
    for label, dres in depss:
        for f in dres["findings"]:
            if f["severity"] == "info":
                continue
            key = ("deps", f["kind"], f["what"])
            if key in seen:
                continue
            seen.add(key)
            found.append({"stage": label, "severity": f["severity"], "kind": f["kind"], "what": f["what"]})
    if analysis:
        for r in analysis["runs"]:
            stage = "sandbox install" if r["mode"] == "net" else "sandbox run"
            for f in r["findings"]:
                if f["severity"] == "info":
                    continue
                phase = f.get("phase") or ""
                stage_label = f"{stage}: {phase}" if phase and phase not in ("run", "install") else stage
                by = f" | by {f['process']}" if f["process"] else ""
                cnt = f" (x{f['count']})" if f["count"] > 1 else ""
                found.append({"stage": stage_label, "severity": f["severity"], "kind": f["kind"], "what": f"{f['what']}{cnt}{by}"})
    order = {s: i for i, s in enumerate(SEVERITIES)}
    found.sort(key=lambda f: order[f["severity"]])
    return found, hidden
