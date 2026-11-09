from baitbox import SEVERITIES
from baitbox.analyze.rules import MAX_ITEMS


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
