from baitbox.report.verdict import VERDICT_TEXT

LIMITS = (
    "Malware that waits longer than the run, or waits for a date, a login or a click.",
    "Malware that notices the sandbox and stays quiet.",
    "Code paths that need a real database, account, browser or network.",
    "Windows-only or Mac-only code, and non-Node projects: these get the static scan only.",
    "Sandbox escapes through kernel bugs. Use a VM for projects you have real doubts about.",
)


def render_report(rep):
    v = rep["verdict"]
    out = [f"# BaitBox report: {rep['name']}", ""]
    out.append(f"**Verdict: {VERDICT_TEXT[v]}**")
    out.append("")
    out.append(f"- Source: `{rep['source']}`")
    out.append(f"- Checked: {rep['checked_at']} with BaitBox {rep['version']}")
    out.append(f"- Project folder: `{rep['project_root']}`")
    c = rep["counts"]
    out.append(f"- Findings: {c.get('high', 0)} high, {c.get('medium', 0)} medium")
    if rep["errors"]:
        out.append("")
        out.append("## Errors")
        out.extend(f"- {e}" for e in rep["errors"])
    for sev in ("high", "medium"):
        items = [f for f in rep["findings"] if f["severity"] == sev]
        if not items:
            continue
        out.append("")
        out.append(f"## {sev.capitalize()} ({len(items)})")
        for f in items[:120]:
            out.append(f"- [{f['stage']}] {f['what']}")
        if len(items) > 120:
            out.append(f"- ... and {len(items) - 120} more in report.json")
    if rep["runs"]:
        out.append("")
        out.append("## What ran in the sandbox")
        for r in rep["runs"]:
            label = "Install (online, scripts off)" if r["mode"] == "net" else "Run (offline)"
            t = ", stopped by the time limit" if r.get("timed_out") else ""
            out.append(f"- {label}: exit {r['exit_status']}{t}, {r['seconds']}s. Programs: {', '.join(f'{k} x{n}' for k, n in list(r['programs'].items())[:12]) or 'none'}")
    if rep["notes"]:
        out.append("")
        out.append("## Notes")
        out.extend(f"- {n}" for n in rep["notes"])
    out.append("")
    out.append("## Not covered by this check")
    out.extend(f"- {x}" for x in LIMITS)
    out.append("")
    out.append("## Files")
    for k, p in rep["files"].items():
        out.append(f"- {k}: `{p}`")
    return "\n".join(out)
