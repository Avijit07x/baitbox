from collections import defaultdict

from baitbox import SEVERITIES
from baitbox.scan.rules import LIFECYCLE


def render(r):
    out = [f"# Static scan of {r['root']}"]
    st = r["stats"]
    out.append(
        f"files: {st.get('project files', 0)} in the project, {st.get('node_modules files', 0)} in node_modules "
        f"({st.get('packages in node_modules', 0)} packages)"
    )
    out.append("findings: " + ", ".join(f"{r['counts'][s]} {s}" for s in SEVERITIES))
    out.append("")
    out.append("## Files that can run code without you starting them")
    if not r["autorun"]:
        out.append("  none")
    for a in r["autorun"]:
        loads = f" | loads: {', '.join(a['loads'])}" if a["loads"] else ""
        out.append(f"  [{a['severity']}] {a['file']}: {a['why']}{loads}")
    if r["npmrc"]:
        out.append("")
        out.append("## Package manager settings (tokens masked)")
        for n in r["npmrc"]:
            out.append(f"  --- {n['file']}")
            out.extend(f"      {line}" for line in n["content"].splitlines()[:25])
    out.append("")
    out.append("## Project scripts")
    proj = [s for s in r["scripts"] if not s["in_node_modules"]]
    if not proj:
        out.append("  none")
    for s in proj:
        out.append(f"  --- {s['file']}")
        for k, v in s["scripts"].items():
            mark = " (runs on install)" if k in LIFECYCLE else ""
            out.append(f"     {k}{mark}: {v[:200]}")
    nm = [s for s in r["scripts"] if s["in_node_modules"]]
    if nm:
        out.append(f"  install scripts inside node_modules: {len(nm)}")
        for s in nm[:40]:
            out.append(f"     {s['file']}: " + "; ".join(f"{k}={v[:120]}" for k, v in s["scripts"].items()))
    by = defaultdict(list)
    for f in r["findings"]:
        by[f["severity"]].append(f)
    for sev in SEVERITIES:
        if not by[sev]:
            continue
        out.append("")
        out.append(f"## {sev.upper()} ({len(by[sev])})")
        for f in by[sev]:
            where = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            nm_tag = " [node_modules]" if f["in_node_modules"] else ""
            snip = f"  {f['snippet']}" if f["snippet"] else ""
            what = f["what"] if not f["snippet"] else f["kind"]
            out.append(f"  - {where}{nm_tag}: {what}{snip}")
    out.append("")
    out.append("Read every file under 'Files that can run code' before running anything.")
    return "\n".join(out)
