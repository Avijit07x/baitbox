from baitbox import SEVERITIES


def render(r):
    out = [f"# Package check for {r['root']}"]
    out.append(f"direct dependencies: {r['direct_count']}, packages checked: {r['package_count']}, lockfiles: {', '.join(r['lockfiles']) or 'none'}")
    if r["registries"]:
        out.append("custom registries: " + ", ".join(f"{k or 'default'}={v}" for k, v in r["registries"].items()))
    out.append("findings: " + ", ".join(f"{r['counts'][s]} {s}" for s in SEVERITIES))
    for sev in SEVERITIES:
        items = [f for f in r["findings"] if f["severity"] == sev]
        if not items:
            continue
        out.append("")
        out.append(f"## {sev.upper()} ({len(items)})")
        for f in items[:150]:
            out.append(f"  - {f['what']} [{f['file']}]")
        if len(items) > 150:
            out.append(f"  ... and {len(items) - 150} more")
    risky = [p for p in r["packages"] if p["severity"] in ("high", "medium")]
    if risky:
        out.append("")
        out.append("## Details for risky packages")
        for p in risky[:60]:
            bits = []
            if p.get("created"):
                bits.append(f"created {p['created'][:10]}")
            if p.get("weekly") is not None:
                bits.append(f"{p['weekly']}/week")
            if p.get("version_count") is not None:
                bits.append(f"{p['version_count']} versions")
            if p.get("maintainers"):
                bits.append("by " + ", ".join(p["maintainers"]))
            if p["versions"]:
                bits.append("installs " + ", ".join(p["versions"]))
            tag = "direct" if p["direct"] else "nested"
            out.append(f"  {p['name']} [{tag}]: " + "; ".join(bits))
    for n in r["notes"]:
        out.append(f"note: {n}")
    return "\n".join(out)
