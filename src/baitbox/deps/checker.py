import concurrent.futures
from collections import Counter

from baitbox import SEVERITIES
from baitbox.deps.collector import Collector
from baitbox.deps.lookalike import flag_lookalikes
from baitbox.deps.registry import Http, check_package, osv_check, registry_for


def severity_of(r):
    if not r["flags"]:
        return None
    return min((f["severity"] for f in r["flags"]), key=SEVERITIES.index)


def check(root, offline=False, workers=16, http=None):
    c = Collector(root)
    if not c.root.is_dir():
        raise NotADirectoryError(str(root))
    c.walk()
    names = sorted(n for n in c.packages if n not in c.local)
    results = []
    osv_failed = 0
    if not offline:
        http = http or Http()
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            futs = [ex.submit(check_package, http, n, c.packages[n], registry_for(n, c.registries)) for n in names]
            for f in futs:
                results.append(f.result())
        osv_failed = osv_check(http, results)
    else:
        results = [{"name": n, "versions": sorted(c.packages[n]), "flags": [], "weekly": None} for n in names]
    lookalikes = flag_lookalikes(results)
    for r in results:
        r["direct"] = r["name"] in c.direct
        r["severity"] = severity_of(r)
    extras = []
    if c.lock_names and c.nm_top_names:
        extras = sorted(n for n in c.nm_top_names - c.lock_names - c.local - c.aliases if n not in c.direct)[:100]
    findings = []
    for s in c.sources:
        findings.append({"severity": s["severity"], "kind": "non-registry-source", "what": f"{s['name']}: {s['kind']} {s['source']}", "file": s["origin"]})
    for i in c.invalid:
        findings.append({"severity": "high", "kind": "invalid-name", "what": f"invalid package name {i['name']!r}", "file": i["origin"]})
    for m in c.mismatch:
        findings.append({"severity": "medium", "kind": "name-mismatch", "what": f"folder {m['folder']} holds a package named {m['name']}", "file": m["folder"]})
    for n in extras:
        findings.append({"severity": "medium", "kind": "not-in-lockfile", "what": f"{n} is in node_modules but not in any lockfile", "file": "node_modules"})
    for r in results:
        for f in r["flags"]:
            findings.append({"severity": f["severity"], "kind": f["code"].lower().replace("_", "-"), "what": f"{r['name']}: {f['text']}", "file": "direct dependency" if r["direct"] else "nested dependency"})
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f["severity"]], f["kind"], f["what"]))
    counts = Counter(f["severity"] for f in findings)
    notes = list(c.notes)
    failed = sum(1 for r in results if any(f["code"] == "LOOKUP_FAILED" for f in r["flags"]))
    if failed:
        notes.append(f"{failed} registry lookups failed; run again before trusting the package list")
    if osv_failed:
        notes.append("the OSV malware database could not be reached; known-malware checks are incomplete")
    if offline:
        notes.append("offline mode: packages were listed but not checked against npm or OSV")
    if not c.lockfiles:
        notes.append("no lockfile found; nested packages are only known after an install")
    return {
        "root": str(c.root), "offline": offline, "lockfiles": c.lockfiles, "registries": c.registries,
        "direct_count": len(c.direct), "package_count": len(names), "local_packages": sorted(c.local),
        "counts": {s: counts.get(s, 0) for s in SEVERITIES}, "findings": findings,
        "packages": sorted(results, key=lambda r: (order.get(r["severity"] or "zz", 9), r["name"])),
        "lookalikes": lookalikes, "notes": notes,
    }
