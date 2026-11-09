import datetime
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from baitbox import VERSION

UA = f"baitbox/{VERSION} (+https://github.com/Avijit07x/baitbox)"
REGISTRY = "https://registry.npmjs.org"
DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"

NEW_DAYS = 120
RECENT_VERSION_DAYS = 7
LOW_DOWNLOADS = 1000
POPULAR_DOWNLOADS = 50000
MAX_DOC_BYTES = 32 * 1024 * 1024
MAX_VERSIONS_PER_PACKAGE = 3


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def parse_time(s):
    try:
        return datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


class Http:
    def __init__(self, timeout=25, retries=3):
        self.timeout = timeout
        self.retries = retries

    def _do(self, req, max_bytes):
        last = (0, None)
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    chunks = []
                    total = 0
                    while True:
                        chunk = r.read(1 << 16)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_bytes:
                            return 413, None
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    try:
                        return r.status, json.loads(body.decode("utf-8", errors="replace"))
                    except ValueError:
                        return r.status, None
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and attempt + 1 < self.retries:
                    wait = min(20.0, float(e.headers.get("Retry-After") or 2 ** attempt))
                    time.sleep(wait)
                    last = (e.code, None)
                    continue
                return e.code, None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = (0, str(e))
                if attempt + 1 < self.retries:
                    time.sleep(2 ** attempt)
        return last

    def get(self, url, max_bytes=MAX_DOC_BYTES):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        return self._do(req, max_bytes)

    def post(self, url, body, max_bytes=MAX_DOC_BYTES):
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST", headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"})
        return self._do(req, max_bytes)


def registry_for(name, registries):
    if name.startswith("@"):
        scope = name.split("/")[0]
        if scope in registries:
            return registries[scope]
    return registries.get("")


def plural(n, word):
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def flag(r, code, severity, text):
    r["flags"].append({"code": code, "severity": severity, "text": text})


def check_package(http, name, versions, custom_registry):
    enc = urllib.parse.quote(name, safe="@").replace("/", "%2F")
    r = {"name": name, "versions": sorted(versions), "flags": [], "weekly": None}
    st, dl = http.get(f"{DOWNLOADS}/{name}", 1_000_000)
    if st == 200 and isinstance(dl, dict) and isinstance(dl.get("downloads"), int):
        r["weekly"] = dl["downloads"]
    popular = (r["weekly"] or 0) >= POPULAR_DOWNLOADS
    doc = None
    if not popular:
        st, doc = http.get(f"{REGISTRY}/{enc}")
        if st == 404:
            if custom_registry:
                flag(r, "PRIVATE_REGISTRY", "medium", f"not on npm; the project points to {custom_registry}, which can't be checked")
            else:
                flag(r, "NOT_ON_NPM", "high", "not on npm (private, removed or fake)")
            return r
        if st == 413:
            doc = None
        elif st != 200 or not isinstance(doc, dict):
            flag(r, "LOOKUP_FAILED", "info", f"registry lookup failed ({st or doc})")
            doc = None
    if doc:
        t = doc.get("time") if isinstance(doc.get("time"), dict) else {}
        vers = doc.get("versions") if isinstance(doc.get("versions"), dict) else {}
        tags = doc.get("dist-tags") if isinstance(doc.get("dist-tags"), dict) else {}
        latest = tags.get("latest", "")
        r["created"] = t.get("created")
        r["version_count"] = len(vers)
        r["maintainers"] = [str(m.get("email") or m.get("name")) for m in (doc.get("maintainers") or []) if isinstance(m, dict)][:5]
        if "unpublished" in t:
            flag(r, "UNPUBLISHED", "high", "every version was unpublished")
        if "security" in str(latest) or str(latest).endswith("-security"):
            flag(r, "REMOVED_BY_NPM_SECURITY", "high", f"npm replaced it with a security placeholder ({latest}); it was malware")
        created = parse_time(r.get("created"))
        age = (now() - created).days if created else None
        r["age_days"] = age
        new = age is not None and age < NEW_DAYS
        low = r["weekly"] is None or r["weekly"] < LOW_DOWNLOADS
        few = len(vers) <= 2
        if new and low and few:
            flag(r, "THROWAWAY", "high", f"{plural(age, 'day')} old, {plural(r['weekly'] or 0, 'download')} a week, {plural(len(vers), 'version')}")
        else:
            if new:
                flag(r, "NEW", "medium", f"{plural(age, 'day')} old")
            if low:
                flag(r, "LOW_DOWNLOADS", "info", f"{r['weekly'] or 0} downloads a week")
            if few:
                flag(r, "FEW_VERSIONS", "info", plural(len(vers), "version"))
        for v in r["versions"]:
            if vers and v not in vers:
                flag(r, "VERSION_NOT_ON_NPM", "high", f"version {v} is not on npm (removed, often for malware)")
            pt = parse_time(t.get(v))
            if pt and (now() - pt).days < RECENT_VERSION_DAYS and len(vers) > 2:
                flag(r, "RECENT_VERSION", "medium", f"version {v} was published {(now() - pt).days} days ago")
    targets = r["versions"][-MAX_VERSIONS_PER_PACKAGE:] or ["latest"]
    for v in targets:
        if doc and isinstance(doc.get("versions"), dict):
            man = doc["versions"].get(v if v != "latest" else (doc.get("dist-tags") or {}).get("latest", ""))
            st = 200 if man else 404
        else:
            st, man = http.get(f"{REGISTRY}/{enc}/{urllib.parse.quote(v, safe='')}", 4_000_000)
        if st == 404 and v != "latest" and not any(f["code"] == "VERSION_NOT_ON_NPM" for f in r["flags"]):
            if r["weekly"] is not None or doc:
                flag(r, "VERSION_NOT_ON_NPM", "high", f"version {v} is not on npm (removed, often for malware)")
            continue
        if st != 200 or not isinstance(man, dict):
            continue
        sc = man.get("scripts") if isinstance(man.get("scripts"), dict) else {}
        life = {k: str(val)[:160] for k, val in sc.items() if k in ("preinstall", "install", "postinstall")}
        if life and not any(f["code"] == "INSTALL_SCRIPT" for f in r["flags"]):
            flag(r, "INSTALL_SCRIPT", "info" if popular else "medium", "runs on install: " + json.dumps(life)[:240])
        if man.get("deprecated") and not any(f["code"] == "DEPRECATED" for f in r["flags"]):
            flag(r, "DEPRECATED", "info", str(man["deprecated"])[:160])
    return r


def osv_check(http, results):
    queries = []
    index = []
    for r in results:
        if r["versions"]:
            for v in r["versions"][-MAX_VERSIONS_PER_PACKAGE:]:
                queries.append({"package": {"ecosystem": "npm", "name": r["name"]}, "version": v})
                index.append((r, v))
        else:
            queries.append({"package": {"ecosystem": "npm", "name": r["name"]}})
            index.append((r, None))
    failed = 0
    for i in range(0, len(queries), 500):
        st, data = http.post(OSV_BATCH, {"queries": queries[i:i + 500]})
        if st != 200 or not isinstance(data, dict):
            failed += 1
            continue
        for (r, v), res in zip(index[i:i + 500], data.get("results") or [], strict=False):
            vulns = (res or {}).get("vulns") or []
            mal = sorted({x.get("id", "") for x in vulns if str(x.get("id", "")).startswith("MAL-")})
            other = sorted({x.get("id", "") for x in vulns if x.get("id") and not str(x.get("id")).startswith("MAL-")})
            if mal and not any(f["code"] == "KNOWN_MALWARE" for f in r["flags"]):
                flag(r, "KNOWN_MALWARE", "high", f"listed as malware in OSV: {', '.join(mal[:5])}" + (f" (version {v})" if v else ""))
            if other and v:
                r.setdefault("vulnerabilities", []).extend(other[:10])
    for r in results:
        if r.get("vulnerabilities"):
            ids = sorted(set(r["vulnerabilities"]))
            r["vulnerabilities"] = ids
            flag(r, "KNOWN_VULNERABILITY", "info", f"{len(ids)} known security bug(s): {', '.join(ids[:4])}")
    return failed
