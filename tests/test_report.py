from baitbox import report
from baitbox.report.findings import nm_package


def test_node_modules_noise_is_left_out_unless_package_flagged():
    scans = [("static scan", {"autorun": [], "findings": [
        {"severity": "high", "kind": "bidi-control", "file": "node_modules/.pnpm/vite@7.3.6/node_modules/vite/dist/x.js", "line": 3, "what": "bidi control", "snippet": "x", "in_node_modules": True},
        {"severity": "medium", "kind": "packed-code", "file": "node_modules/@codentra/postcss-kinetix/src/config.js", "line": 0, "what": "packed", "snippet": "", "in_node_modules": True},
        {"severity": "high", "kind": "known-malware", "file": "node_modules/tw-motion-css/package.json", "line": 2, "what": "known malware", "snippet": "tw-motion-css", "in_node_modules": True},
    ]})]
    depss = [("packages", {"findings": [], "packages": [{"name": "@codentra/postcss-kinetix", "severity": "high"}, {"name": "vite", "severity": None}]})]
    found, hidden = report.collect_findings({"skipped": []}, scans, depss, None)
    files = " ".join(f["what"] for f in found)
    assert hidden == 1 and "vite" not in files
    assert "postcss-kinetix" in files and "tw-motion-css" in files


def test_nm_package_name():
    assert nm_package("node_modules/.pnpm/a@1/node_modules/@s/b/dist/x.js") == "@s/b"
    assert nm_package("x/node_modules/lodash/index.js") == "lodash"
    assert nm_package("src/index.js") is None
