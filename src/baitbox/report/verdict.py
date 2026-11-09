from baitbox.report.findings import MALWARE_KINDS

EXIT_CODES = {"nothing-seen": 0, "review": 0, "suspicious": 1, "malicious": 2, "error": 3}
VERDICT_TEXT = {
    "malicious": "Malware found. Do not open or run this project.",
    "suspicious": "Suspicious. Do not run it until you have read the findings.",
    "review": "Nothing bad happened when it ran, but some files need a look before you trust it.",
    "nothing-seen": "Nothing bad was seen. That is not proof that it is safe.",
    "error": "The check did not finish. Treat the project as unchecked.",
}


def decide(findings, scans, depss, analysis, errors):
    malware = []
    for _, s in scans:
        malware += [f for f in s["findings"] if f["kind"] in MALWARE_KINDS]
    for _, d in depss:
        malware += [f for f in d["findings"] if f["kind"] in MALWARE_KINDS]
    if analysis and analysis["verdict"] == "malicious-behaviour":
        return "malicious"
    if malware:
        return "malicious"
    if errors:
        return "error"
    sandbox = [f for f in findings if f["stage"].startswith("sandbox")]
    if any(f["severity"] == "high" for f in findings) or any(f["severity"] == "medium" for f in sandbox):
        return "suspicious"
    if any(f["severity"] == "medium" for f in findings):
        return "review"
    return "nothing-seen"
