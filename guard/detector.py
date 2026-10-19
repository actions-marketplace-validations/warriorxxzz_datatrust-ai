import re
from guard.normalizer import normalize_digits
from guard.patterns.nepal import NEPAL_PATTERNS
from guard.patterns.global_ids import GLOBAL_PATTERNS

SEVERITY = {
    "NP_CITIZENSHIP": "HIGH",
    "NP_NID": "HIGH",
    "NP_PAN": "HIGH",
    "NP_PASSPORT": "HIGH",
    "CREDIT_CARD": "HIGH",
    "NP_PHONE_MOBILE": "MEDIUM",
    "NP_PHONE_LANDLINE": "LOW",
    "EMAIL": "LOW",
    "IPV4": "LOW",
}

ALL_PATTERNS = {**NEPAL_PATTERNS, **GLOBAL_PATTERNS}

def scan_text(text: str) -> dict:
    normalized = normalize_digits(text)
    findings = []

    # 1. Saare patterns run karo
    for name, pattern in ALL_PATTERNS.items():
        for match in re.finditer(pattern, normalized):
            findings.append({
                "type": name,
                "severity": SEVERITY.get(name, "LOW"),
                "start": match.start(),
                "end": match.end(),
            })

    # 2. Overlapping fixes: Sort by length (descending)
    findings.sort(key=lambda x: (x["end"] - x["start"]), reverse=True)
    
    filtered = []
    for f in findings:
        overlap = False
        for existing in filtered:
            # Check if the current finding overlaps with an already accepted finding
            if max(f["start"], existing["start"]) < min(f["end"], existing["end"]):
                overlap = True
                break
        if not overlap:
            filtered.append(f)

    # 3. Sort by start position for clean output
    filtered.sort(key=lambda x: x["start"])

    if any(f["severity"] == "HIGH" for f in filtered):
        risk = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in filtered):
        risk = "MEDIUM"
    elif filtered:
        risk = "LOW"
    else:
        risk = "NONE"

    return {"risk": risk, "findings": filtered}
