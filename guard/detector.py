import re
from guard.normalizer import normalize_digits
from guard.patterns.nepal import NEPAL_PATTERNS
from guard.patterns.india import INDIA_PATTERNS
from guard.patterns.global_ids import GLOBAL_PATTERNS

SEVERITY = {
    # Nepal
    "NP_CITIZENSHIP": "HIGH",
    "NP_NID": "HIGH",
    "NP_PAN": "HIGH",
    "NP_PASSPORT": "HIGH",
    "NP_PHONE_MOBILE": "MEDIUM",
    "NP_PHONE_LANDLINE": "LOW",
    # India
    "IN_AADHAAR": "HIGH",
    "IN_PAN": "HIGH",
    "IN_UPI": "MEDIUM",
    "IN_IFSC": "LOW",
    "IN_PHONE_MOBILE": "MEDIUM",
    # Global
    "CREDIT_CARD": "HIGH",
    "EMAIL": "LOW",
    "IPV4": "LOW",
}

ALL_PATTERNS = {**NEPAL_PATTERNS, **INDIA_PATTERNS, **GLOBAL_PATTERNS}

def scan_text(text: str) -> dict:
    normalized = normalize_digits(text)
    findings = []

    # 1. Run all patterns
    for name, pattern in ALL_PATTERNS.items():
        for match in re.finditer(pattern, normalized):
            findings.append({
                "type": name,
                "severity": SEVERITY.get(name, "LOW"),
                "start": match.start(),
                "end": match.end(),
            })

    # 2. Fix overlapping matches (e.g., keep the longest match)
    findings.sort(key=lambda x: (x["end"] - x["start"]), reverse=True)
    
    filtered = []
    for f in findings:
        overlap = False
        for existing in filtered:
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
