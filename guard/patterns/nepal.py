NEPAL_PATTERNS = {
    
    "NP_CITIZENSHIP": r"\b\d{1,2}[-/\s]\d{1,2}[-/\s]\d{2,4}[-/\s]\d{4,5}\b",
    "NP_NID": r"\b\d{10}\b",
    "NP_PAN": r"\b\d{9}\b",
    "NP_PASSPORT": r"\b(?:[A-Z]\d{7}|[A-Z]{2}\d{6,8})\b",
    "NP_PHONE_MOBILE": r"\b(?:\+977[- ]?)?9[678]\d{8}\b",
    "NP_PHONE_LANDLINE": r"\b0[1-9]\d{6,7}\b",
}
