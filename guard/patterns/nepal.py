NEPAL_PATTERNS = {
    # Citizenship: e.g., 12-01-78-12345 (Separators are mandatory)
    "NP_CITIZENSHIP": r"\b\d{1,2}[-/\s]\d{1,2}[-/\s]\d{2,4}[-/\s]\d{4,5}\b",
    
    # NID: 10 digits, BUT ignores numbers starting with 96, 97, 98 (which are mobiles)
    "NP_NID": r"\b(?!9[678]\d{8})\d{10}\b",
    
    # PAN: 9 digits
    "NP_PAN": r"\b\d{9}\b",
    
    # Passport: e.g., M1234567 or PA1234567
    "NP_PASSPORT": r"\b(?:[A-Z]\d{7}|[A-Z]{2}\d{6,8})\b",
    
    # Mobile: +977 or 98/97/96 followed by 8 digits
    "NP_PHONE_MOBILE": r"\b(?:\+977[- ]?)?9[678]\d{8}\b",
    
    # Landline: e.g., 01XXXXXX
    "NP_PHONE_LANDLINE": r"\b0[1-9]\d{6,7}\b",
}
