import re

def scan_iac(filepath: str):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                continue
                
            if re.search(r'(?i)privileged\s*:\s*true', line_stripped):
                findings.append({"line": line_num, "type": "K8S_PRIVILEGED", "value": line_stripped})
                
            if re.search(r'(?i)allowPrivilegeEscalation\s*:\s*true', line_stripped):
                findings.append({"line": line_num, "type": "K8S_PRIV_ESC", "value": line_stripped})
                
            if re.search(r'(?i)(password|secret|token|key)\s*:\s*["\']?[a-zA-Z0-9_\-]{8,}["\']?', line_stripped):
                if "valueFrom" not in line_stripped and "secretKeyRef" not in line_stripped:
                    findings.append({"line": line_num, "type": "K8S_HARDCODED_SECRET", "value": line_stripped})
                    
    except Exception:
        pass
    return findings
