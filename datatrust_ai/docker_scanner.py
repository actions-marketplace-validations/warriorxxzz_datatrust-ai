import re

def scan_dockerfile(filepath: str):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                continue
                
            if re.match(r'(?i)^USER\s+root', line_stripped):
                findings.append({"line": line_num, "type": "DOCKER_ROOT_USER", "value": line_stripped})
                
            if re.match(r'(?i)^(ENV|ARG)\s+.*(PASSWORD|SECRET|TOKEN|KEY)=', line_stripped):
                findings.append({"line": line_num, "type": "DOCKER_HARDCODED_SECRET", "value": line_stripped})
                
            if re.match(r'(?i)^ADD\s+', line_stripped):
                findings.append({"line": line_num, "type": "DOCKER_ADD_USAGE", "value": line_stripped})
                
    except Exception:
        pass
    return findings
