import ast
from datatrust_ai.validators import calculate_shannon_entropy

KEYWORDS = ['password', 'secret', 'token', 'key', 'api_key', 'apikey', 'auth', 'credential', 'pwd']
IGNORE_VALUES = ['HIGH', 'MEDIUM', 'LOW', 'NONE', 'true', 'false', 'null']
DANGEROUS_FUNCS = ['eval', 'exec', 'os.system', 'pickle.loads', 'subprocess.call', 'subprocess.run', 'yaml.load']
WEAK_CRYPTO = ['md5', 'sha1', 'des', 'rc4']
SQL_EXEC_FUNCS = ['execute', 'executemany', 'raw']

def check_dict(node):
    findings = []
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            if any(key in k.value.lower() for key in KEYWORDS):
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    val = v.value
                    if len(val) > 8 and val not in IGNORE_VALUES and " " not in val.strip():
                        if calculate_shannon_entropy(val) > 3.5 or any(char.isdigit() for char in val):
                            findings.append((node.lineno, "AST_HARDCODED", k.value, val))
    return findings

def scan_ast(filepath: str):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read())
            
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(k in var_name for k in KEYWORDS):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                val = node.value.value
                                if len(val) > 3 and val not in IGNORE_VALUES:
                                    findings.append({"line": node.lineno, "type": "AST_HARDCODED", "var": target.id, "value": val})
            
            if isinstance(node, ast.Dict):
                dict_findings = check_dict(node)
                for line, ftype, key_name, val in dict_findings:
                    findings.append({"line": line, "type": ftype, "var": f"Dict Key '{key_name}'", "value": val})
            
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        func_name = f"{node.func.value.id}.{node.func.attr}"
                    elif isinstance(node.func.value, ast.Call):
                        func_name = node.func.attr
                    else:
                        func_name = node.func.attr
                
                if func_name in DANGEROUS_FUNCS:
                    findings.append({"line": node.lineno, "type": "DANGEROUS_FUNC", "var": func_name, "value": ""})
                    
                if any(wc == func_name.split('.')[-1].lower() for wc in WEAK_CRYPTO):
                    findings.append({"line": node.lineno, "type": "WEAK_CRYPTO", "var": func_name, "value": ""})
                    
                if any(sq in func_name.lower() for sq in SQL_EXEC_FUNCS):
                    if node.args:
                        arg = node.args[0]
                        if isinstance(arg, ast.BinOp):
                            findings.append({"line": node.lineno, "type": "SQL_INJECTION", "var": func_name, "value": ""})
                        elif isinstance(arg, ast.JoinedStr):
                            findings.append({"line": node.lineno, "type": "SQL_INJECTION", "var": func_name, "value": ""})
                        elif isinstance(arg, ast.Call) and getattr(arg.func, 'attr', '') == 'format':
                            findings.append({"line": node.lineno, "type": "SQL_INJECTION", "var": func_name, "value": ""})
                        
    except Exception:
        pass
    return findings
