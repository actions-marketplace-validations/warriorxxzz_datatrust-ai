import sys
import os
import json
import argparse
import concurrent.futures
import subprocess
import re
import requests
import webbrowser
import yaml
import xml.etree.ElementTree as ET
import sqlite3
import hashlib
import fnmatch
from datetime import datetime
from http.server import os.getenv('DATATRUST_HIGH_ENTROPY_15'), HTTPServer
from functools import partial
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.box import ROUNDED
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt
from datatrust_ai.detector import scan_text
from datatrust_ai.ast_scanner import scan_ast
from datatrust_ai.docker_scanner import scan_dockerfile
from datatrust_ai.iac_scanner import scan_iac
from datatrust_ai.plugin_manager import load_custom_plugins

console = Console()

BANNER = r"""
[bold #a29bfe]
  ____        _        _____               _     _      _    ___ 
 |  _ \  __ _| |_ __ _|_   _| _ __ _   _ ___| |_  / \  |_ _|
 | | | |/ _` | __/ _` | | || '__| | | / __| __| / _ \  | |
 | |_| | (_| | || (_| | | || |  | |_| \__ \ |_ / ___ \ | |
 |____/ \__,_|\__\__,_| |_||_|   \__,_|___/\__/_/   \_\___|
[/bold #a29bfe]
[italic #81ecec]Ultimate Enterprise Security Platform | v2.4.1 Final[/italic #81ecec]
"""

FRIENDLY_NAMES = {
    "NP_CITIZENSHIP": "Nepal Citizenship Number", "NP_NID": "National ID (NID)",
    "NP_PAN": "Nepal PAN Number", "NP_PASSPORT": "Nepal Passport Number",
    "NP_PHONE_MOBILE": "Nepal Mobile Number", "NP_PHONE_LANDLINE": "Nepal Landline Number",
    "IN_AADHAAR": "India Aadhaar Number", "IN_PAN": "India PAN Card",
    "IN_UPI": "India UPI ID", "IN_IFSC": "India IFSC Code", "IN_PHONE_MOBILE": "India Mobile Number",
    "CREDIT_CARD": "Credit Card Number", "AWS_KEY": "AWS Access Key",
    "OPENAI_KEY": "OpenAI API Key", "GITHUB_PAT": "GitHub Personal Access Token",
    "GOOGLE_API": "Google API Key", "PRIVATE_KEY": "SSH/RSA Private Key",
    "EMAIL": "Email Address", "IPV4": "IP Address", "HIGH_ENTROPY": "High Entropy Secret/Password",
    "AST_HARDCODED": "AST: Hardcoded Secret", "DANGEROUS_FUNC": "SAST: Dangerous Function",
    "WEAK_CRYPTO": "SAST: Weak Cryptography", "SQL_INJECTION": "SAST: SQL Injection Risk",
    "PROMPT_INJECTION": "AI Prompt Injection Attempt",
    "DOCKER_ROOT_USER": "Docker: Running as Root", "DOCKER_HARDCODED_SECRET": "Docker: Hardcoded Secret",
    "DOCKER_ADD_USAGE": "Docker: ADD instead of COPY",
    "K8S_PRIVILEGED": "K8s: Privileged Mode Enabled", "K8S_PRIV_ESC": "K8s: Privilege Escalation",
    "K8S_HARDCODED_SECRET": "K8s: Hardcoded Secret in YAML",
    "BASE64_AWS_KEY": "Base64 AWS Key", "BASE64_HIGH_ENTROPY": "Base64 Secret"
}

DEFAULT_IGNORES = ['.git', 'venv', 'env', '__pycache__', 'node_modules', 'dist', 'build', '.github', 'custom_rules.json', 'datatrust.sarif', '.egg-info', 'datatrust_report.html', 'datatrust.yml', '.datatrust.db', 'extension']
global_stats = {"files": 0, "findings": 0, "fixed": 0, "high": 0, "medium": 0}
all_findings = []
global_risk_found = False
config = {}
custom_plugins = []

def show_help():
    console.print(BANNER)
    console.print(Panel("[bold white]DataTrust AI - Complete Command Reference[/bold white]", box=ROUNDED, border_style="dim cyan"))
    
    table = Table(box=ROUNDED, show_header=True, header_style="bold #a29bfe")
    table.add_column("Category", style="bold #81ecec", width=12)
    table.add_column("Command", style="bold white", width=20)
    table.add_column("Description", style="white", width=35)

    table.add_row("Scanning", "datatrust \"text\"", "Scan a raw string.")
    table.add_row("Scanning", "datatrust -f <file>", "Scan a specific file.")
    table.add_row("Scanning", "datatrust -d <dir>", "Scan an entire directory.")
    table.add_row("Scanning", "datatrust --staged", "Scan only Git staged files.")
    
    table.add_row("Remediation", "datatrust -d . --fix", "Auto-fix secrets, Docker, and K8s issues.")
    table.add_row("Remediation", "datatrust -d . --fix --dry-run", "Simulate fixes.")
    
    table.add_row("Automation", "datatrust --automate", "Setup Git pre-commit hooks & GitHub Actions.")
    table.add_row("Automation", "datatrust --enable-plugins", "Enable custom plugins in datatrust_plugins.")
    
    table.add_row("CI/CD", "datatrust -d . --gh-actions", "Output errors in GitHub Actions format.")
    table.add_row("CI/CD", "datatrust -d . --sarif", "Generate SARIF report.")
    table.add_row("CI/CD", "datatrust --sbom", "Generate CycloneDX SBOM.")
    table.add_row("CI/CD", "datatrust --sca", "Scan dependencies for vulnerabilities.")
    table.add_row("CI/CD", "datatrust --license-check", "Check dependencies for restrictive licenses.")
    table.add_row("CI/CD", "datatrust --report-md", "Generate Markdown report for PR comments.")
    
    table.add_row("Utilities", "datatrust --serve", "Start a secure local web dashboard.")
    table.add_row("Utilities", "datatrust --stats", "View historical scan stats.")
    
    console.print(table)
    console.print("\n[italic #81ecec]Tip: Add # datatrust:ignore at the end of any line to skip it.[/italic #81ecec]\n")

def interactive_menu():
    global global_stats, all_findings, global_risk_found
    while True:
        console.print(BANNER)
        console.print(Panel("[bold white]Interactive Menu[/bold white]", box=ROUNDED, border_style="dim cyan"))
        console.print("[bold #81ecec]1.[/bold #81ecec] Scan Entire Directory (Current Folder)")
        console.print("[bold #81ecec]2.[/bold #81ecec] Scan Specific File")
        console.print("[bold #81ecec]3.[/bold #81ecec] Scan Raw Text")
        console.print("[bold #81ecec]4.[/bold #81ecec] Auto-Fix Current Directory")
        console.print("[bold #81ecec]5.[/bold #81ecec] Setup CI/CD Automation (Git Hooks)")
        console.print("[bold #81ecec]6.[/bold #81ecec] View Historical Stats")
        console.print("[bold #ff7675]7.[/bold #ff7675] Exit\n")

        choice = Prompt.ask("[bold white]Select an option[/bold white]", choices=["1", "2", "3", "4", "5", "6", "7"], default="1")

        if choice == "1":
            global_stats = {"files": 0, "findings": 0, "fixed": 0, "high": 0, "medium": 0}
            all_findings = []
            global_risk_found = False
            scan_directory(".", False, False, False)
            print_summary()
            display_results_table()
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]", default="")
        elif choice == "2":
            filepath = Prompt.ask("[bold white]Enter file path[/bold white]")
            if os.path.exists(filepath):
                global_stats = {"files": 1, "findings": 0, "fixed": 0, "high": 0, "medium": 0}
                all_findings = []
                global_risk_found = False
                task = (filepath, False, False, 1, False)
                _, findings, stats = process_file_worker(task)
                all_findings.extend(findings)
                for k in global_stats: global_stats[k] += stats[k]
                global_risk_found = any(not f["fixed"] for f in all_findings)
                print_summary()
                display_results_table()
            else:
                console.print("[bold #ff7675]File not found![/bold #ff7675]")
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]", default="")
        elif choice == "3":
            text = Prompt.ask("[bold white]Enter text to scan[/bold white]")
            global_stats = {"files": 1, "findings": 0, "fixed": 0, "high": 0, "medium": 0}
            all_findings = []
            global_risk_found = False
            result = scan_text(text, include_value=True)
            if result["risk"] != "NONE":
                global_risk_found = True
                for item in result["findings"]:
                    all_findings.append({"file": "Input", "line": "-", "type": FRIENDLY_NAMES.get(item['type']), "severity": item["severity"], "value": item.get("value", ""), "fixed": False})
                display_results_table()
            else:
                console.print("\n[bold #55efc4]✅ Safe. No sensitive info detected.[/bold #55efc4]")
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]", default="")
        elif choice == "4":
            global_stats = {"files": 0, "findings": 0, "fixed": 0, "high": 0, "medium": 0}
            all_findings = []
            global_risk_found = False
            scan_directory(".", True, False, False)
            print_summary()
            display_results_table()
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]", default="")
        elif choice == "5":
            hook_dir = ".git/hooks"
            if os.path.exists(hook_dir):
                with open(os.path.join(hook_dir, "pre-commit"), "w") as f:
                    f.write("#!/bin/sh\necho \"🛡️ Running DataTrust AI Pre-commit...\"\ndatatrust --staged\nif [ $? -ne 0 ]; then\n echo \"🛑 Commit blocked! Sensitive info detected.\"\n exit 1\nfi\n")
                os.chmod(os.path.join(hook_dir, "pre-commit"), 0o755)
                console.print("[bold #55efc4]✔ Automation setup complete.[/bold #55efc4]")
            else:
                console.print("[bold #ff7675]Not a git repository. Cannot setup hooks.[/bold #ff7675]")
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")
        elif choice == "6":
            show_stats()
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]", default="")
        elif choice == "7":
            console.print("[bold #81ecec]Goodbye! Stay Secure. 🛡️[/bold #81ecec]")
            break

def init_db():
    conn = sqlite3.connect('.datatrust.db')
    conn.execute('CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, timestamp TEXT, files INTEGER, findings INTEGER, high INTEGER, score INTEGER)')
    conn.execute('CREATE TABLE IF NOT EXISTS cache (filepath TEXT PRIMARY KEY, filehash TEXT)')
    conn.commit()
    conn.close()

def get_file_hash(filepath):
    hasher = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()
    except Exception:
        return ""

def is_cached(filepath, filehash):
    conn = sqlite3.connect('.datatrust.db')
    cur = conn.cursor()
    cur.execute("SELECT filehash FROM cache WHERE filepath=?", (filepath,))
    row = cur.fetchone()
    conn.close()
    return row and row[0] == filehash

def update_cache(filepath, filehash):
    conn = sqlite3.connect('.datatrust.db')
    conn.execute("INSERT OR REPLACE INTO cache (filepath, filehash) VALUES (?, ?)", (filepath, filehash))
    conn.commit()
    conn.close()

def save_to_db():
    score, _ = calculate_security_score()
    conn = sqlite3.connect('.datatrust.db')
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("INSERT INTO scans (timestamp, files, findings, high, score) VALUES (?, ?, ?, ?, ?)",
                 (now, global_stats["files"], global_stats["findings"], global_stats["high"], score))
    conn.commit()
    conn.close()

def show_stats():
    conn = sqlite3.connect('.datatrust.db')
    rows = conn.execute("SELECT timestamp, files, findings, high, score FROM scans ORDER BY id DESC LIMIT 10").fetchall()
    conn.close()
    table = Table(title="[bold white]Historical Stats[/bold white]", box=ROUNDED)
    table.add_column("Time", style="#a29bfe")
    table.add_column("Files")
    table.add_column("Findings")
    table.add_column("High Risk")
    table.add_column("Score")
    for r in rows:
        table.add_row(r[0], str(r[1]), str(r[2]), str(r[3]), f"{r[4]}/100")
    console.print(table)

def load_config():
    global config
    if os.path.exists('datatrust.yml'):
        try:
            with open('datatrust.yml', 'r') as f:
                config = yaml.safe_load(f) or {}
        except Exception:
            pass

def load_ignore_patterns():
    patterns = set(DEFAULT_IGNORES)
    if 'ignore_paths' in config:
        patterns.update(config['ignore_paths'])
    if os.path.exists('.datatrustignore'):
        with open('.datatrustignore', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    patterns.add(line)
    return patterns

def is_ignored(filepath, patterns):
    for p in patterns:
        if fnmatch.fnmatch(filepath, f"*{p}*") or fnmatch.fnmatch(filepath, f"*/{p}/*") or filepath.startswith(p):
            return True
    return False

def mask_secret(val: str) -> str:
    return val[:3] + "•" * (len(val) - 6) + val[-3:] if len(val) > 6 else "••••"

def calculate_security_score():
    remaining_high = len([f for f in all_findings if f['severity'] == 'HIGH' and not f.get('fixed')])
    remaining_med = len([f for f in all_findings if f['severity'] == 'MEDIUM' and not f.get('fixed')])
    score = max(0, 100 - (remaining_high * 10) - (remaining_med * 5))

    if score >= 90: grade = "[bold #55efc4]A[/bold #55efc4]"
    elif score >= 80: grade = "[bold #81ecec]B[/bold #81ecec]"
    elif score >= 70: grade = "[bold #fdcb6e]C[/bold #fdcb6e]"
    else: grade = "[bold #ff7675]F[/bold #ff7675]"
    return score, grade

def process_file_worker(args):
    filepath, fix_mode, gh_mode, min_severity, dry_run = args
    ignores = load_ignore_patterns()

    if is_ignored(filepath, ignores):
        return filepath, [], {"files": 0, "findings": 0, "high": 0, "medium": 0, "fixed": 0}

    findings = []
    stats = {"files": 1, "findings": 0, "high": 0, "medium": 0, "fixed": 0}

    if not filepath.endswith(('.py', '.txt', '.env', '.json', '.js', '.md', '.yaml', '.yml', '.csv', '.sh', '.xml', '.html', '.toml', '.ini', '.cfg', 'Dockerfile', '.dockerfile')):
        return filepath, findings, stats

    try:
        if filepath.endswith('.py'):
            for af in scan_ast(filepath):
                findings.append({"file": filepath, "line": af["line"], "type": FRIENDLY_NAMES.get(af["type"]), "severity": "HIGH", "value": af["value"], "fixed": False})
                stats["findings"] += 1
                stats["high"] += 1
                if gh_mode: print(f"::error file={filepath},line={af['line']}::{af['type']}")

        if filepath.endswith(('Dockerfile', '.dockerfile')):
            for df in scan_dockerfile(filepath):
                findings.append({"file": filepath, "line": df["line"], "type": FRIENDLY_NAMES.get(df["type"]), "severity": "HIGH", "value": df["value"], "fixed": False})
                stats["findings"] += 1
                stats["high"] += 1
                if gh_mode: print(f"::error file={filepath},line={df['line']}::{df['type']}")

        if filepath.endswith(('.yaml', '.yml')):
            for yf in scan_iac(filepath):
                findings.append({"file": filepath, "line": yf["line"], "type": FRIENDLY_NAMES.get(yf["type"]), "severity": "HIGH", "value": yf["value"], "fixed": False})
                stats["findings"] += 1
                stats["high"] += 1
                if gh_mode: print(f"::error file={filepath},line={yf['line']}::{yf['type']}")

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        file_modified = False
        new_lines = []

        for line_num, line in enumerate(lines, 1):
            if "# datatrust:ignore" in line:
                new_lines.append(line)
                continue

            result = scan_text(line, include_value=fix_mode)
            if result["risk"] in ["HIGH", "MEDIUM"]:
                real_findings = [i for i in result["findings"] if not (i["type"] == "PROMPT_INJECTION" and 'r"' in line)]
                
                if 'ignore_types' in config:
                    real_findings = [i for i in real_findings if i["type"] not in config['ignore_types']]

                if not real_findings:
                    new_lines.append(line)
                    continue

                for item in real_findings:
                    if item["severity"] == "HIGH": stats["high"] += 1
                    if item["severity"] == "MEDIUM": stats["medium"] += 1

                    val_to_save = item.get("value", "")
                    finding_entry = {"file": filepath, "line": line_num, "type": FRIENDLY_NAMES.get(item['type']), "severity": item["severity"], "value": val_to_save, "fixed": False}
                    findings.append(finding_entry)
                    stats["findings"] += 1
                    if gh_mode: print(f"::error file={filepath},line={line_num}::{item['type']}")

                if fix_mode:
                    for item in real_findings:
                        if "value" in item:
                            val = item["value"]
                            var_name = f"DATATRUST_{item['type']}_{len(new_lines)}"
                            if dry_run:
                                print(f"[DRY RUN] Would move secret to .env and replace in {filepath} (Line {line_num})")
                            else:
                                with open(".env", "a") as env_file:
                                    env_file.write(f"{var_name}='{val}'\n")
                            line = line.replace(val, f"os.getenv('{var_name}')" if filepath.endswith('.py') else f"${var_name}")
                            file_modified = True

            for plugin in custom_plugins:
                try:
                    plugin_results = plugin.scan_line(line)
                    if plugin_results:
                        for pr in plugin_results:
                            findings.append({"file": filepath, "line": line_num, "type": pr["type"], "severity": pr.get("severity", "HIGH"), "value": pr.get("value", ""), "fixed": False})
                            stats["findings"] += 1
                            stats["high"] += 1
                except Exception:
                    pass

            if fix_mode and filepath.endswith(('Dockerfile', '.dockerfile')):
                if re.match(r'(?i)^USER\s+root', line.strip()):
                    if dry_run: print(f"[DRY RUN] Would change USER root to USER nonroot in {filepath} (Line {line_num})")
                    line = re.sub(r'(?i)^USER\s+root', 'USER nonroot', line)
                    file_modified = True
                if re.match(r'(?i)^ADD\s+', line.strip()):
                    if dry_run: print(f"[DRY RUN] Would change ADD to COPY in {filepath} (Line {line_num})")
                    line = re.sub(r'(?i)^ADD\s+', 'COPY ', line)
                    file_modified = True

            if fix_mode and filepath.endswith(('.yaml', '.yml')):
                if 'privileged: true' in line:
                    if dry_run: print(f"[DRY RUN] Would change privileged: true to false in {filepath} (Line {line_num})")
                    line = line.replace('privileged: true', 'privileged: false')
                    file_modified = True
                if 'allowPrivilegeEscalation: true' in line:
                    if dry_run: print(f"[DRY RUN] Would change allowPrivilegeEscalation to false in {filepath} (Line {line_num})")
                    line = line.replace('allowPrivilegeEscalation: true', 'allowPrivilegeEscalation: false')
                    file_modified = True

            new_lines.append(line)

        if fix_mode and file_modified and not dry_run:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            stats["fixed"] += 1
            for f in findings:
                f["fixed"] = True
        elif fix_mode and file_modified and dry_run:
            for f in findings:
                f["fixed"] = True

    except Exception as e:
        console.print(f"[red]Error scanning {filepath}: {e}[/red]")

    return filepath, findings, stats

def scan_staged_files(fix_mode: bool = False, gh_mode: bool = False, dry_run: bool = False):
    global global_stats, all_findings, global_risk_found
    all_findings = []
    global_stats = {"files": 0, "findings": 0, "fixed": 0, "high": 0, "medium": 0}
    global_risk_found = False

    ignores = load_ignore_patterns()

    try:
        res = subprocess.run(["git", "diff", "--cached", "--name-only"], capture_output=True, text=True)
        raw_files = res.stdout.split('\n')
        filepaths = []
        for f in raw_files:
            f = f.strip()
            if f and os.path.exists(f):
                if not is_ignored(f, ignores):
                    filepaths.append(f)
    except Exception:
        return

    if not filepaths:
        return

    tasks = [(f, fix_mode, gh_mode, 1, dry_run) for f in filepaths]
    global_stats["files"] = len(filepaths)

    if gh_mode:
        for task in tasks:
            _, findings, stats = process_file_worker(task)
            all_findings.extend(findings)
            for k in global_stats: global_stats[k] += stats[k]
    else:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Scanning staged files..."), BarColumn(), TaskProgressColumn()) as progress:
            task_bar = progress.add_task("", total=len(tasks))
            with concurrent.futures.ProcessPoolExecutor() as executor:
                for fpath, findings, stats in executor.map(process_file_worker, tasks):
                    all_findings.extend(findings)
                    for k in global_stats: global_stats[k] += stats[k]
                    progress.advance(task_bar)

    global_risk_found = any(not f["fixed"] for f in all_findings)

def scan_directory(directory: str, fix_mode: bool = False, gh_mode: bool = False, dry_run: bool = False):
    global global_stats, all_findings, global_risk_found
    all_findings = []
    global_stats = {"files": 0, "findings": 0, "fixed": 0, "high": 0, "medium": 0}
    global_risk_found = False

    ignores = load_ignore_patterns()
    filepaths = []

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if not is_ignored(d, ignores)]
        for file in files:
            filepath = os.path.join(root, file)
            if is_ignored(filepath, ignores):
                continue
            if file.endswith(('.py', '.txt', '.env', '.json', '.js', '.md', '.yaml', '.yml', '.csv', '.sh', '.xml', '.html', '.toml', '.ini', '.cfg', 'Dockerfile', '.dockerfile')):
                filepaths.append(filepath)

    files_to_scan = []
    for f in filepaths:
        fhash = get_file_hash(f)
        if not is_cached(f, fhash) or fix_mode:
            files_to_scan.append(f)

    global_stats["files"] = len(files_to_scan)
    if len(files_to_scan) == 0:
        if not gh_mode: console.print("[yellow]No new or modified files to scan.[/yellow]")
        return

    tasks = [(f, fix_mode, gh_mode, 1, dry_run) for f in files_to_scan]

    if gh_mode:
        for task in tasks:
            _, findings, stats = process_file_worker(task)
            all_findings.extend(findings)
            for k in global_stats: global_stats[k] += stats[k]
    else:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Scanning files in parallel..."), BarColumn(), TaskProgressColumn()) as progress:
            task_bar = progress.add_task("", total=len(tasks))
            with concurrent.futures.ProcessPoolExecutor() as executor:
                for fpath, findings, stats in executor.map(process_file_worker, tasks):
                    all_findings.extend(findings)
                    for k in global_stats: global_stats[k] += stats[k]
                    if not fix_mode:
                        update_cache(fpath, get_file_hash(fpath))
                    progress.advance(task_bar)

    global_risk_found = any(not f["fixed"] for f in all_findings)

def display_results_table():
    if not all_findings: return
    table = Table(title="[bold white]Security Findings[/bold white]", box=ROUNDED, border_style="dim cyan", show_lines=True)
    table.add_column("File", style="#81ecec", width=20)
    table.add_column("Line", justify="right", style="#fdcb6e", width=5)
    table.add_column("Risk", style="bold", width=8)
    table.add_column("Type & Detail", style="white")

    unique = {f"{f['file']}-{f['line']}-{f['type']}": f for f in all_findings}.values()
    for f in unique:
        if f.get("fixed"):
            status = "[green]FIXED[/green]"
            risk_color = "green"
            detail = f"✅ {f['type']} (Auto-fixed)"
        else:
            status = f["severity"]
            risk_color = "bold #ff7675" if f["severity"] == "HIGH" else "bold #fdcb6e"
            detail = f"🔴 {f['type']}"

        if f.get("value") and not f.get("fixed"):
            detail += f"\n[dim #b2bec3]{mask_secret(str(f['value']))}[/dim #b2bec3]"

        table.add_row(f["file"], str(f["line"]), f"[{risk_color}]{status}[/{risk_color}]", detail)
    console.print("\n", table)

def print_summary():
    score, grade = calculate_security_score()
    table = Table(title="[bold white]Scan Summary[/bold white]", box=ROUNDED)
    table.add_column("Metric", style="#a29bfe")
    table.add_column("Value", style="bold white")
    table.add_row("Security Score", f"{score}/100 (Grade: {grade})")
    table.add_row("Files Processed", str(global_stats["files"]))
    table.add_row("Total Findings", str(global_stats["findings"]))
    if global_stats["fixed"] > 0:
        table.add_row("Auto-Fixed Files", f"[#55efc4]{global_stats['fixed']}[/#55efc4]")

    remaining_high = len([f for f in all_findings if f['severity']=='HIGH' and not f['fixed']])
    table.add_row("Remaining High Risk", f"[#ff7675]{remaining_high}[/#ff7675]")
    console.print("\n", table)

def generate_sarif_report():
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "DataTrust AI", "informationUri": "https://github.com/warriorxxzz/datatrust-ai"}},
            "results": []
        }]
    }
    for f in all_findings:
        if f.get("fixed"): continue
        sarif["runs"][0]["results"].append({
            "ruleId": f["type"].replace(" ", "_"),
            "message": {"text": f"{f['type']} detected"},
            "level": "error" if f["severity"] == "HIGH" else "warning",
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]}, "region": {"startLine": int(f["line"]) if str(f["line"]).isdigit() else 1}}}]
        })
    with open("datatrust.sarif", "w", encoding="utf-8") as file:
        json.dump(sarif, file, indent=2)
    console.print("[bold #81ecec]📄 SARIF report generated: datatrust.sarif[/bold #81ecec]")

def generate_sbom():
    if not os.path.exists("requirements.txt"):
        console.print("[yellow]No requirements.txt found for SBOM.[/yellow]")
        return
    with open("requirements.txt", "r") as f:
        lines = f.readlines()
    
    components = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            match = re.match(r"([a-zA-Z0-9_-]+)==([0-9.]+)", line)
            if match:
                components.append({
                    "type": "library",
                    "name": match.group(1),
                    "version": match.group(2),
                    "purl": f"pkg:pypi/{match.group(1)}@{match.group(2)}"
                })
    
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "DataTrust AI"}
        },
        "components": components
    }
    with open("datatrust_sbom.json", "w") as f:
        json.dump(sbom, f, indent=2)
    console.print("[bold #81ecec]📄 CycloneDX SBOM generated: datatrust_sbom.json[/bold #81ecec]")

def scan_dependencies():
    console.print("[bold cyan]Scanning requirements.txt for vulnerabilities (OSV API)...[/bold cyan]")
    if not os.path.exists("requirements.txt"):
        console.print("[yellow]No requirements.txt found.[/yellow]")
        return
    with open("requirements.txt") as f:
        lines = f.readlines()
    table = Table(title="[bold white]Dependency Vulnerabilities[/bold white]", box=ROUNDED)
    table.add_column("Package", style="cyan")
    table.add_column("Vulnerability ID", style="yellow")
    table.add_column("Fix", style="green")
    found = False
    for line in lines:
        match = re.match(r"([a-zA-Z0-9_-]+)==([0-9.]+)", line.strip())
        if match:
            try:
                res = requests.post("https://api.osv.dev/v1/query", json={"package": {"name": match.group(1), "ecosystem": "PyPI"}, "version": match.group(2)}, timeout=5)
                if res.status_code == 200 and "vulns" in res.json():
                    found = True
                    for v in res.json()["vulns"]:
                        fix = "No fix available"
                        for aff in v.get("affected", []):
                            for r in aff.get("ranges", []):
                                for e in r.get("events", []):
                                    if "fixed" in e: fix = f">= {e['fixed']}"
                        table.add_row(f"{match.group(1)}=={match.group(2)}", v["id"], fix)
            except Exception:
                pass
    if found: console.print(table)
    else: console.print("[bold #55efc4]✅ No vulnerable dependencies found.[/bold #55efc4]")

def check_licenses():
    console.print("[bold cyan]Checking Open-Source Licenses for dependencies...[/bold cyan]")
    if not os.path.exists("requirements.txt"):
        console.print("[yellow]No requirements.txt found.[/yellow]")
        return
    with open("requirements.txt") as f:
        lines = f.readlines()
    table = Table(title="[bold white]Dependency Licenses[/bold white]", box=ROUNDED)
    table.add_column("Package", style="cyan")
    table.add_column("License", style="yellow")
    table.add_column("Status", style="green")
    bad = ['GPL', 'AGPL', 'SSPL']
    for line in lines:
        match = re.match(r"([a-zA-Z0-9_-]+)", line.strip())
        if match:
            try:
                res = requests.get(f"https://pypi.org/pypi/{match.group(1)}/json", timeout=5)
                lic = res.json()["info"].get("license", "Unknown") or "Unknown"
                status = "[red]Restrictive[/red]" if any(b in lic.upper() for b in bad) else "[green]Safe[/green]"
                table.add_row(match.group(1), lic[:30], status)
            except Exception:
                pass
    console.print(table)

def generate_markdown_report():
    md = "# 🛡️ DataTrust AI Security Report\n\n"
    score, grade = calculate_security_score()
    md += f"**Security Score:** {score}/100 (Grade: {grade})\n\n"
    if not all_findings:
        md += "✅ No security issues found!\n"
    else:
        md += "## Findings\n\n| File | Line | Risk | Issue |\n|---|---|---|---|\n"
        for f in all_findings:
            if not f.get("fixed"):
                md += f"| `{f['file']}` | {f['line']} | {f['severity']} | {f['type']} |\n"
    with open("datatrust_report.md", "w", encoding="utf-8") as f:
        f.write(md)
    console.print("[bold #81ecec]📄 Markdown report generated: datatrust_report.md[/bold #81ecec]")

def main():
    global global_risk_found, custom_plugins
    init_db()
    load_config()
    
    if "--enable-plugins" in sys.argv:
        custom_plugins = load_custom_plugins()
        console.print("[bold #fdcb6e]⚠️ Custom plugins enabled.[/bold #fdcb6e]")
    else:
        custom_plugins = []

    if len(sys.argv) == 1:
        interactive_menu()
        return

    if "--help" in sys.argv or "-h" in sys.argv:
        show_help()
        return

    if not any(arg in sys.argv for arg in ['--sca', '--gh-actions', '--license-check', '--stats', '--automate', '--serve', '--staged', '--sbom']):
        console.print(BANNER)

    parser = argparse.ArgumentParser(description="DataTrust AI - Ultimate Enterprise Security Platform", add_help=False)
    parser.add_argument("text", nargs="?", help="Text to scan directly")
    parser.add_argument("--file", "-f", help="Scan a specific file")
    parser.add_argument("--dir", "-d", help="Scan an entire directory")
    parser.add_argument("--staged", action="store_true", help="Scan only git staged files")
    parser.add_argument("--fix", action="store_true", help="Auto-fix issues")
    parser.add_argument("--dry-run", action="store_true", help="Simulate fixes")
    parser.add_argument("--serve", action="store_true", help="Start secure server")
    parser.add_argument("--json", action="store_true", help="Output in JSON")
    parser.add_argument("--sarif", action="store_true", help="Generate SARIF report")
    parser.add_argument("--sbom", action="store_true", help="Generate CycloneDX SBOM")
    parser.add_argument("--report-md", action="store_true", help="Generate Markdown report")
    parser.add_argument("--stats", action="store_true", help="Show historical stats")
    parser.add_argument("--automate", action="store_true", help="Setup Git hooks")
    parser.add_argument("--gh-actions", action="store_true", help="GitHub Actions format")
    parser.add_argument("--sca", action="store_true", help="Scan dependencies")
    parser.add_argument("--license-check", action="store_true", help="Check licenses")
    parser.add_argument("--enable-plugins", action="store_true", help="Enable custom plugins")
    args = parser.parse_args()

    if args.sbom:
        generate_sbom()
        return
    if args.sca:
        scan_dependencies()
        return
    if args.license_check:
        check_licenses()
        return
    if args.automate:
        hook_dir = ".git/hooks"
        if os.path.exists(hook_dir):
            with open(os.path.join(hook_dir, "pre-commit"), "w") as f:
                f.write("#!/bin/sh\necho \"🛡️ Running DataTrust AI Pre-commit...\"\ndatatrust --staged\nif [ $? -ne 0 ]; then\n echo \"🛑 Commit blocked! Sensitive info detected.\"\n exit 1\nfi\n")
            os.chmod(os.path.join(hook_dir, "pre-commit"), 0o755)
        console.print("[bold #55efc4]✔ Automation setup complete.[/bold #55efc4]")
        return
    if args.stats: 
        show_stats()
        return
    if args.serve:
        import http.server
        import socketserver
        import os
        
        class SafeHandler(http.server.os.getenv('DATATRUST_HIGH_ENTROPY_724')):
            def do_GET(self):
                if self.path in ['/', '/datatrust_report.html']:
                    self.path = '/datatrust_report.html'
                    return http.server.os.getenv('DATATRUST_HIGH_ENTROPY_728').do_GET(self)
                self.send_error(403, "Access Denied")
                
        console.print(f"[bold #81ecec]🌐 Secure Web Server at http://127.0.0.1:8080[/bold #81ecec]")
        with socketserver.TCPServer(("127.0.0.1", 8080), SafeHandler) as httpd:
            try: httpd.serve_forever()
            except KeyboardInterrupt: pass
        return

    if not sys.stdin.isatty() and not args.text:
        text = sys.stdin.read()
        if text:
            result = scan_text(text, include_value=True)
            if result["risk"] != "NONE":
                global_risk_found = True
                for item in result["findings"]:
                    all_findings.append({"file": "STDIN", "line": "-", "type": FRIENDLY_NAMES.get(item['type']), "severity": item["severity"], "value": item.get("value", ""), "fixed": False})
                display_results_table()
            else:
                console.print("\n[bold #55efc4]✅ Safe.[/bold #55efc4]")
            if global_risk_found: sys.exit(1)
            return

    if args.staged:
        scan_staged_files(args.fix, args.gh_actions, args.dry_run)
        if not args.gh_actions and not args.json:
            print_summary()
            display_results_table()
    elif args.dir:
        scan_directory(args.dir, args.fix, args.gh_actions, args.dry_run)
        if not args.gh_actions and not args.json:
            print_summary()
            display_results_table()
    elif args.file:
        global_stats["files"] = 1
        task = (args.file, args.fix, args.gh_actions, 1, args.dry_run)
        _, findings, stats = process_file_worker(task)
        all_findings.extend(findings)
        for k in global_stats: global_stats[k] += stats[k]
        global_risk_found = any(not f["fixed"] for f in all_findings)
        if not args.gh_actions and not args.json:
            print_summary()
            display_results_table()
    elif args.text:
        result = scan_text(args.text, include_value=True)
        if result["risk"] != "NONE":
            global_risk_found = True
            for item in result["findings"]:
                all_findings.append({"file": "Input", "line": "-", "type": FRIENDLY_NAMES.get(item['type']), "severity": item["severity"], "value": item.get("value", ""), "fixed": False})
            if not args.json: display_results_table()
        else:
            if not args.json: console.print("\n[bold #55efc4]✅ Safe.[/bold #55efc4]")
    else:
        show_help()
        return

    if args.json:
        print(json.dumps({"score": calculate_security_score()[0], "findings": all_findings}, indent=2))
    elif args.sarif:
        generate_sarif_report()
    elif args.report_md:
        generate_markdown_report()
    elif global_risk_found:
        console.print("\n[bold #ff7675]❌ Unresolved security issues found.[/bold #ff7675]")

    save_to_db()
    if global_risk_found: sys.exit(1)

if __name__ == "__main__":
    main()
