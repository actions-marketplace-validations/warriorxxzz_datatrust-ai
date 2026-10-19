import sys
import os
import json
import argparse
import concurrent.futures
import subprocess
import re
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from datatrust_ai.detector import scan_text

console = Console()

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
    "NLP_PERSON": "Person Name (AI)", "NLP_GPE": "Location/Address (AI)"
}

DEFAULT_IGNORES = ['.git', 'venv', 'env', '__pycache__', 'node_modules', 'dist', 'build', '.github', 'custom_rules.json', 'datatrust.sarif']
global_stats = {"files": 0, "findings": 0, "high": 0, "medium": 0}
all_findings = []
global_risk_found = False
env_counter = 1

def load_ignore_patterns():
    patterns = set(DEFAULT_IGNORES)
    if os.path.exists('.datatrustignore'):
        with open('.datatrustignore', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    patterns.add(line)
    return patterns

def display_result(text: str, source: str = "Input"):
    global global_risk_found
    result = scan_text(text)
    if result["risk"] == "NONE": return False
        
    global_risk_found = True
    console.print()
    title = Text("🛑 WARNING: Sensitive Info Detected!", style="bold white on red")
    console.print(Panel(title, expand=False, border_style="red"))
    console.print(f"[dim]Source: {source}[/dim]\n")
    
    detected_types = set()
    for item in result["findings"]:
        detected_types.add(FRIENDLY_NAMES.get(item['type'], item['type']))
        
    for info in detected_types:
        console.print(f"  [bold red]🔴 {info}[/bold red]")
        
    console.print("\n[yellow]⚠️  Please remove these details before sharing.[/yellow]")
    console.print("=" * 50 + "\n")
    return True

def save_to_env(secret_value: str, secret_type: str):
    global env_counter
    var_name = f"DATATRUST_{secret_type}_{env_counter}"
    with open(".env", "a") as env_file:
        env_file.write(f"{var_name}='{secret_value}'\n")
    
    if not os.path.exists(".gitignore"):
        with open(".gitignore", "w") as gi:
            gi.write(".env\n")
    else:
        with open(".gitignore", "r") as gi:
            content = gi.read()
        if ".env" not in content:
            with open(".gitignore", "a") as gi:
                gi.write("\n.env\n")
                
    env_counter += 1
    return var_name

def process_file(filepath: str, fix_mode: bool = False):
    global global_risk_found, global_stats
    try:
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
                global_risk_found = True
                global_stats["findings"] += len(result["findings"])
                for item in result["findings"]:
                    if item["severity"] == "HIGH": global_stats["high"] += 1
                    if item["severity"] == "MEDIUM": global_stats["medium"] += 1
                    all_findings.append({"file": filepath, "line": line_num, "type": FRIENDLY_NAMES.get(item['type'], item['type']), "severity": item["severity"]})
                
                if not fix_mode:
                    display_result(line, f"{filepath} (Line {line_num})")
                else:
                    for item in result["findings"]:
                        if "value" in item:
                            val = item["value"]
                            secret_type = item['type']
                            var_name = save_to_env(val, secret_type)
                            if filepath.endswith('.py'):
                                line = line.replace(val, f"os.getenv('{var_name}')")
                            else:
                                line = line.replace(val, f"${var_name}")
                            file_modified = True
            new_lines.append(line)
            
        if fix_mode and file_modified:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            console.print(f"[green]✔ Fixed secrets in: {filepath} (Moved to .env)[/green]")
            
    except Exception:
        pass

def scan_git_history():
    console.print("[bold cyan]Scanning Git commit history for leaked secrets...[/bold cyan]")
    try:
        result = subprocess.run(["git", "log", "-p"], capture_output=True, text=True, errors="ignore")
        lines = result.stdout.split('\n')
        current_commit = "Unknown"
        commit_msg = ""
        
        history_findings = []
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            task = progress.add_task("[cyan]Analyzing Git Diffs...", total=len(lines))
            for line in lines:
                if line.startswith('commit '):
                    current_commit = line.split(' ')[1][:8]
                elif line.startswith('    ') and not line.startswith('    ') is None:
                    if len(line.strip()) > 5 and not commit_msg:
                        commit_msg = line.strip()
                elif line.startswith('+') and not line.startswith('+++'):
                    if "tests/" in line or "patterns/" in line or "PATTERNS" in line:
                        progress.advance(task)
                        continue
                        
                    scan_result = scan_text(line[1:])
                    if scan_result["risk"] in ["HIGH", "MEDIUM"]:
                        for item in scan_result["findings"]:
                            history_findings.append({
                                "commit": current_commit,
                                "msg": commit_msg[:30] + "..." if len(commit_msg) > 30 else commit_msg,
                                "type": FRIENDLY_NAMES.get(item['type'], item['type']),
                                "severity": item["severity"]
                            })
                progress.advance(task)
                
        if not history_findings:
            console.print("[green]✅ No secrets found in Git history.[/green]")
            return
            
        table = Table(title="Git History Scan Results", show_lines=True)
        table.add_column("Commit", style="yellow", width=10)
        table.add_column("Leaked Data", style="red", width=25)
        table.add_column("Risk", style="bold", width=8)
        
        unique_findings = {f"{f['commit']}-{f['type']}": f for f in history_findings}.values()
        
        for f in unique_findings:
            risk_color = "red" if f["severity"] == "HIGH" else "yellow"
            table.add_row(f["commit"], f["type"], f"[{risk_color}]{f['severity']}[/{risk_color}]")
            
        console.print("\n", table)
        console.print("[bold red]⚠️  Note: These secrets are in your Git history. Rotate them immediately if they are real![/bold red]\n")
        
    except Exception as e:
        console.print(f"[red]Error running git history scan: {e}[/red]")

def generate_sarif_report():
    if not all_findings: return
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "DataTrust AI", "version": "0.6.0"}},
            "results": []
        }]
    }
    for f in all_findings:
        sarif["runs"][0]["results"].append({
            "ruleId": f["type"].replace(" ", "_"),
            "message": {"text": f"Sensitive data found: {f['type']}"},
            "level": "error" if f["severity"] == "HIGH" else "warning",
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]}, "region": {"startLine": f["line"]}}}]
        })
    with open("datatrust.sarif", "w", encoding="utf-8") as file:
        json.dump(sarif, file, indent=2)
    console.print("[bold cyan]📄 SARIF Report generated: datatrust.sarif[/bold cyan]")

def scan_directory(directory: str, fix_mode: bool = False):
    global global_stats
    ignores = load_ignore_patterns()
    filepaths = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ignores]
        for file in files:
            if file.endswith(('.py', '.txt', '.env', '.json', '.js', '.md', '.yaml', '.yml', '.csv')):
                filepath = os.path.join(root, file)
                if not any(ignore in filepath for ignore in ignores):
                    filepaths.append(filepath)

    global_stats["files"] = len(filepaths)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn()) as progress:
        task = progress.add_task("[cyan]Scanning files...", total=len(filepaths))
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for filepath in filepaths:
                process_file(filepath, fix_mode)
                progress.advance(task)

def print_summary():
    table = Table(title="Scan Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold white")
    table.add_row("Files Scanned", str(global_stats["files"]))
    table.add_row("Total Findings", str(global_stats["findings"]))
    table.add_row("High Risk", f"[red]{global_stats['high']}[/red]")
    table.add_row("Medium Risk", f"[yellow]{global_stats['medium']}[/yellow]")
    console.print("\n", table)

def main():
    global global_risk_found, global_stats
    parser = argparse.ArgumentParser(description="DataTrust AI - PII & Secret Scanner")
    parser.add_argument("text", nargs="?", help="Text to scan directly")
    parser.add_argument("--file", "-f", help="Scan a specific file")
    parser.add_argument("--dir", "-d", help="Scan an entire directory")
    parser.add_argument("--git-history", action="store_true", help="Scan Git commit history")
    parser.add_argument("--sarif", action="store_true", help="Output in SARIF format")
    parser.add_argument("--fix", action="store_true", help="Move secrets to .env and replace in code")
    parser.add_argument("--install-hook", action="store_true", help="Install Git pre-commit hook")
    args = parser.parse_args()

    if args.install_hook:
        hook_dir = ".git/hooks"
        if os.path.exists(hook_dir):
            hook_path = os.path.join(hook_dir, "pre-commit")
            with open(hook_path, "w") as f:
                f.write("#!/bin/sh\necho \"Running DataTrust AI scan...\"\ndatatrust --dir .\nif [ $? -ne 0 ]; then\n echo \"🛑 DataTrust AI blocked the commit!\"\n exit 1\nfi\n")
            os.chmod(hook_path, 0o755)
            console.print("[green]✅ Pre-commit hook installed successfully![/green]")
        else:
            console.print("[red]Error: .git directory not found.[/red]")
        return

    if args.git_history:
        scan_git_history()
    elif args.file:
        global_stats["files"] = 1
        process_file(args.file, args.fix)
        print_summary()
    elif args.dir:
        scan_directory(args.dir, args.fix)
        print_summary()
    elif args.text:
        display_result(args.text, "Direct Input")
    else:
        console.print("[yellow]Usage: datatrust \"text\" | -f file | -d dir | --git-history | --fix[/yellow]")

    if args.sarif: generate_sarif_report()
        
    if global_risk_found: 
        sys.exit(1)

if __name__ == "__main__":
    main()
