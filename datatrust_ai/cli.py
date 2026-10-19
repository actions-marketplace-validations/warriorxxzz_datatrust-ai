import sys
import os
import json
import argparse
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from datatrust_ai.detector import scan_text

console = Console()

FRIENDLY_NAMES = {
    "NP_CITIZENSHIP": "Nepal Citizenship Number",
    "NP_NID": "National ID (NID)",
    "NP_PAN": "Nepal PAN Number",
    "NP_PASSPORT": "Nepal Passport Number",
    "NP_PHONE_MOBILE": "Nepal Mobile Number",
    "NP_PHONE_LANDLINE": "Nepal Landline Number",
    "IN_AADHAAR": "India Aadhaar Number",
    "IN_PAN": "India PAN Card",
    "IN_UPI": "India UPI ID",
    "IN_IFSC": "India IFSC Code",
    "IN_PHONE_MOBILE": "India Mobile Number",
    "CREDIT_CARD": "Credit Card Number",
    "AWS_KEY": "AWS Access Key",
    "OPENAI_KEY": "OpenAI API Key",
    "GITHUB_PAT": "GitHub Personal Access Token",
    "GOOGLE_API": "Google API Key",
    "PRIVATE_KEY": "SSH/RSA Private Key",
    "EMAIL": "Email Address",
    "IPV4": "IP Address"
}

DEFAULT_IGNORES = ['.git', 'venv', 'env', '__pycache__', 'node_modules', 'dist', 'build', '.github']

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
    result = scan_text(text)
    risk = result["risk"]
    findings = result["findings"]
    
    if risk == "NONE":
        return False
        
    console.print()
    title = Text("🛑 WARNING: Sensitive Info Detected!", style="bold white on red")
    console.print(Panel(title, expand=False, border_style="red"))
    console.print(f"[dim]Source: {source}[/dim]\n")
    
    detected_types = set()
    for item in findings:
        friendly_name = FRIENDLY_NAMES.get(item['type'], item['type'])
        detected_types.add(friendly_name)
        
    for info in detected_types:
        console.print(f"  [bold red]🔴 {info}[/bold red]")
        
    console.print("\n[yellow]⚠️  Please remove these details before sharing.[/yellow]")
    console.print("=" * 50 + "\n")
    return True

def scan_file(filepath: str):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                result = scan_text(line)
                if result["risk"] in ["HIGH", "MEDIUM"]:
                    display_result(line, f"{filepath} (Line {line_num})")
    except Exception as e:
        console.print(f"[red]Error reading file {filepath}: {e}[/red]")

def scan_directory(directory: str):
    console.print(f"[cyan]Scanning directory: {directory}...[/cyan]")
    found_any = False
    ignores = load_ignore_patterns()
    
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ignores and d not in ['.git', 'venv', 'env', '__pycache__', 'node_modules', 'dist', 'build']]
        
        for file in files:
            if file.endswith(('.py', '.txt', '.env', '.json', '.js', '.md', '.yaml', '.yml', '.csv')):
                filepath = os.path.join(root, file)
                
                if any(ignore in filepath for ignore in ignores):
                    continue

                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        result = scan_text(line)
                        if result["risk"] in ["HIGH", "MEDIUM"]:
                            found_any = True
                            display_result(line, f"{filepath} (Line {line_num})")
    
    if not found_any:
        console.print("[green]✅ Scan complete. No sensitive info found.[/green]")

def main():
    parser = argparse.ArgumentParser(description="DataTrust AI - PII & Secret Scanner")
    parser.add_argument("text", nargs="?", help="Text to scan directly")
    parser.add_argument("--file", "-f", help="Scan a specific file")
    parser.add_argument("--dir", "-d", help="Scan an entire directory")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    
    args = parser.parse_args()

    if args.file:
        scan_file(args.file)
    elif args.dir:
        scan_directory(args.dir)
    elif args.text:
        if args.json:
            res = scan_text(args.text)
            print(json.dumps(res, indent=2))
        else:
            display_result(args.text, "Direct Input")
    else:
        console.print("[yellow]Usage:[/yellow]")
        console.print("  datatrust \"Your text here\"")
        console.print("  datatrust --file config.py")
        console.print("  datatrust --dir ./my_project")

if __name__ == "__main__":
    main()
