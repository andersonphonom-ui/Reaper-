#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import argparse
from rich.console import Console

from banner import show_banner
from scanner import run_scan, print_report

console = Console()

# ─── Argument Parser ──────────────────────────────────────────
parser = argparse.ArgumentParser(
    prog="reaper",
    description="Reaper — Web Vulnerability Scanner",
    epilog="Example: reaper -u https://example.com"
)

parser.add_argument("-v", "--version", action="version", version="Reaper v1.0.0")
parser.add_argument("-u", "--url",     required=True, help="Target URL")
parser.add_argument("-t", "--timeout", type=int, default=5, help="Request timeout (default: 5)")
parser.add_argument(
    "-m", "--modules",
    nargs="+",
    choices=["sqli", "xss", "headers", "admin", "files"],
    help="Run specific modules only (default: all)"
)

args = parser.parse_args()

# ─── Banner ───────────────────────────────────────────────────
show_banner()

# ─── Normalize URL ────────────────────────────────────────────
url = args.url
if not url.startswith("http"):
    url = "https://" + url

console.print(f"[bold red]Target  :[/bold red] {url}")
console.print(f"[bold red]Modules :[/bold red] {', '.join(args.modules) if args.modules else 'all'}")
console.print(f"[bold red]Timeout :[/bold red] {args.timeout}s\n")
console.print("[yellow]Starting scan...[/yellow]\n")

# ─── Scan ─────────────────────────────────────────────────────
findings = run_scan(url, modules=args.modules, timeout=args.timeout)

# ─── Report ───────────────────────────────────────────────────
print_report(url, findings)
