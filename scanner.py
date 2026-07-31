import requests
import urllib3
from rich.console import Console
from rich.table import Table
from rich import box

from sqli    import test_sqli
from xss     import test_xss
from headers import test_headers
from admin   import test_admin
from files   import test_files

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

SEVERITY_ORDER = {
    "Critical 🔴": 0,
    "High 🟠":     1,
    "Medium 🟡":   2,
    "Low 🔵":      3,
}


def run_scan(url, modules=None, timeout=5):
    """
    Runs all or selected modules against the target URL.
    Returns sorted list of findings.
    """
    all_findings = []

    # Check if target is reachable
    try:
        requests.get(url, timeout=timeout, verify=False)
    except Exception:
        console.print(f"[red]❌ Cannot reach: {url}[/red]")
        return []

    available = {
        "sqli":    ("SQL Injection",       test_sqli),
        "xss":     ("XSS",                 test_xss),
        "headers": ("Security Headers",    test_headers),
        "admin":   ("Admin Panels",        test_admin),
        "files":   ("Sensitive Files",     test_files),
    }

    selected = modules if modules else list(available.keys())

    for key in selected:
        if key not in available:
            continue
        name, func = available[key]
        console.print(f"[cyan]  → Testing {name}...[/cyan]")
        try:
            findings = func(url, timeout=timeout)
            all_findings.extend(findings)
        except Exception as e:
            console.print(f"[yellow]  ⚠ {name} error: {e}[/yellow]")

    # Sort by severity
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    return all_findings


def calculate_score(findings):
    """Returns a vulnerability score 0-100"""
    weights = {"Critical 🔴": 30, "High 🟠": 15, "Medium 🟡": 7, "Low 🔵": 2}
    total = sum(weights.get(f["severity"], 0) for f in findings)
    return min(total, 100)


def print_report(url, findings):
    """Prints the final scan report"""

    if not findings:
        console.print("\n[bold green]✅ No vulnerabilities found![/bold green]\n")
        return

    score = calculate_score(findings)

    if score >= 70:
        level = "Critical 🔴"
    elif score >= 40:
        level = "High Risk 🟠"
    elif score >= 20:
        level = "Medium Risk 🟡"
    else:
        level = "Low Risk 🔵"

    # Main findings table
    table = Table(
        title=f"💀 Reaper Report — {url}",
        box=box.DOUBLE_EDGE,
        style="red",
        title_style="bold red",
        header_style="bold magenta",
        show_lines=True
    )

    table.add_column("#",        width=4,  style="dim")
    table.add_column("Type",     width=30, style="bold white")
    table.add_column("Severity", width=15)
    table.add_column("Parameter/Path", width=20)
    table.add_column("Evidence", width=35)

    for i, f in enumerate(findings, 1):
        table.add_row(
            str(i),
            f["type"],
            f["severity"],
            f.get("param", "-") if f.get("param") != "-" else f.get("payload", "-"),
            f["evidence"]
        )

    console.print()
    console.print(table)

    # Score table
    score_table = Table(box=box.SIMPLE_HEAVY, style="red", show_lines=True)
    score_table.add_column("Metric",   style="bold white", width=20)
    score_table.add_column("Value",    style="bold red",   width=25)

    score_table.add_row("Target",             url)
    score_table.add_row("Vulnerabilities",    str(len(findings)))
    score_table.add_row("Risk Score",         f"{score}/100")
    score_table.add_row("Risk Level",         level)

    console.print()
    console.print(score_table)
    console.print()
