from rich.console import Console

console = Console()

VERSION = "1.0.0"

def show_banner():
    console.print(r"""[bold red]
██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
[/bold red]""")
    console.print(f"[bold red]Reaper v{VERSION}[/bold red]")
    console.print("[yellow]Web Vulnerability Scanner[/yellow]")
    console.print("[dim]Developed by Youssef Mediouni[/dim]\n")
