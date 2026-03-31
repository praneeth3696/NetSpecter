from rich.console import Console
from rich.panel import Panel

console = Console()

def print_alert(src_ip: str, dst_ip: str, detection: dict):
    lines = [
        f"[bold cyan]Source IP:[/bold cyan]       {src_ip}",
        f"[bold cyan]Destination IP:[/bold cyan]  {dst_ip}",
        f"[bold cyan]Detection type:[/bold cyan]  {detection.get('type', 'Unknown')}",
    ]
    
    if username := detection.get("username", ""):
        lines.append(f"[bold cyan]Username:[/bold cyan]        [bold white]{username}[/bold white]")
        
    if password := detection.get("password", ""):
        lines.append(f"[bold red]Password:[/bold red]        [bold red]{password}[/bold red]")
        
    lines.append(f"[bold cyan]Confidence:[/bold cyan]      {detection.get('confidence', 'low').upper()}")
    
    if snippet := detection.get("raw_snippet"):
        lines.append(f"[dim]Snippet: {snippet[:80]}[/dim]")
        
    lines.append("")
    lines.append("[dim]Credentials are transmitted in plaintext and can be intercepted.[/dim]")

    panel = Panel(
        "\n".join(lines),
        title="[bold red]⚠️ INSECURE CREDENTIAL TRANSMISSION DETECTED ⚠️[/bold red]",
        border_style="red"
    )
    console.print(panel)

def print_error(msg: str):
    console.print(f"[bold red][✖] {msg}[/bold red]")

def print_info(msg: str):
    console.print(f"[bold cyan][ℹ] {msg}[/bold cyan]")
