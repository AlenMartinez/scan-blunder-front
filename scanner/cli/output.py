from rich import print
from rich.table import Table
from rich.console import Console

console = Console()

def success(msg: str):
    console.print(f"[bold green][+][/bold green] {msg}")

def error(msg: str):
    console.print(f"[bold red][-][/bold red] {msg}")

def info(msg: str):
    console.print(f"[bold blue][*][/bold blue] {msg}")

def warning(msg: str):
    console.print(f"[bold yellow][!][/bold yellow] {msg}")

def show_banner():
    console.print("""
                                                                                        
 _____                   _____  _              _              _____                 _   
|   __| ___  ___  ___   | __  || | _ _  ___  _| | ___  ___   |   __| ___  ___  ___ | |_ 
|__   ||  _|| .'||   |  | __ -|| || | ||   || . || -_||  _|  |   __||  _|| . ||   ||  _|
|_____||___||__,||_|_|  |_____||_||___||_|_||___||___||_|    |__|   |_|  |___||_|_||_|  
                                                                                                                                                                                                                                         
    """, style="bold cyan")

def show_results(results):
    print("\n" + "="*60)
    console.print("[bold cyan]SCAN SUMMARY[/bold cyan]", justify="center")
    print("="*60)

    # Libraries
    if results["libs"]:
        print("\n[bold blue][+] LIBRARIES DETECTED:[/bold blue]")
        for lib, ver in results["libs"].items():
            print(f"  - [green]{lib}[/green]: {ver}")

    # Secrets Table
    if results["secrets"]:
        print("\n[bold red][!] SECRETS FOUND:[/bold red]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Type", style="dim")
        table.add_column("Value")
        table.add_column("URL", style="dim")
        table.add_column("Line")
        
        for secret in results["secrets"]:
            table.add_row(
                secret["type"],
                secret["value"][:50] + "..." if len(secret["value"]) > 50 else secret["value"],
                secret["url"].split("/")[-1],
                str(secret["line"])
            )
        console.print(table)

    # Vulnerabilities Table
    if results["vulnerabilities"]:
        print("\n[bold yellow][!] VULNERABILITIES / BAD PRACTICES:[/bold yellow]")
        v_table = Table(show_header=True, header_style="bold yellow")
        v_table.add_column("Type")
        v_table.add_column("Snippet")
        v_table.add_column("URL", style="dim")
        
        for v in results["vulnerabilities"]:
            v_table.add_row(
                v["type"],
                v["value"][:60].strip() + "...",
                v["url"].split("/")[-1]
            )
        console.print(v_table)

    # HTTP Methods
    if results["methods"]:
        print("\n[bold cyan][+] HTTP METHODS / ENDPOINTS FOUND:[/bold cyan]")
        m_table = Table(show_header=True, header_style="bold cyan")
        m_table.add_column("Method")
        m_table.add_column("Endpoint")
        
        for m in results["methods"]:
            m_table.add_row(m["method"], m["url"])
        console.print(m_table)

    # Top URLs
    if results["urls"]:
        print(f"\n[bold blue][+] TOTAL URLs FOUND: {len(results['urls'])}[/bold blue]")
        for u in sorted(results["urls"])[:15]:
            print(f"  - {u}")
        if len(results["urls"]) > 15:
            print(f"  ... and {len(results['urls']) - 15} more.")

    print("\n" + "="*60)