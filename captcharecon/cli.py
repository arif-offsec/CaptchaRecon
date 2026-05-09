#!/usr/bin/env python3
"""
CaptchaRecon — CAPTCHA & Anti-Automation Reconnaissance Toolkit
GPL v3 — For authorised penetration testing only.
"""

import argparse
import sys
import time
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel

from captcharecon.core.detector   import CAPTCHADetector
from captcharecon.core.resilience import ResilienceTester
from captcharecon.core.ratelimit  import RateLimitAnalyzer
from captcharecon.core.antibot    import AntiBotMapper
from captcharecon.core.reporter   import Reporter
from captcharecon.utils.http      import SessionManager

console = Console()

BANNER = r"""
  ____           _       _           ____
 / ___|__ _ _ __| |_ ___| |__   __ _|  _ \ ___  ___ ___  _ __
| |   / _` | '_ \ __/ __| '_ \ / _` | |_) / _ \/ __/ _ \| '_ \
| |__| (_| | |_) | || (__| | | | (_| |  _ <  __/ (_| (_) | | | |
 \____\__,_| .__/ \__\___|_| |_|\__,_|_| \_\___|\___\___/|_| |_|
           |_|
"""

VERSION  = "1.0.0"
SUBTITLE = "CAPTCHA & Anti-Automation Reconnaissance Toolkit"
LICENSE  = "GPL v3  |  Open Source  |  Authorised use only"


def print_banner():
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(f"  [bold white]{SUBTITLE}[/bold white]  [dim]v{VERSION}[/dim]")
    console.print(f"  [dim]{LICENSE}[/dim]\n")


def validate_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        console.print("[red]Invalid URL.[/red]")
        sys.exit(1)
    return url


def ethics_check():
    console.print(Panel(
        "[bold yellow]  AUTHORISED USE ONLY[/bold yellow]\n\n"
        "This tool is for [bold]authorised penetration testing and security research[/bold] only.\n\n"
        "Running it against systems without explicit written permission may violate\n"
        "the CFAA, Computer Misuse Act, and equivalent laws in your jurisdiction.\n\n"
        "This tool does [bold]NOT[/bold] bypass, solve, or interact with any CAPTCHA.\n"
        "It performs [bold]passive reconnaissance and implementation analysis only[/bold].",
        border_style="yellow",
        expand=False,
    ))
    try:
        ans = console.input(
            "\n[bold]Do you have explicit authorisation to test the target? [y/N]: [/bold]"
        ).strip().lower()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Aborted.[/dim]")
        sys.exit(0)

    if ans != "y":
        console.print("[red]Aborted.[/red]")
        sys.exit(0)
    console.print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="captcharecon",
        description="CAPTCHA & Anti-Automation Reconnaissance Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
modules:
  detect      CAPTCHA fingerprinting — type, version, provider, sitekey leaks
  resilience  Implementation weakness testing — missing validation, token reuse
  ratelimit   Rate limit analysis — headers, bypass headers, timing
  antibot     Anti-automation stack — WAF, bot management, fingerprinting libs

examples:
  captcharecon -u https://target.com/login
  captcharecon -u https://target.com/login --modules detect antibot
  captcharecon -u https://target.com/login --full --output report.json
  captcharecon -u https://target.com/login --proxy http://127.0.0.1:8080

manual:
  man captcharecon
        """,
    )
    parser.add_argument("-u", "--url", required=True,
        help="Target URL")
    parser.add_argument("--modules", nargs="+",
        choices=["detect", "resilience", "ratelimit", "antibot"],
        default=["detect", "resilience", "ratelimit", "antibot"],
        metavar="MODULE",
        help="Modules to run (default: all)")
    parser.add_argument("--full", action="store_true",
        help="Run all modules with extended checks")
    parser.add_argument("--output", metavar="FILE",
        help="Save JSON report to FILE")
    parser.add_argument("--proxy", metavar="URL",
        help="Proxy URL e.g. http://127.0.0.1:8080")
    parser.add_argument("--delay", type=float, default=1.0, metavar="SECS",
        help="Delay between requests in seconds (default: 1.0)")
    parser.add_argument("--timeout", type=int, default=10,
        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--ratelimit-requests", type=int, default=10, metavar="N",
        help="Requests for rate limit probing (default: 10)")
    parser.add_argument("--user-agent", metavar="UA",
        help="Custom User-Agent string")
    parser.add_argument("--no-banner", action="store_true",
        help="Suppress ASCII banner")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="Verbose output")
    return parser


def run_module(label, fn, *args, verbose=False, **kwargs):
    console.rule(f"[bold white]{label}[/bold white]")
    start = time.time()
    try:
        result = fn(*args, **kwargs)
    except KeyboardInterrupt:
        console.print("[yellow]Module interrupted.[/yellow]")
        return None
    except Exception as exc:
        console.print(f"[red]Module error: {exc}[/red]")
        if verbose:
            console.print_exception()
        return None
    console.print(f"\n[dim]Completed in {time.time()-start:.2f}s[/dim]\n")
    return result


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.no_banner:
        print_banner()

    ethics_check()

    target  = validate_url(args.url)
    modules = (
        ["detect", "resilience", "ratelimit", "antibot"]
        if args.full else args.modules
    )

    console.print(f"[bold green]Target :[/bold green] {target}")
    console.print(f"[bold green]Modules:[/bold green] {', '.join(modules)}")
    console.print(f"[bold green]Delay  :[/bold green] {args.delay}s per request")
    if args.proxy:
        console.print(f"[bold green]Proxy  :[/bold green] {args.proxy}")
    console.print()

    session = SessionManager(
        proxy=args.proxy, timeout=args.timeout,
        user_agent=args.user_agent, delay=args.delay,
    )

    results = {"target": target, "modules": {}}

    if "detect" in modules:
        r = run_module("CAPTCHA Fingerprinting",
                       CAPTCHADetector(session, verbose=args.verbose).run,
                       target, verbose=args.verbose)
        if r:
            results["modules"]["detect"] = r

    if "resilience" in modules:
        r = run_module("Resilience Testing",
                       ResilienceTester(session, verbose=args.verbose).run,
                       target, verbose=args.verbose)
        if r:
            results["modules"]["resilience"] = r

    if "ratelimit" in modules:
        r = run_module("Rate Limit Analysis",
                       RateLimitAnalyzer(session,
                           num_requests=args.ratelimit_requests,
                           verbose=args.verbose).run,
                       target, verbose=args.verbose)
        if r:
            results["modules"]["ratelimit"] = r

    if "antibot" in modules:
        r = run_module("Anti-Automation Stack Mapping",
                       AntiBotMapper(session, verbose=args.verbose).run,
                       target, verbose=args.verbose)
        if r:
            results["modules"]["antibot"] = r

    reporter = Reporter(results)
    reporter.print_summary()

    if args.output:
        reporter.save_json(args.output)
        console.print(f"\n[green]JSON report saved to {args.output}[/green]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
