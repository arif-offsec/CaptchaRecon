"""
Rate Limit Analysis Module
Probes throttling mechanisms, header-based limits, and IP bypass header effectiveness.
"""

import time
import statistics
from collections import Counter

import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

console = Console()

RATE_LIMIT_HEADERS = [
    "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
    "X-Rate-Limit-Limit", "X-Rate-Limit-Remaining", "X-Rate-Limit-Reset",
    "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset",
    "Retry-After", "X-RateLimit-Retry-After",
]

BYPASS_HEADERS = [
    {"X-Forwarded-For":   "127.0.0.1"},
    {"X-Forwarded-For":   "1.1.1.1"},
    {"X-Real-IP":         "127.0.0.1"},
    {"X-Originating-IP":  "127.0.0.1"},
    {"X-Remote-IP":       "127.0.0.1"},
    {"X-Client-IP":       "127.0.0.1"},
    {"CF-Connecting-IP":  "127.0.0.1"},
    {"True-Client-IP":    "127.0.0.1"},
    {"Forwarded":         "for=127.0.0.1"},
]


class RateLimitAnalyzer:

    def __init__(self, session, num_requests=10, verbose=False):
        self.session      = session
        self.num_requests = num_requests
        self.verbose      = verbose

    def run(self, url, **_):
        result = {
            "url":             url,
            "headers_found":   {},
            "rate_limited":    False,
            "bypass_findings": [],
            "timing":          {},
            "status_codes":    [],
        }

        # 1 — Header scan
        console.print(f"[cyan]Checking rate limit headers:[/cyan] {url}")
        result["headers_found"] = self._scan_headers(url)

        # 2 — Rapid probe
        console.print(f"[cyan]Sending {self.num_requests} rapid requests...[/cyan]")
        responses = self._rapid_probe(url)
        result["status_codes"] = [
            getattr(r, "status_code", None) for r in responses
        ]
        result["rate_limited"] = any(
            getattr(r, "status_code", None) in (429, 503) for r in responses
        )
        result["timing"] = self._timing(responses)

        # 3 — Bypass headers
        console.print("[cyan]Testing rate limit bypass headers...[/cyan]")
        result["bypass_findings"] = self._bypass_test(url)

        self._print_results(result)
        return result

    # ── Internal ──────────────────────────────────────────────────────────────

    def _scan_headers(self, url):
        found = {}
        try:
            r = self.session.head(url)
            for h in RATE_LIMIT_HEADERS:
                v = r.headers.get(h)
                if v:
                    found[h] = v
                    console.print(f"  [green]Found:[/green] {h}: {v}")
        except requests.RequestException as e:
            console.print(f"  [red]Header scan failed: {e}[/red]")
        if not found:
            console.print("  [yellow]No rate limit headers detected.[/yellow]")
        return found

    def _rapid_probe(self, url):
        responses = []
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      console=console) as prog:
            task = prog.add_task("  Probing...", total=self.num_requests)
            for i in range(self.num_requests):
                try:
                    r = self.session.session.get(url, timeout=self.session.timeout)
                    responses.append(r)
                    if self.verbose:
                        console.print(f"  [{i+1:02d}] HTTP {r.status_code}", highlight=False)
                    if r.status_code == 429:
                        console.print(f"  [red]Rate limit hit at request {i+1}[/red]")
                except requests.RequestException as e:
                    responses.append(e)
                prog.advance(task)
                time.sleep(0.1)
        return responses

    def _timing(self, responses):
        times = [
            r.elapsed.total_seconds() * 1000
            for r in responses
            if isinstance(r, requests.Response) and hasattr(r, "elapsed")
        ]
        if not times:
            return {}
        result = {
            "min_ms":   round(min(times), 1),
            "max_ms":   round(max(times), 1),
            "mean_ms":  round(statistics.mean(times), 1),
            "stdev_ms": round(statistics.stdev(times), 1) if len(times) > 1 else 0,
        }
        if len(times) >= 4:
            first  = statistics.mean(times[:len(times)//2])
            second = statistics.mean(times[len(times)//2:])
            if second > first * 1.5:
                result["soft_throttle"] = True
                result["throttle_note"] = (
                    f"Response time rose from ~{first:.0f}ms to ~{second:.0f}ms "
                    "mid-session — possible soft throttling."
                )
        return result

    def _bypass_test(self, url):
        findings = []
        try:
            baseline = self.session.get(url)
            base_code = baseline.status_code
        except requests.RequestException:
            return findings

        for headers in BYPASS_HEADERS:
            try:
                r    = self.session.get_with_headers(url, headers)
                name = list(headers.keys())[0]
                if r.status_code != base_code:
                    findings.append({
                        "header":        name,
                        "value":         headers[name],
                        "baseline_code": base_code,
                        "bypass_code":   r.status_code,
                        "severity":      "High",
                        "detail":        f"Response changed {base_code} → {r.status_code} "
                                         f"when '{name}' injected.",
                    })
                    console.print(
                        f"  [red][High][/red] {name}: {base_code} → {r.status_code}"
                    )
                elif self.verbose:
                    console.print(f"  [dim]{name}: no change ({r.status_code})[/dim]")
            except requests.RequestException:
                pass

        if not findings:
            console.print("  [green]No bypass headers caused response change.[/green]")
        return findings

    def _print_results(self, result):
        codes = [c for c in result["status_codes"] if c]
        if codes:
            dist  = Counter(codes)
            t = Table(title="Status Code Distribution", box=box.SIMPLE,
                      header_style="bold cyan")
            t.add_column("HTTP Status", style="white")
            t.add_column("Count",       style="bold")
            t.add_column("Assessment",  style="dim")
            for code, count in sorted(dist.items()):
                if code == 429:
                    note = "[red]Rate limited[/red]"
                elif code == 200:
                    note = "[green]OK[/green]"
                elif code == 503:
                    note = "[yellow]Possible throttle[/yellow]"
                else:
                    note = str(code)
                t.add_row(str(code), str(count), note)
            console.print(t)

        tm = result.get("timing", {})
        if tm:
            console.print(
                f"  Timing — min: [cyan]{tm.get('min_ms')}ms[/cyan]  "
                f"mean: [cyan]{tm.get('mean_ms')}ms[/cyan]  "
                f"max: [cyan]{tm.get('max_ms')}ms[/cyan]  "
                f"σ: [dim]{tm.get('stdev_ms')}ms[/dim]"
            )
            if tm.get("soft_throttle"):
                console.print(f"  [yellow]{tm['throttle_note']}[/yellow]")

        console.print()
        if result["rate_limited"]:
            console.print("  [green]Rate limiting active (HTTP 429 detected).[/green]")
        else:
            console.print(
                "  [yellow]No hard rate limit triggered in this test window.[/yellow]\n"
                "  [dim]Consider increasing --ratelimit-requests for a deeper probe.[/dim]"
            )
