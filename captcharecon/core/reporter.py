"""Reporter — consolidated summary table and JSON export."""

import json
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


class Reporter:

    def __init__(self, results: dict):
        self.results   = results
        self.timestamp = datetime.utcnow().isoformat() + "Z"

    def print_summary(self):
        console.rule("[bold white]Summary[/bold white]")
        console.print(f"\n[bold]Target:[/bold]  {self.results.get('target')}")
        console.print(f"[bold]Scanned:[/bold] {self.timestamp}\n")

        t = Table(box=box.ROUNDED, header_style="bold cyan", show_lines=False)
        t.add_column("Module",   style="white",  min_width=24)
        t.add_column("Result",   style="bold",   min_width=28)
        t.add_column("Severity", min_width=10)

        m = self.results.get("modules", {})

        d = m.get("detect", {})
        if d:
            count = d.get("captcha_count", 0)
            label = f"{count} CAPTCHA type(s) found" if count else "No CAPTCHA detected"
            col   = "yellow" if count else "dim"
            sev   = "Medium" if count else "Info"
            t.add_row("CAPTCHA Fingerprinting", label, f"[{col}]{sev}[/{col}]")

        r = m.get("resilience", {})
        if r:
            findings = r.get("findings", [])
            highs = [f for f in findings if f.get("severity") == "High"]
            meds  = [f for f in findings if f.get("severity") == "Medium"]
            if highs:
                label, col, sev = f"{len(highs)} high-severity weakness(es)", "red", "High"
            elif meds:
                label, col, sev = f"{len(meds)} medium-severity weakness(es)", "yellow", "Medium"
            else:
                label, col, sev = "No weaknesses found", "green", "Low"
            t.add_row("Resilience Testing", label, f"[{col}]{sev}[/{col}]")

        rl = m.get("ratelimit", {})
        if rl:
            bypasses = len(rl.get("bypass_findings", []))
            if bypasses:
                label, col, sev = f"{bypasses} bypass header(s) effective", "red", "High"
            elif rl.get("rate_limited"):
                label, col, sev = "Rate limiting active", "green", "Info"
            else:
                label, col, sev = "No rate limit triggered", "yellow", "Medium"
            t.add_row("Rate Limit Analysis", label, f"[{col}]{sev}[/{col}]")

        ab = m.get("antibot", {})
        if ab:
            wafs = len(ab.get("waf", []))
            bots = len(ab.get("bot_management", []))
            fp   = len(ab.get("fingerprinting", []))
            parts = []
            if wafs: parts.append(f"{wafs} WAF")
            if bots: parts.append(f"{bots} bot mgmt")
            if fp:   parts.append(f"{fp} fingerprinting")
            label = ", ".join(parts) if parts else "No defenses detected"
            col   = "cyan" if parts else "yellow"
            sev   = "Info" if parts else "Medium"
            t.add_row("Anti-Automation Mapping", label, f"[{col}]{sev}[/{col}]")

        console.print(t)
        console.print()
        self._action_items()

    def _action_items(self):
        items = []
        m = self.results.get("modules", {})

        for f in m.get("resilience", {}).get("findings", []):
            if f.get("severity") in ("High", "Medium"):
                detail = f.get("detail", "")
                short  = detail[:70] + "..." if len(detail) > 70 else detail
                items.append(f"[red]>[/red] {f['check']}: {short}")

        for b in m.get("ratelimit", {}).get("bypass_findings", []):
            items.append(
                f"[red]>[/red] Rate limit bypass via {b['header']}: "
                f"{b['detail'][:60]}"
            )

        rl = m.get("ratelimit", {})
        if not rl.get("rate_limited") and not rl.get("bypass_findings"):
            items.append(
                "[yellow]>[/yellow] No rate limiting detected — brute force may be viable"
            )

        missing_hdrs = [
            h for h, info in
            m.get("antibot", {}).get("security_headers", {}).items()
            if not info.get("present")
        ]
        if missing_hdrs:
            items.append(
                f"[yellow]>[/yellow] Missing security headers: {', '.join(missing_hdrs[:4])}"
            )

        if items:
            console.print("[bold]Action Items:[/bold]")
            for item in items:
                console.print(f"  {item}")
        else:
            console.print(
                "[green]No critical action items. "
                "Target appears well-hardened for tested vectors.[/green]"
            )
        console.print()

    def save_json(self, path: str):
        payload = {
            "tool":      "CaptchaRecon",
            "version":   "1.0.0",
            "license":   "GPL v3",
            "timestamp": self.timestamp,
            "target":    self.results.get("target"),
            "modules":   self.results.get("modules", {}),
        }
        with open(path, "w") as fh:
            json.dump(payload, fh, indent=2, default=str)
