"""
Resilience Testing Module
Tests CAPTCHA implementation weaknesses — missing server-side validation,
empty token submission, field removal, low-entropy tokens, honeypots.
"""

import re
from typing import Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

CAPTCHA_FIELD_NAMES = [
    "g-recaptcha-response", "h-captcha-response",
    "cf-turnstile-response", "captcha", "captcha_token",
    "captcha_response", "recaptcha_token", "token",
]


class ResilienceTester:

    def __init__(self, session, verbose=False):
        self.session = session
        self.verbose = verbose

    def run(self, url, **_):
        findings = []
        console.print(f"[cyan]Analysing forms on:[/cyan] {url}")

        try:
            resp = self.session.get(url)
        except requests.RequestException as e:
            console.print(f"[red]Request failed: {e}[/red]")
            return {"error": str(e)}

        soup  = BeautifulSoup(resp.text, "lxml")
        forms = soup.find_all("form")

        if not forms:
            console.print("  [yellow]No HTML forms found on this page.[/yellow]")
            return {"forms": 0, "findings": []}

        console.print(f"  Found [bold]{len(forms)}[/bold] form(s).\n")

        for i, form in enumerate(forms):
            action   = form.get("action", "")
            method   = form.get("method", "GET").upper()
            form_url = urljoin(url, action) if action else url

            console.print(f"  [bold cyan]Form {i+1}:[/bold cyan] {method} {form_url}")

            for check in [
                self._check_missing_field(form, form_url, method),
                self._check_empty_token(form, form_url, method),
                self._check_field_removal(form, form_url, method),
                self._check_entropy(form, resp.text),
                self._check_honeypots(form),
            ]:
                if check:
                    findings.append(check)
                    self._print_finding(check)

        self._print_summary(findings)
        return {"forms_tested": len(forms), "findings": findings}

    # ── Checks ────────────────────────────────────────────────────────────────

    def _check_missing_field(self, form, url, method):
        inputs = {i.get("name", "").lower() for i in form.find_all(["input", "textarea"])}
        found  = [c for c in CAPTCHA_FIELD_NAMES if c in inputs]
        if not found:
            return {
                "check":    "Missing CAPTCHA response field",
                "severity": "Medium",
                "detail":   "No known CAPTCHA response field in form inputs. "
                            "Server-side validation may be absent.",
                "url": url,
            }
        return None

    def _check_empty_token(self, form, url, method):
        data   = self._form_data(form)
        fields = [k for k in data if any(c in k.lower() for c in ["captcha", "recaptcha"])]
        if not fields:
            return None
        for f in fields:
            data[f] = ""
        try:
            r = self.session.post(url, data=data) if method == "POST" \
                else self.session.get(url, params=data)
            if r.status_code == 200 and not self._captcha_error(r.text):
                return {
                    "check":    "Empty CAPTCHA token accepted",
                    "severity": "High",
                    "detail":   f"Blank CAPTCHA token returned HTTP {r.status_code} "
                                "with no rejection detected.",
                    "url": url, "response_code": r.status_code,
                }
        except requests.RequestException:
            pass
        return None

    def _check_field_removal(self, form, url, method):
        data    = self._form_data(form)
        stripped = {k: v for k, v in data.items()
                    if not any(c in k.lower() for c in ["captcha", "recaptcha"])}
        if len(stripped) == len(data):
            return None
        try:
            r = self.session.post(url, data=stripped) if method == "POST" \
                else self.session.get(url, params=stripped)
            if r.status_code == 200 and not self._captcha_error(r.text):
                return {
                    "check":    "Form accepted without CAPTCHA field",
                    "severity": "High",
                    "detail":   f"CAPTCHA field removed — server returned HTTP {r.status_code} "
                                "with no error. Server-side validation appears absent.",
                    "url": url, "response_code": r.status_code,
                }
        except requests.RequestException:
            pass
        return None

    def _check_entropy(self, form, html):
        patterns = [
            (r'captcha[_-]?token["\']?\s*[:=]\s*["\']([a-z0-9]{4,12})["\']',
             "Short alphanumeric token — low entropy"),
            (r'captcha["\']?\s*[:=]\s*["\'](\d{4,8})["\']',
             "Pure numeric token — very weak"),
        ]
        for pattern, label in patterns:
            m = re.search(pattern, html, re.I)
            if m:
                return {
                    "check":    "Low-entropy CAPTCHA token",
                    "severity": "Medium",
                    "detail":   f"{label}: '{m.group(1)}'",
                    "token":    m.group(1),
                }
        return None

    def _check_honeypots(self, form):
        honeypots = []
        for inp in form.find_all("input"):
            style = inp.get("style", "")
            typ   = inp.get("type", "text")
            name  = inp.get("name", "")
            if typ == "hidden":
                continue
            if re.search(r"display\s*:\s*none|visibility\s*:\s*hidden", style, re.I):
                honeypots.append(name or "(unnamed)")
        if honeypots:
            return {
                "check":    "Honeypot fields detected",
                "severity": "Info",
                "detail":   f"Hidden input fields (bot traps): {', '.join(honeypots)}. "
                            "Automated tools filling all fields will trigger these.",
                "fields":   honeypots,
            }
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _form_data(self, form):
        data = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                data[name] = inp.get("value", "")
        return data

    def _captcha_error(self, text):
        return any(p in text.lower() for p in [
            "captcha", "robot", "verification failed",
            "invalid token", "prove you are human", "challenge",
        ])

    def _print_finding(self, f):
        col   = {"High": "red", "Medium": "yellow", "Low": "cyan", "Info": "dim"}.get(
            f.get("severity", "Info"), "white")
        console.print(f"    [{col}][{f['severity']}][/{col}] {f['check']}")
        console.print(f"    [dim]{f['detail']}[/dim]\n")

    def _print_summary(self, findings):
        if not findings:
            console.print("  [green]No resilience weaknesses detected.[/green]")
            return
        t = Table(box=box.SIMPLE, header_style="bold cyan")
        t.add_column("Check",    style="white",  min_width=35)
        t.add_column("Severity", min_width=10)
        t.add_column("Detail",   style="dim",    min_width=50)
        for f in findings:
            col = {"High": "red", "Medium": "yellow", "Low": "cyan", "Info": "dim"}.get(
                f.get("severity", "Info"), "white")
            detail = f["detail"][:80] + "…" if len(f["detail"]) > 80 else f["detail"]
            t.add_row(f["check"], f"[{col}]{f['severity']}[/{col}]", detail)
        console.print(t)
