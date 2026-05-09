"""Reporter — consolidated summary table with remediation column and JSON export."""

import json
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.rule import Rule
from rich import box

console = Console()

# ── Remediation tags — short labels for the summary table ────────────────────
REMEDIATION = {
    # detect
    "no_captcha":         "Evaluate if CAPTCHA protection is needed",
    "weak_provider":      "Migrate to stronger provider (Turnstile / hCaptcha / reCAPTCHA v3)",
    "captcha_found":      "Verify server-side token validation is enforced",

    # resilience
    "missing_field":      "Add server-side CAPTCHA field requirement",
    "empty_token":        "Reject empty tokens server-side — call provider verification API",
    "field_removal":      "Enforce CAPTCHA field presence — reject requests without it",
    "low_entropy":        "Replace with cryptographically random token (min 32 chars)",
    "honeypot":           "Ensure honeypot fields are not filled by legitimate users",
    "resilience_ok":      "No action required — implementation appears solid",

    # ratelimit
    "no_ratelimit":       "Implement lockout after 3–5 failed attempts per IP and account",
    "bypass_headers":     "Strip untrusted IP headers at application boundary",
    "soft_throttle":      "Harden throttle — enforce hard limit with HTTP 429",
    "ratelimit_ok":       "No action required — rate limiting is active",

    # antibot
    "no_waf":             "Place application behind WAF/CDN (Cloudflare, AWS WAF)",
    "no_botmgmt":         "Consider bot management layer for high-risk endpoints",
    "missing_headers":    "Add missing security headers at server or CDN level",
    "antibot_ok":         "No action required — defensive stack detected",
}

# ── Full remediation detail — expanded per finding ───────────────────────────
REMEDIATION_DETAIL = {
    "weak_provider": (
        "The current CAPTCHA provider offers insufficient resistance to automated solvers. "
        "Migrate to Cloudflare Turnstile (free, no user interaction required), hCaptcha, "
        "or reCAPTCHA v3 (score-based, invisible). Custom math/text CAPTCHAs are solvable "
        "by basic OCR tools and should be replaced entirely."
    ),
    "empty_token": (
        "The server accepted a blank CAPTCHA token without rejection. Every protected form "
        "submission must be validated server-side by calling the provider's verification "
        "API before processing the request. For reCAPTCHA: POST to "
        "https://www.google.com/recaptcha/api/siteverify with the token and secret key. "
        "Reject the request if the API returns success=false. Tokens must be single-use — "
        "invalidate after verification to prevent replay attacks."
    ),
    "field_removal": (
        "The server processed the form successfully when the CAPTCHA field was removed "
        "from the request entirely. This means server-side validation is absent. The "
        "CAPTCHA field must be treated as required — requests missing it should return "
        "HTTP 400 or 403 immediately, before any business logic executes."
    ),
    "no_ratelimit": (
        "No rate limiting was detected. Implement account lockout after 3–5 failed "
        "CAPTCHA verifications within a rolling time window (recommended: 15 minutes). "
        "Rate limit by both IP address and account/session identifier — IP-only limits "
        "are bypassable. Return HTTP 429 with a Retry-After header on limit breach."
    ),
    "bypass_headers": (
        "One or more IP spoofing headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP, "
        "etc.) caused a different server response, indicating the application trusts "
        "client-supplied IP headers for rate limiting or access decisions. Strip or ignore "
        "these headers at the application boundary unless they are injected by a trusted "
        "upstream proxy the client cannot control. Never use client-supplied IP headers "
        "as the sole basis for rate limiting."
    ),
    "no_waf": (
        "No WAF or CDN layer was detected in front of the application. Place the "
        "application behind Cloudflare (free tier covers basic bot protection), AWS WAF, "
        "or an equivalent service. This adds TLS fingerprinting, behavioural analysis, "
        "and volumetric protection that a CAPTCHA alone cannot provide."
    ),
    "missing_headers": (
        "One or more critical security headers are absent. Add the following at the web "
        "server or CDN level: Content-Security-Policy (whitelist CAPTCHA provider domains "
        "explicitly), Strict-Transport-Security (max-age=31536000; includeSubDomains), "
        "X-Frame-Options: DENY, X-Content-Type-Options: nosniff, "
        "Referrer-Policy: strict-origin-when-cross-origin."
    ),
}

PRIORITY_ORDER = {
    "High":   1,
    "Medium": 2,
    "Low":    3,
    "Info":   4,
}


class Reporter:

    def __init__(self, results: dict):
        self.results      = results
        self.timestamp    = datetime.utcnow().isoformat() + "Z"
        self._detail_keys = []   # collect which detail blocks to print

    def print_summary(self):
        console.rule("[bold white]Summary[/bold white]")
        console.print(f"\n[bold]Target:[/bold]  {self.results.get('target')}")
        console.print(f"[bold]Scanned:[/bold] {self.timestamp}\n")

        rows = self._build_rows()

        # ── Summary table ─────────────────────────────────────────────────────
        t = Table(box=box.ROUNDED, header_style="bold cyan",
                  show_lines=True, expand=False)
        t.add_column("Module",        style="white",  min_width=24)
        t.add_column("Result",        style="bold",   min_width=28)
        t.add_column("Severity",      min_width=10)
        t.add_column("Remediation",   style="dim",    min_width=42)

        for row in sorted(rows, key=lambda r: PRIORITY_ORDER.get(r["severity"], 5)):
            col = {
                "High":   "red",
                "Medium": "yellow",
                "Low":    "cyan",
                "Info":   "dim",
            }.get(row["severity"], "white")

            t.add_row(
                row["module"],
                row["result"],
                f"[{col}]{row['severity']}[/{col}]",
                f"[white]→[/white] {row['remediation']}",
            )

        console.print(t)
        console.print()

        # ── Remediation detail ────────────────────────────────────────────────
        if self._detail_keys:
            console.rule("[bold white]Remediation Detail[/bold white]")
            seen = []
            counter = 1
            for key in self._detail_keys:
                if key in REMEDIATION_DETAIL and key not in seen:
                    seen.append(key)
                    console.print(
                        f"\n  [bold cyan][{counter}][/bold cyan] "
                        f"[bold white]{self._key_to_title(key)}[/bold white]"
                    )
                    console.print(
                        f"  [dim]{REMEDIATION_DETAIL[key]}[/dim]"
                    )
                    counter += 1
            console.print()

    # ── Row builders ──────────────────────────────────────────────────────────

    def _build_rows(self):
        rows = []
        m    = self.results.get("modules", {})

        # detect
        d = m.get("detect", {})
        if d:
            count = d.get("captcha_count", 0)
            if count == 0:
                rows.append(self._row(
                    "CAPTCHA Fingerprinting",
                    "No CAPTCHA detected",
                    "Info",
                    "no_captcha",
                ))
            else:
                findings = d.get("findings", [])
                weak     = any(f.get("risk") in ("Low",) for f in findings)
                rkey     = "weak_provider" if weak else "captcha_found"
                rows.append(self._row(
                    "CAPTCHA Fingerprinting",
                    f"{count} CAPTCHA type(s) found",
                    "Medium" if weak else "Low",
                    rkey,
                ))
                if weak:
                    self._detail_keys.append("weak_provider")

        # resilience
        r = m.get("resilience", {})
        if r:
            findings = r.get("findings", [])
            highs    = [f for f in findings if f.get("severity") == "High"]
            meds     = [f for f in findings if f.get("severity") == "Medium"]

            if highs:
                # pick the most critical finding for the row
                top      = highs[0]
                rkey     = self._resilience_key(top["check"])
                rows.append(self._row(
                    "Resilience Testing",
                    f"{len(highs)} high-severity weakness(es)",
                    "High",
                    rkey,
                ))
                for f in highs:
                    k = self._resilience_key(f["check"])
                    self._detail_keys.append(k)
            elif meds:
                top  = meds[0]
                rkey = self._resilience_key(top["check"])
                rows.append(self._row(
                    "Resilience Testing",
                    f"{len(meds)} medium-severity weakness(es)",
                    "Medium",
                    rkey,
                ))
                for f in meds:
                    k = self._resilience_key(f["check"])
                    self._detail_keys.append(k)
            else:
                rows.append(self._row(
                    "Resilience Testing",
                    "No weaknesses found",
                    "Low",
                    "resilience_ok",
                ))

        # ratelimit
        rl = m.get("ratelimit", {})
        if rl:
            bypasses = rl.get("bypass_findings", [])
            if bypasses:
                rows.append(self._row(
                    "Rate Limit Analysis",
                    f"{len(bypasses)} bypass header(s) effective",
                    "High",
                    "bypass_headers",
                ))
                self._detail_keys.append("bypass_headers")
            elif not rl.get("rate_limited"):
                rows.append(self._row(
                    "Rate Limit Analysis",
                    "No rate limit triggered",
                    "Medium",
                    "no_ratelimit",
                ))
                self._detail_keys.append("no_ratelimit")
            else:
                tm = rl.get("timing", {})
                if tm.get("soft_throttle"):
                    rows.append(self._row(
                        "Rate Limit Analysis",
                        "Soft throttle only — no hard limit",
                        "Medium",
                        "soft_throttle",
                    ))
                else:
                    rows.append(self._row(
                        "Rate Limit Analysis",
                        "Rate limiting active",
                        "Info",
                        "ratelimit_ok",
                    ))

        # antibot
        ab = m.get("antibot", {})
        if ab:
            wafs     = len(ab.get("waf", []))
            bots     = len(ab.get("bot_management", []))
            missing  = [
                h for h, info in ab.get("security_headers", {}).items()
                if not info.get("present")
            ]

            if wafs == 0 and bots == 0:
                rows.append(self._row(
                    "Anti-Automation Mapping",
                    "No WAF or bot management detected",
                    "Medium",
                    "no_waf",
                ))
                self._detail_keys.append("no_waf")
            else:
                parts = []
                if wafs: parts.append(f"{wafs} WAF")
                if bots: parts.append(f"{bots} bot mgmt")
                rows.append(self._row(
                    "Anti-Automation Mapping",
                    ", ".join(parts) + " detected",
                    "Info",
                    "antibot_ok",
                ))

            if missing:
                rows.append(self._row(
                    "Security Headers",
                    f"{len(missing)} header(s) missing",
                    "Medium",
                    "missing_headers",
                ))
                self._detail_keys.append("missing_headers")

        return rows

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _row(self, module, result, severity, rkey):
        return {
            "module":      module,
            "result":      result,
            "severity":    severity,
            "remediation": REMEDIATION.get(rkey, "Review finding and apply appropriate fix"),
        }

    def _resilience_key(self, check_name: str) -> str:
        check = check_name.lower()
        if "missing" in check and "field" in check:
            return "missing_field"
        if "empty" in check:
            return "empty_token"
        if "removal" in check or "without" in check:
            return "field_removal"
        if "entropy" in check:
            return "low_entropy"
        if "honeypot" in check:
            return "honeypot"
        return "resilience_ok"

    def _key_to_title(self, key: str) -> str:
        titles = {
            "weak_provider":   "Migrate to a Stronger CAPTCHA Provider",
            "empty_token":     "Enforce Server-Side Token Validation",
            "field_removal":   "Require CAPTCHA Field on Every Submission",
            "no_ratelimit":    "Implement Rate Limiting and Account Lockout",
            "bypass_headers":  "Strip Untrusted IP Spoofing Headers",
            "no_waf":          "Deploy WAF / CDN Protection Layer",
            "missing_headers": "Add Missing HTTP Security Headers",
            "low_entropy":     "Replace Low-Entropy Token with Secure Random Value",
        }
        return titles.get(key, key.replace("_", " ").title())

    def save_json(self, path: str):
        payload = {
            "tool":      "CaptchaRecon",
            "version":   "1.0.0",
            "license":   "GPL v3",
            "author":    "Ariful Islam Mazumdar (arif-offsec)",
            "timestamp": self.timestamp,
            "target":    self.results.get("target"),
            "modules":   self.results.get("modules", {}),
        }
        with open(path, "w") as fh:
            json.dump(payload, fh, indent=2, default=str)
