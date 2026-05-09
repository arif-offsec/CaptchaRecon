# CaptchaRecon

```
  ____           _       _           ____
 / ___|__ _ _ __| |_ ___| |__   __ _|  _ \ ___  ___ ___  _ __
| |   / _` | '_ \ __/ __| '_ \ / _` | |_) / _ \/ __/ _ \| '_ \
| |__| (_| | |_) | || (__| | | | (_| |  _ <  __/ (_| (_) | | | |
 \____\__,_| .__/ \__\___|_| |_|\__,_|_| \_\___|\___\___/|_| |_|
           |_|
CAPTCHA & Anti-Automation Reconnaissance Toolkit
```

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platform: Kali Linux](https://img.shields.io/badge/platform-Kali%20Linux-557C94.svg)]()
[![Ethical Use Only](https://img.shields.io/badge/use-authorised%20only-red.svg)]()

> **For authorised penetration testing and security research only.**
> Running this tool against systems without explicit written permission may violate
> computer crime laws in your jurisdiction.

---

## What is CaptchaRecon?

CaptchaRecon is a modular reconnaissance and analysis toolkit for web application
penetration testers. It maps the **entire anti-automation defence stack** of a target
application — not to bypass it, but to understand it, identify misconfigurations,
and document findings for a professional pentest report.

It does **NOT** solve, bypass, or interact with any CAPTCHA.

---

## Modules

| Module | What it does |
|---|---|
| **detect** | Identifies CAPTCHA type, version, provider, and exposed sitekeys from HTML/JS |
| **resilience** | Tests implementation weaknesses — missing server-side validation, empty tokens, field removal |
| **ratelimit** | Probes throttling, rate limit headers, timing analysis, and IP bypass header effectiveness |
| **antibot** | Detects WAFs, bot management platforms, fingerprinting libraries, and security header gaps |

---

## Open-Source Dependencies

All integrated libraries are free and open-source. No proprietary tools.

| Package | Licence | Purpose |
|---|---|---|
| [requests](https://github.com/psf/requests) | Apache 2.0 | HTTP client |
| [beautifulsoup4](https://www.crummy.com/software/BeautifulSoup/) | MIT | HTML parsing |
| [rich](https://github.com/Textualize/rich) | MIT | Terminal output |
| [urllib3](https://github.com/urllib3/urllib3) | MIT | HTTP transport |
| [lxml](https://github.com/lxml/lxml) | BSD | Fast HTML/XML parser |
| [certifi](https://github.com/certifi/python-certifi) | MPL 2.0 | CA certificates |

---

## Installation (Kali Linux)

```bash
git clone https://github.com/arif-offsec/captcharecon.git
cd captcharecon
sudo bash install.sh
```

The installer:
- Updates apt package lists
- Installs and upgrades all Python dependencies to their latest versions
- Installs the `captcharecon` command system-wide
- Installs the man page (`man captcharecon`)
- Creates a config file at `/etc/captcharecon/captcharecon.conf`

To uninstall:

```bash
sudo bash uninstall.sh
```

---

## Usage

### Full scan — all modules

```bash
captcharecon -u https://target.com/login
```

### Specific modules

```bash
captcharecon -u https://target.com/login --modules detect antibot
```

### Route through Burp Suite / Caido / ZAP

```bash
captcharecon -u https://target.com/login --proxy http://127.0.0.1:8080
```

### Deep rate limit probe

```bash
captcharecon -u https://target.com/login --ratelimit-requests 30 --delay 0.3
```

### Save JSON report

```bash
captcharecon -u https://target.com/login --full --output report.json
```

### Full options

```
-u, --url URL                Target URL (required)
--modules [...]              Modules: detect resilience ratelimit antibot
--full                       Run all modules with extended checks
--output FILE                Save JSON report to FILE
--proxy URL                  Proxy URL (Burp / Caido / ZAP)
--delay SECS                 Delay between requests (default: 1.0)
--timeout SECS               Request timeout (default: 10)
--ratelimit-requests N       Requests for rate limit probing (default: 10)
--user-agent UA              Custom User-Agent string
--no-banner                  Suppress ASCII banner
-v, --verbose                Verbose output
```

---

## Manual Page

```bash
man captcharecon
```

The man page covers all options, modules, output format, proxy integration,
open-source dependency licences, and ethical use requirements.

---

## CAPTCHA Providers Detected

- reCAPTCHA v2 (Checkbox)
- reCAPTCHA v3 (Invisible / Enterprise)
- hCaptcha
- Cloudflare Turnstile
- FunCaptcha / Arkose Labs
- GeeTest (Slide Puzzle)
- KeyCAPTCHA
- Math / Text CAPTCHA (custom implementations)

---

## WAF / Bot Management Detected

**WAF / CDN:** Cloudflare, Akamai, AWS WAF/CloudFront, Imperva Incapsula,
F5 BIG-IP ASM, ModSecurity, Sucuri

**Bot Management:** DataDome, PerimeterX/HUMAN Security, Cloudflare Bot Management,
Kasada, Akamai Bot Manager, Radware Bot Manager, Shape Security/F5

**Fingerprinting:** FingerprintJS, ThreatMetrix, Sift Science, Mouseflow,
Hotjar, FullStory

---

## Output

### Terminal
Rich-formatted tables with colour-coded severity — CRITICAL, HIGH, MEDIUM, LOW, INFO.

### JSON
```bash
captcharecon -u https://target.com/login --output findings.json
```

```json
{
  "tool": "CaptchaRecon",
  "version": "1.0.0",
  "license": "GPL v3",
  "timestamp": "2025-04-26T10:00:00Z",
  "target": "https://target.com/login",
  "modules": {
    "detect":     { "captcha_found": true, "findings": [...] },
    "resilience": { "forms_tested": 1,     "findings": [...] },
    "ratelimit":  { "rate_limited": false,  "bypass_findings": [...] },
    "antibot":    { "waf": [...],           "security_headers": {...} }
  }
}
```

---

## Proxy Integration

Works with Burp Suite, Caido, and OWASP ZAP out of the box.

```bash
# Burp Suite / Caido
captcharecon -u https://target.com/login --proxy http://127.0.0.1:8080

# OWASP ZAP
captcharecon -u https://target.com/login --proxy http://127.0.0.1:8090
```

When testing HTTPS targets through an intercepting proxy, ensure the proxy
CA certificate is installed in the system trust store.

---

## Project Structure

```
captcharecon/
├── captcharecon/
│   ├── __init__.py
│   ├── cli.py              ← entry point, arg parsing, ethics prompt
│   ├── core/
│   │   ├── detector.py     ← CAPTCHA fingerprinting (8 providers)
│   │   ├── resilience.py   ← 5 implementation weakness checks
│   │   ├── ratelimit.py    ← header scan + rapid probe + 9 bypass headers
│   │   ├── antibot.py      ← WAF/bot mgmt/fingerprinting/security headers
│   │   └── reporter.py     ← summary table + JSON export
│   └── utils/
│       └── http.py         ← shared session, throttle, proxy support
├── man/
│   └── captcharecon.1      ← man page source
├── install.sh              ← system-wide installer
├── uninstall.sh            ← clean uninstaller
├── setup.py
├── requirements.txt        ← all open-source dependencies with licences
├── LICENSE                 ← GPL v3
└── README.md
```

---

## Ethical Use

This tool is designed for:

- Authorised web application penetration tests
- Bug bounty hunting within defined scope
- Security research on systems you own or have permission to test
- Defensive security — understanding your own application's exposure

Misuse may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse
Act, and equivalent legislation in other jurisdictions. The ethics acknowledgement
prompt at startup is mandatory.

---

## Contributing

Pull requests are welcome. If you find a new CAPTCHA provider, WAF signature,
or bot management platform not covered, open an issue or PR.

---

## License

GPL v3 — Free and open-source forever. See [LICENSE](LICENSE).
