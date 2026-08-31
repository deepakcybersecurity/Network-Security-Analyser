# Security Policy

Aegis Scanner is a security tool, so its own security posture matters. This document covers
how to report a vulnerability in Aegis itself, and the boundaries of responsible use.

## Supported versions

This project is developed on `main`. Only the latest commit on `main` receives security
fixes — please confirm an issue reproduces there before reporting it.

| Version | Supported |
| --- | --- |
| `main` (latest) | ✅ |
| Older tags / forks | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately through either channel:

1. **GitHub Security Advisories** — preferred. Open the
   [Security tab](https://github.com/deepakcybersecurity/Network-Security-Analyser/security/advisories/new)
   and file a private advisory. This keeps the report confidential and gives you credit
   when a fix ships.
2. **Email** — <pantdeepak980@gmail.com> with `[SECURITY]` in the subject line.

Please include, as far as you are able:

- The affected file and, ideally, the specific line or route.
- The class of issue (injection, XSS, path traversal, auth bypass, DoS, and so on).
- Reproduction steps, a proof-of-concept request, or a failing test.
- The impact you believe an attacker could achieve.
- Your environment: OS, Python version, Nmap version.

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement of your report | Within 5 days |
| Initial assessment and severity triage | Within 14 days |
| Fix or documented mitigation for confirmed issues | Best effort, prioritised by severity |

This is a solo-maintained educational project without a funded security programme, so these
are good-faith targets rather than a contractual SLA. There is no bug bounty. Credit in the
release notes and advisory is offered for every valid report unless you prefer otherwise.
Please give a reasonable window for a fix before disclosing publicly.

## Scope

### In scope

Vulnerabilities in this repository's own code, including:

- Bypasses of the target validation in `scanner.py` — anything that gets unintended
  arguments or shell metacharacters through to Nmap.
- Command injection, SQL injection, or path traversal in any route.
- Stored or reflected XSS in the dashboard, or a Content Security Policy bypass.
- Information disclosure through error messages, logs, headers, or API responses.
- Bypasses of the rate limiting on `POST /api/scan`.
- Insecure defaults that would harm someone following the documented setup.

### Out of scope

- **Vulnerabilities in Nmap itself** — report those to the
  [Nmap project](https://nmap.org/book/man-bugs.html).
- **Vulnerabilities in third-party dependencies** — report upstream. Dependabot tracks
  advisories here; open a normal issue if an update needs to be applied.
- **Findings that require an already-compromised host** or local filesystem access.
- **Risks inherent to the documented design**, all of which are stated in the README's
  *Known limitations*: no authentication, Flask's development server, in-memory rate-limit
  storage, and localhost-only binding. Reports that Aegis is unsafe when deliberately
  exposed to the internet describe intended behaviour, not a vulnerability.
- **Reports that the tool can scan ports.** That is its documented purpose.
- Automated scanner output submitted without a demonstrated impact.

## Responsible use

Aegis performs active network reconnaissance. Unauthorised port scanning is a criminal
offence in many jurisdictions, can disrupt the systems it touches, and will trigger
security monitoring.

**Only scan systems you own or have explicit written authorisation to test.**

Do not use this project, or any modification of it, to scan third-party infrastructure
without permission. The maintainer accepts no liability for misuse. If you are testing
against a target you do not control, stop and obtain authorisation first.

## Hardening notes for operators

If you run Aegis anywhere beyond a trusted local machine:

- Set `SECRET_KEY` to a persistent, cryptographically random value.
- Leave `FLASK_DEBUG` unset or `false`. Never enable it on a network-reachable host.
- Replace the Flask development server with a production WSGI server behind a reverse
  proxy that terminates TLS.
- Add authentication in front of the application — there is none built in.
- Back Flask-Limiter with Redis so limits survive restarts and apply across workers.
- Keep `instance/` off version control and treat the SQLite database as sensitive; it
  records which hosts were scanned and what was found.
