# SecScan

[![CI and deploy](https://github.com/Sergio-Osorio09/SecScan/actions/workflows/deploy.yml/badge.svg)](https://github.com/Sergio-Osorio09/SecScan/actions/workflows/deploy.yml)

*[Léelo en español](README.md)*

**Scan your code and learn how to protect it.** SecScan finds security flaws in code and
configuration, and explains every finding in plain Spanish: **what it is, how you would be
attacked, and how to fix it**.

It runs **entirely in the browser**. No server, no sign-up, no cost — your code never leaves your
machine.

**Live demo:** https://sergio-osorio09.github.io/SecScan/

![SecScan analysing a vulnerable login: syntax-highlighted code on the left, findings with their teaching cards on the right](docs/consola.png)

**How to use it:** paste your code, drop a file onto the editor, or load one of the four one-click
examples. Severity chips filter the list, every finding links to its official OWASP and MITRE
entry, and the fixed code copies with a button.

> **Note on language.** The interface and every explanation are in Spanish, and that is the point:
> quality AppSec material in Spanish is scarce, especially in Latin America. This English README
> exists so the engineering behind it can be read by anyone.

---

## Why it exists

Static analysis tools tend to tell you *what* is wrong — in English, and assuming you already know
security. SecScan is built for the other side: every finding comes with a card that teaches. It
works both for a developer pasting their own code and for someone non-technical loading an example
with one click.

---

## What it detects

**24 rules** recognising around 90 concrete patterns, grouped by **OWASP Top 10 (2021)** category
and mapped to their **CWE**. The app lists all of them behind a panel, so anyone trying it out
knows what to look for.

| Rule | Severity | OWASP | CWE |
| --- | --- | --- | --- |
| SQL injection through string concatenation | Critical | A03 | CWE-89 |
| Hardcoded password or key | Critical | A07 | CWE-798 |
| Exposed AWS access key | Critical | A07 | CWE-798 |
| Known-provider credential, by its format | Critical | A07 | CWE-798 |
| File path built from outside input | High | A01 | CWE-22 |
| Unvalidated archive extraction (zip slip) | High | A01 | CWE-22 |
| OS command injection | High | A03 | CWE-78 |
| Use of `eval()` / `exec()` | High | A03 | CWE-95 |
| XSS: unsanitised HTML insertion | High | A03 | CWE-79 |
| Server-side template built from outside input | High | A03 | CWE-1336 |
| XML external entities (XXE) | High | A05 | CWE-611 |
| JWT read without verifying the signature | High | A07 | CWE-347 |
| Insecure deserialisation | High | A08 | CWE-502 |
| CSRF protection disabled | Medium | A01 | CWE-352 |
| Weak hash (MD5 / SHA-1) | Medium | A02 | CWE-327 |
| TLS certificate verification disabled | Medium | A02 | CWE-295 |
| Security value from a predictable random source | Medium | A02 | CWE-338 |
| Obsolete cipher or ECB mode | Medium | A02 | CWE-327 |
| CORS open to any origin | Medium | A05 | CWE-942 |
| Session cookie missing its security attributes | Medium | A05 | CWE-614 |
| Overly permissive file permissions | Medium | A05 | CWE-732 |
| Open redirect to an outside destination | Low | A01 | CWE-601 |
| Unencrypted HTTP connection | Low | A02 | CWE-319 |
| Debug mode enabled | Low | A05 | CWE-489 |

**Languages:** Python and JavaScript/TypeScript are covered end to end. Several rules also reach
**Java** and PHP, and generic configuration files — JSON, YAML, `.env`, Terraform — for everything
around secrets, HTTP, CORS, cookies and debug flags.

The editor tab shows the detected language, IDE-style, and the detector tells **Java from
JavaScript** — they share braces, semicolons and `null` — by looking for signals only Java has:
the package declaration, access modifiers before a method, generics, annotations. It is a label
only: **every rule always runs**, so a wrong guess can never hide a finding.

---

## How it works

```
code  →  prepararCodigo()  →  rules  →  findings  →  interface
```

1. **`prepararCodigo()`** walks the text with a small state machine that separates comments from
   single-, double-, triple-quoted strings and template literals. Comments are blanked while
   keeping every offset, and each character is marked as inside a string or not. That is what
   avoids two classic mistakes: reading the two slashes of `"http://..."` as a comment, and
   flagging an `eval(` that was only written inside a piece of text.
2. **Rules** are objects with a pattern, its negative guards and its teaching card. Each one lives
   in the file of its OWASP category (`src/engine/reglas/`).
3. **`analizar()`** is a pure function: same input, same output. No network, no disk, no global
   state.

### False positives are the metric that matters

An engine that flags `password = os.getenv("DB_PASS")` — which is exactly the right way to do it —
loses the user on the first try. So every rule declares negative guards alongside its pattern, and
the test suite checks both sides: that it catches the vulnerable case, and that it stays quiet on
the correct one.

**Measured on real code.** Passing my own tests only proves the engine ignores the correct cases
*I* chose. So I ran it over **26,821 lines of well-written third-party code** — requests, Flask,
express and axios — and reviewed every finding by hand:

| | Findings | Per 1,000 lines |
| --- | --- | --- |
| First pass | 30 | 1.12 |
| **After fixing what it exposed** | **9** | **0.34** |

The 21 that went away were engine mistakes — including a real bug: a type alias named
`AppOrBlueprintKey` was being read as a credential — and each is now a regression test built from
the exact line that caused it. The 9 that remain are correct detections of patterns those projects
keep on purpose, such as the MD5 that the HTTP Digest specification mandates.

Method, data and every fix are in **[docs/falsos-positivos.md](docs/falsos-positivos.md)**
(Spanish). Reproducible with `npm run auditoria`.

---

## Stack

| Layer | Decision |
| --- | --- |
| UI | React 19 + TypeScript, built with Vite |
| Styling | CSS custom properties + CSS Modules, no framework |
| Palette | Xcode's default theme for code; iOS system colours for severities |
| Editor | A `textarea` over a custom highlight layer, no dependencies |
| Engine | Plain TypeScript, no libraries |
| Fonts | Bundled with the app (`@fontsource`), never fetched from a CDN |
| Backend | **None** |
| Tests | Vitest — 251 cases |
| CI/CD | GitHub Actions → GitHub Pages |

**No server means no cost, no maintenance and no attack surface.** The privacy claim is verifiable:
open DevTools, go to the Network tab, and check that running an analysis makes exactly zero
requests.

---

## Running it locally

```bash
npm install
npm run dev
```

| Command | What it does |
| --- | --- |
| `npm run dev` | Development server |
| `npm run test` | Engine and teaching-card tests |
| `npm run build` | Type check + production build |
| `npm run lint` | ESLint |
| `npm run auditoria` | Measures engine noise against a corpus of real code |

---

## Honest disclaimer

> **An educational tool.** SecScan detects common risk patterns through static analysis. It helps
> you learn and review, but it **does not replace a professional security audit**: there can be
> false positives, and it does not catch everything. Specifically, it performs no data-flow
> analysis, resolves no dependencies and never executes your code.

---

## Contributing

Everything is in **[CONTRIBUTING.md](CONTRIBUTING.md)** (Spanish), with issue templates ready to
use. The single most valuable report is a **false positive**: paste the exact line and it becomes a
regression test.

---

## Licence

MIT — see [LICENSE](LICENSE).

Built by **Sergio Osorio** · Software Engineering, UNMSM.
