# Security Policy — Coordinated Vulnerability Disclosure

chick-check is a "product with digital elements" in the sense of the EU
Cyber Resilience Act (Regulation 2024/2847). This file is its
Coordinated Vulnerability Disclosure (CVD) policy and reporting channel.

## Reporting a vulnerability

- **Preferred:** open a private security advisory at
  <https://github.com/sophiekeesing/URLphishingDetector/security/advisories/new>.
- **Alternative:** email the maintainer (add a monitored address here
  before distribution).

Please include: affected version, environment/browser, reproduction
steps, and impact. Do not open a public issue for a suspected
vulnerability.

## What to expect

| Stage | Target |
| --- | --- |
| Acknowledge receipt | within 72 hours |
| Initial assessment / severity | within 7 days |
| Fix or mitigation for confirmed high/critical issues | within 30 days |
| Public disclosure | coordinated with the reporter, normally after a fix ships |

We will credit reporters who wish to be named.

## Scope

In scope: the extension code in this repository (background worker,
popup, options, `lib/`), the manifest and its permission surface, and
the data-handling described in [`PRIVACY.md`](PRIVACY.md).

Out of scope: vulnerabilities in Google Safe Browsing, Cloudflare DNS,
Quad9 DNS, or the browser itself — report those to the respective
vendors.

## CRA reporting obligations (from 11 September 2026)

If chick-check is placed on the EU market in the course of a commercial
activity, the maintainer must report **actively exploited
vulnerabilities** and **severe incidents** to ENISA via the Single
Reporting Platform:

- early warning within **24 hours** of becoming aware,
- full notification within **72 hours**,
- final report within **14 days** of a corrective update being
  available.

This process is owned by the maintainer/distributor, not by end users.

## Secure-by-design commitments

- Minimal permissions: base install requests only `activeTab` and
  `storage`; network hosts and `tabs` are optional and requested at
  runtime only when a feature is switched on.
- No remote code execution: all logic ships in the package; nothing is
  `eval`'d or loaded from a CDN.
- No secret material bundled. Any API key is entered and stored by the
  user.
- Security updates will be published through the same distribution
  channel as releases, with a changelog entry.
- A Software Bill of Materials will accompany releases once full CRA
  obligations apply (11 December 2027). The current dependency count is
  zero.
