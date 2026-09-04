# URL Shield — Phishing Link Checker

A Manifest V3 browser extension that **warns** you about likely phishing
/ malware pages. It never blocks anything — you decide whether to
continue.

Built privacy-first: by default it checks pages **only on your device**
and **only when you click it**. Cloud lookups exist but are off until
you switch them on.

## How it decides

| Signal | Default | Data that leaves the device |
| --- | --- | --- |
| **Local detection engine** | on | none |
| **Google Safe Browsing** | off (opt-in + free API key) | only **4-byte SHA-256 prefixes** of host+path; never the URL, never the query string |
| **DNS blocklist cross-check** | off (opt-in) | the **hostname only**, to Cloudflare `1.1.1.1` and Quad9 `9.9.9.9` |
| **Domain age (RDAP)** | off (opt-in, no key) | the **registrable domain only** (`example.com`), to that TLD's own registry |

### Domain age

Free and keyless, via [RDAP](https://www.rfc-editor.org/rfc/rfc7482) —
the IETF successor to WHOIS. Phishing domains are usually days old; the
brands they imitate are decades old. It contributes to the score rather
than giving a yes/no answer:

| Age | Points |
| --- | --- |
| under 7 days | +42 |
| under 30 days | +32 |
| under 90 days | +20 |
| under 180 days | +10 |
| over 2 years | −12 credit |

The credit is **discarded whenever the address is impersonating a
brand**, because attackers buy aged domains too — a real case:
`instogram.com` was registered in 2011, so without that rule its age
would have pulled it back under the danger threshold.

The extension queries each registry **directly** from a bundled endpoint
map ([lib/rdap.js](lib/rdap.js)) rather than going through the
`rdap.org` bootstrap redirector — that keeps host permissions tight and
avoids an intermediary seeing the lookups. Coverage is partial:
`.com`, `.net`, `.org`, `.info`, `.xyz`, `.top`, `.online`, `.shop`,
`.uk` and others are supported; TLDs with no public RDAP (`.lv`, `.de`,
`.io`, `.co`, `.ru`, `.eu`) are reported as unavailable and **never
count against a site**.

### The local engine

Every rule that fires adds points to a **0–100 risk score**
(≥22 suspicious, ≥50 dangerous), so one strong signal outweighs several
weak ones. Scored against ~150 commonly-impersonated brands and their
real domains ([lib/brands.js](lib/brands.js)):

| Rule | Points | Catches |
| --- | --- | --- |
| Look-alike characters | 55 | `micros0ft.com`, `instagrarn.com` (`rn`→`m`), Cyrillic `аpple.com` |
| Misspelling (edit distance) | 58 / 46 | `instogram.com`, `gogole.com`, `netflx.com`, `faceboook.com` |
| Brand in a subdomain | 52 | `paypal.com.secure-billing.ru` |
| Brand on a domain it doesn't own | 48 | `instagram.co`, `paypal.net` |
| Brand + extra words | 46 | `paypal-login-verify.com` |
| Punycode / IDN homograph | 42 | `xn--pple-43d.com` |
| Raw IP host · credentials in URL | 35 | `192.168.12.44/login`, `user@evil.tk` |
| No HTTPS · odd port | 22 / 12 | `http://…` |
| Risky TLD | 10–25 | `.tk`, `.zip`, `.top`, `.xyz` |
| Urgent keywords · deep subdomains · hyphen soup | 10–24 | `secure-login-update…` |

Misspelling uses Damerau–Levenshtein distance, so substitutions,
deletions, insertions **and** transpositions all count. The tolerance
scales with brand length (≤4 chars: exact match only) to keep short
names from matching everything.

Domains a brand actually owns are allow-listed first, so
`login.microsoftonline.com` and `s3.amazonaws.com` score 0.

Current benchmark ([lib/heuristics.js](lib/heuristics.js)): **30/30**
phishing patterns flagged, **0/26** false positives on real sites.

## Install (Chrome / Edge)

1. Clone the repo, check out the `extension` branch.
2. `chrome://extensions` → enable **Developer mode** → **Load unpacked**
   → pick this folder.
3. Click the icon on any page to scan it.

Base install asks for only `activeTab` + `storage`. Network access and
the `tabs` permission are requested at runtime, and only if you enable
the matching feature on the options page.

## Turn on the online checks (optional)

Right-click the icon → **Options**:

- **Google Safe Browsing** — enable the
  [Safe Browsing API](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com)
  in Google Cloud Console, create an API key, paste it, **Save key**,
  **Test**.
- **DNS blocklist** — one toggle; the browser will ask to allow the two
  resolver hosts.
- **Scan as I browse** — one toggle; grants `tabs` so a badge appears
  automatically.

"Turn everything off & revoke permissions" reverts to local-only.

## Privacy, security, legal

- [PRIVACY.md](PRIVACY.md) — what is processed and on what legal basis
- [TERMS.md](TERMS.md) — best-effort disclaimer, EU-appropriate liability
- [SECURITY.md](SECURITY.md) — coordinated vulnerability disclosure
- [COMPLIANCE.md](COMPLIANCE.md) — map to the EU compliance checklist
  (GDPR, ePrivacy, AI Act, CRA, store rules)
- [docs/LIA.md](docs/LIA.md), [docs/DPIA-screening.md](docs/DPIA-screening.md)

The URL classifier is deterministic (no ML model), so under the EU AI
Act it is **minimal risk** — analogous to a spam filter — with no
mandatory obligations.

## Files

```
manifest.json        MV3 manifest (minimal base permissions)
background.js         service worker: verdicts, badge, opt-in auto-scan
index.html / script.js   popup UI + controller
options.html / options.js  consent surface for the optional cloud features
styles.css           shared styles
lib/config.js        defaults, settings helpers, DETECTION_VERSION
lib/heuristics.js     the scoring engine (pure functions)
lib/brands.js         ~150 brands + real domains, keywords, TLD risk, suffixes
lib/similarity.js     Damerau-Levenshtein + confusable-character folding
lib/punycode.js       decodes xn-- labels to spot IDN homographs
lib/canonicalize.js   URL -> host/path expressions, query stripped
lib/hash.js           SHA-256 + 4-byte prefix for the k-anonymity lookup
lib/rdap.js           TLD -> registry endpoint map, domain-age scoring
lib/reputation.js     Safe Browsing + DNS blocklist + domain age
lib/verdict.js        score thresholds -> one verdict
```
