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
| **Local heuristics** | on | none — raw-IP host, `http://`, deep subdomains, brand look-alikes (`paypa1`), abused TLDs, small bundled list |
| **Google Safe Browsing** | off (opt-in + free API key) | only **4-byte SHA-256 prefixes** of host+path; never the URL, never the query string |
| **DNS blocklist cross-check** | off (opt-in) | the **hostname only**, to Cloudflare `1.1.1.1` and Quad9 `9.9.9.9` |

Verdict: **dangerous** if a cloud source flags it, it's on the bundled
list, or ≥2 heuristics fire · **suspicious** if exactly one heuristic
fires · **safe** otherwise. The exact combining logic is in
[lib/verdict.js](lib/verdict.js).

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
lib/heuristics.js     offline URL inspection (pure functions)
lib/canonicalize.js   URL -> host/path expressions, query stripped
lib/hash.js           SHA-256 + 4-byte prefix for the k-anonymity lookup
lib/reputation.js     Safe Browsing (hash-prefix) + DNS blocklist
lib/verdict.js        combines all signals into one verdict
```
