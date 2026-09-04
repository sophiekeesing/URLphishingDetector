# Compliance Map (EU)

How each item on the legal & compliance board is addressed in this
repository. This is engineering documentation, not legal advice — have
counsel review before any commercial or large-scale distribution.

## Guiding principle — privacy by design

- Local scan is the default and needs no network. → `lib/heuristics.js`
- If a lookup hits the cloud, no full URL in cleartext: only 4-byte
  SHA-256 **hash prefixes** of host+path are sent; exact match is
  finished locally. → `lib/hash.js`, `lib/canonicalize.js`,
  `checkSafeBrowsing()` in `lib/reputation.js`
- Query string and fragment are discarded before hashing. →
  `canonicalize.js`

## 1. GDPR / Data protection

| Point | Where |
| --- | --- |
| URLs treated as personal data | `PRIVACY.md`, `docs/LIA.md` |
| Lawful basis: legitimate interest for local scan | `docs/LIA.md` (documented balancing test) |
| Lawful basis: consent for optional cloud lookups, tool still works if withdrawn | `options.js` toggles + `cloudConsentAt`; `background.js` runs local-only when `cloudEnabled()` is false |
| Data minimisation | host+path only, query stripped, hostname-only for DNS, 4-byte prefixes, 10-min in-memory cache, no history |
| Hashing ≠ anonymisation; k-anonymity prefix is the real control | comments in `lib/hash.js`; `PRIVACY.md` |
| Third-party APIs: DPA needed (Art. 28); no crowd-sharing services | `PRIVACY.md` ("What we never do"); VirusTotal / public urlscan.io deliberately not integrated |
| Domain age lookup sends registrable domain only, direct to registry (no `rdap.org` intermediary) | `lib/rdap.js`, `PRIVACY.md` §3 |
| Transparency (Art. 13/14) | `PRIVACY.md`, linked from popup and options |
| DPIA (Art. 35) | `docs/DPIA-screening.md` — screened out, with re-trigger list |
| Accountability (Art. 5(2)) | `DETECTION_VERSION` recorded in every verdict; LIA + DPIA screening retained |

## 2. ePrivacy / device storage (§ 25 TDDDG)

- Only "strictly necessary" storage: settings + API key + transient
  cache. No non-essential storage, so no consent banner. → `PRIVACY.md`,
  `lib/config.js`
- No telemetry or analytics exists in the codebase.

## 3. User autonomy & false positives

- Warning only, never a hard block (no `declarativeNetRequest`, no
  request cancellation anywhere). → `background.js` sets a badge; popup
  shows a panel
- "Report a false positive" link in the popup. → `FALSE_POSITIVE_CONTACT`
  in `lib/config.js`, wired in `script.js`
- Detection logic version shown and stored with the verdict. →
  `DETECTION_VERSION`, `lib/verdict.js`

## 4. EU AI Act (2024/1689)

- No ML model. Deterministic heuristics + list/DNS lookups → minimal
  risk, analogous to a spam filter (Recital example). No mandatory
  obligations, no Art. 50 disclosure duty for a silent background
  classifier. → noted in `README.md`
- Re-assess if an external/general-purpose model is ever added.

## 5. Cyber Resilience Act (2024/2847)

- CVD policy + reporting channel. → `SECURITY.md`
- Secure-by-design now: zero dependencies, no remote code, minimal
  permissions, security updates via the release channel. → `SECURITY.md`,
  `manifest.json`
- Art. 14 reporting workflow (24h / 72h / 14d) documented as a
  maintainer obligation. → `SECURITY.md`
- SBOM commitment for full-obligation phase (Dec 2027). → `SECURITY.md`
- Open-source / steward vs. manufacturer bucket: **to be decided by the
  maintainer before launch** — monetisation changes this. → `SECURITY.md`,
  `TERMS.md`

## 6. Terms of service & liability

- "As is", best-effort, no protection guarantee. → `TERMS.md`
- EU-appropriate liability section: no exclusion for intent, gross
  negligence, or harm to life/body/health; § 309 BGB aware; not a US
  template. → `TERMS.md`
- Warning about the higher bar once charging/advertising a protection
  outcome (UWG). → `TERMS.md`

## 7. Platform / store rules

| Rule | Status |
| --- | --- |
| Single purpose | Phishing/malware URL warning only |
| Least privilege | Base: `activeTab` + `storage`. Optional: `tabs`, and host access for the two APIs — requested at runtime on opt-in. → `manifest.json`, `options.js` |
| Data-use disclosure + linked privacy policy | `PRIVACY.md`, linked from popup and options; fill in the store listing fields to match |
| Manifest V3 | Yes. No blocking API used; observe-and-warn only |
| Cross-browser | Uses `chrome.*` with feature detection; `optional_host_permissions` is Chrome 116+. Verify Firefox behaviour before an AMO listing |

## Still to do before public / commercial release

1. Replace placeholder contacts (controller, security email) with
   monitored ones.
2. Decide and document the CRA bucket (steward vs. manufacturer).
3. Put a Data Processing Agreement in place with Google (Safe Browsing).
4. Legal review of `PRIVACY.md` and `TERMS.md` for the target
   jurisdiction.
5. Complete the Chrome Web Store / AMO data-use declarations to match
   `PRIVACY.md`.
6. If distributing commercially at scale, revisit the DPIA screening.
