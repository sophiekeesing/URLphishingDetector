# URL Shield — Phishing Link Checker

A Manifest V3 browser extension that tells you whether the page you're on
(or any link you paste) is likely a phishing / malware site.

## How it decides

Three independent signals are combined into one verdict:

| Signal | Needs a key? | What it does |
| --- | --- | --- |
| **Local heuristics** | No | Raw-IP hosts, `http://`, deep subdomain chains, brand look-alikes (`paypa1`), abused TLDs (`.top`, `.zip`, …), plus a small bundled blocklist. Runs instantly, works offline. |
| **Quad9 DNS blocklist** | No | Resolves the hostname through Cloudflare `1.1.1.1` (unfiltered) and Quad9 `9.9.9.9` (blocks known-malicious domains). If Cloudflare resolves it but Quad9 refuses, the domain is on a threat feed. |
| **Google Safe Browsing** | Yes (free) | The same phishing/malware list Chrome uses. Add a key on the options page to enable it. |

Verdict: **dangerous** if any online source flags it or ≥2 heuristics fire •
**suspicious** if exactly one heuristic fires • **safe** otherwise.

The toolbar icon shows a badge (`!` / `!!`) as you browse; open the popup for
the full breakdown.

## Install (Chrome / Edge)

1. `git clone` this repo and check out the `extension` branch.
2. Go to `chrome://extensions`, enable **Developer mode**.
3. **Load unpacked** → select this folder.

## Enable Google Safe Browsing (optional)

1. Right-click the extension icon → **Options**.
2. Enable the **Safe Browsing API** in Google Cloud Console and create an API key.
3. Paste the key, **Save**, then **Test key**.

Without a key the extension still runs the DNS blocklist and heuristic checks.

## Files

```
manifest.json      MV3 manifest
background.js       service worker: auto-checks tabs, sets the badge, answers the popup
index.html/js       popup UI + controller
options.html/js     Safe Browsing API key settings
styles.css          shared styles
lib/heuristics.js   offline URL inspection (pure functions)
lib/reputation.js   Google Safe Browsing + DNS blocklist lookups
lib/verdict.js      combines all signals into one verdict
```
