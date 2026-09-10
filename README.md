# chick-check

A Manifest V3 browser extension that warns you about likely phishing
pages, IP-logger links and disguised redirects — and, if you switch that
part on, stops them loading at all. It never blocks without a way
through: every warning has a *Continue anyway*.

Built privacy-first. Most of the work happens on your device. The three
network lookups are on by default, each sends the minimum it can (a
4-byte hash prefix, a hostname, a registrable domain — never the full
URL or the query string), and every one can be turned off.

## How it decides

| Signal | Default | Data that leaves the device |
| --- | --- | --- |
| **Local detection engine** | on | none |
| **Google Safe Browsing** | on (needs a free API key) | only **4-byte SHA-256 prefixes** of host+path; never the URL, never the query string |
| **DNS blocklist cross-check** | on | the **hostname only**, to Cloudflare `1.1.1.1` and Quad9 `9.9.9.9` |
| **Domain age (RDAP)** | on | the **registrable domain only** (`example.com`), to that TLD's own registry |
| **Block before load** | off — needs an extra permission | nothing; decided on-device |

All the network lookups can be switched off individually, and the
extension still works with every one of them off. See
[PRIVACY.md](PRIVACY.md).

## Staying inside the free rate limits

Every request comes from **your own browser and IP**, and Safe Browsing
uses **your own API key**, so the number of people using the extension
never adds up against a shared quota. What does need managing is one
person opening a lot of tabs at once.

| Measure | Effect |
| --- | --- |
| Verdict cache in `chrome.storage.session` | Survives the service worker being stopped (~30s idle), which a plain in-memory cache does not. **~83% fewer requests** in ordinary browsing |
| Per-hostname request coalescing | 20 tabs of one site make **1** set of lookups, not 20 |
| Domain-age cache for the session | RDAP drops to ~one query per domain per session |
| Per-service queues | Smooths a burst: ~9 req/s per DNS resolver, ~40/min per registry |
| Back-off after errors | Google's mandated `MIN((2^(N-1) × 15 min) × (RAND+1), 24h)`; a gentler curve elsewhere; `Retry-After` always wins |

Measured on a simulated 40-tab session restore: DNS completes 100%,
Safe Browsing 80%, and RDAP is mostly deferred — it is a bonus signal,
so a check that cannot get a turn quickly is **skipped and labelled**
rather than left to stall the verdict. Nothing waits on it: the local
engine has already decided, and it is the local engine that gates
blocking.

Back-off state is persisted too, so restarting the worker does not
forget that a service asked us to stop.

## Right-click any link to check it

The answer you want is usually needed **before** you click, not after.
Right-click a link — or select an address anywhere and right-click — and
choose **Check this link with chick-check**.

The verdict appears as a card in the corner of the page you are already
on, so you never leave it. Selected text is accepted without a scheme,
so highlighting `paypa1-login.com` in an email works.

The card is rendered inside a **closed shadow root**: the host page
cannot restyle a security warning to look harmless, and its scripts
cannot read the result out of the DOM. If a page refuses injection at
all — `chrome://` pages, the web store, PDFs — the verdict opens in an
ordinary tab instead, so the answer is never simply lost.

Nothing is fetched from the link to produce this. The verdict comes from
the address alone, which is the entire point: fetching a tracker to see
where it goes is the thing that records you.

## Blocking dangerous pages

Off by default because it needs permission to see the addresses you
navigate to, which Chrome will not grant without an explicit click.
Turn it on in **Options**.

When on, a dangerous verdict stops the browser **before it sends the
request** and shows a warning page with a *Continue anyway* button. The
timing is the entire point: against a link tracker, the request itself
is what records you, so a warning that arrives once the page has loaded
is already too late.

Because a navigation cannot be held open for a network round-trip, the
block is gated by the **local engine only** — it is synchronous and
instant. The online lookups still run afterwards and refine the badge.

### Links that hide where they go

A sub-option, on by default when blocking is on: also stop short links
and unknown redirectors (`bit.ly/…`, `ej.uz/…`).

This exists because of **chaining**. Put a tracker behind an
innocent-looking short link — `ej.uz/abc` → `urlto.me/2NeG5` → the real
site — and there is nothing left in the address to inspect. The request
still passes through the tracker, so it still records you; the chain
only hides it.

There is no way to resolve that chain safely. Finding out where the link
leads means sending the request, and the request **is** the thing that
records you — whether your browser makes it or the extension does, it
comes from your IP either way. A third-party unshortening service would
move the exposure rather than remove it, trading your IP for handing
your full URLs to someone else.

So the extension does not try. It stops before anything is sent and
lets you decide, which is the one point where the outcome is still open.
Note the verdict and the block are separate judgements here: `ej.uz/abc`
scores 15 (safe — it is probably fine) yet is still stopped, because
"probably fine" and "verified" are not the same claim. Expect this to
fire on ordinary short links; that is the trade, and it is one toggle
to turn off.

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
| IP logger / click tracker | 60 | `grabify.link`, `iplogger.org`, and their innocent-looking custom domains |
| Open redirect to an impersonator | 55 | `google.com/url?q=https://instogram.com` |
| Open redirect off-site | 35 | `google.com/url?q=…`, `facebook.com/l.php?u=…` |
| Raw IP host · credentials in URL | 35 | `192.168.12.44/login`, `user@evil.tk` |
| Shortened link (destination hidden) | 15 | `bit.ly/…` — noted, not alarming on its own |
| No HTTPS · odd port | 22 / 12 | `http://…` |
| Risky TLD | 10–25 | `.tk`, `.zip`, `.top`, `.xyz` |
| Urgent keywords · deep subdomains · hyphen soup | 10–24 | `secure-login-update…` |

Misspelling uses Damerau–Levenshtein distance, so substitutions,
deletions, insertions **and** transpositions all count. The tolerance
scales with brand length (≤4 chars: exact match only) to keep short
names from matching everything.

Domains a brand actually owns are allow-listed first, so
`login.microsoftonline.com` and `s3.amazonaws.com` score 0. The logger
and open-redirect rules are the exception — they deliberately run on
allow-listed domains too, because "the visible domain really is
google.com" is exactly what makes an open redirect work.

### Links that hide or harvest

A separate family from brand imitation: the link looks completely
ordinary and often forwards you to the real site afterwards, so nothing
seems wrong.

- **IP loggers** (`grabify.link`, `iplogger.org`, `urlto.me`, plus the
  harmless-sounding custom domains they hand out) record your IP — and
  from it a city-level guess at your location — along with your browser,
  OS, screen size and the time. They **cannot** silently get precise GPS
  location, camera or microphone; those require the browser's own
  permission prompt.
- **Unknown redirectors**, caught by shape rather than by name: a short
  domain whose whole path is one generated-looking code and nothing else
  (`urlto.me/2NeG5`, `xyz9.co/aB3xY`). Scored +30 — suspicious, not
  dangerous — because this rule genuinely cannot tell a tracker from an
  honest shortener. What it really reports is "the destination is hidden
  and can't be checked". Hosts that legitimately use short codes
  (`imgur.com`, `pastebin.com`, `youtu.be`, `prnt.sc`) are allow-listed.
- **Open redirects** start at a domain you trust and hand you off
  elsewhere. If the destination is itself imitating a brand, the score
  rises from 35 to 55.

Detection is by URL only — the extension never opens the link, because
visiting a logger to test it is exactly what you don't want. The
tradeoff is that a brand-new logger domain on no list, or a custom
domain quietly running logging scripts, is indistinguishable from an
ordinary site by its address alone.

Current benchmark ([lib/heuristics.js](lib/heuristics.js)): **34/34**
phishing patterns flagged, **0/34** false positives on real sites.

## Install (Chrome / Edge)

1. Clone the repo (everything lives on `main`).
2. `chrome://extensions` → enable **Developer mode** → **Load unpacked**
   → pick this folder.
3. The options page opens on first install so you can see what is
   already running.

Everything works immediately except the two things that genuinely
cannot self-enable.

## The two things you have to switch on

Right-click the icon → **Options**:

- **A Google Safe Browsing API key.** Enable the
  [Safe Browsing API](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com)
  in Google Cloud Console, create a key, paste it, **Save key**,
  **Test**. Until then that one check sits idle; the others run.
- **Block dangerous pages before they load.** Needs `webNavigation` on
  all sites, and Chrome only grants that from a click.

"Turn everything off" disables every network feature; the on-device
engine keeps working.

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
manifest.json         MV3 manifest
background.js         service worker: verdicts, badge, blocking, context menu
index.html / script.js   popup UI + controller
blocked.html / blocked.js  the pre-load warning page
result.html / result.js    verdict page, used when a page refuses injection
options.html / options.js  settings + opt-outs
styles.css           shared styles
lib/config.js        defaults, settings helpers, DETECTION_VERSION
lib/heuristics.js     the scoring engine (pure functions)
lib/brands.js         ~150 brands + real domains, keywords, TLD risk, suffixes
lib/trackers.js       IP loggers, shorteners, redirect params, short-code allowlist
lib/similarity.js     Damerau-Levenshtein + confusable-character folding
lib/punycode.js       decodes xn-- labels to spot IDN homographs
lib/canonicalize.js   URL -> host/path expressions, query stripped
lib/hash.js           SHA-256 + 4-byte prefix for the k-anonymity lookup
lib/cache.js          session-backed verdict + domain-age cache, coalescing
lib/throttle.js       per-service queues and back-off curves
lib/dns.js            RFC 8484 wireformat DoH client (Quad9 rejects JSON)
lib/rdap.js           TLD -> registry endpoint map, domain-age scoring
lib/reputation.js     Safe Browsing + DNS blocklist + domain age
lib/verdict.js        score thresholds -> one verdict
```
