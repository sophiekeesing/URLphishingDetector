# URL Shield — Privacy Policy

_Last updated: 2026-09-04 · Detection logic v3.0.0_

This policy explains exactly what URL Shield processes, what (if
anything) leaves your device, and on what legal basis. It is written to
GDPR Art. 13/14.

## Who is the controller

The developer/distributor of this extension. Contact:
<https://github.com/sophiekeesing/URLphishingDetector/issues>. Replace
this with a real contact point before public distribution.

## What the extension does by default

When you click the URL Shield icon it inspects the address of the
current tab **entirely on your device**:

- structural heuristics (raw-IP host, `http://`, deep subdomain chains,
  brand look-alikes, abused TLDs);
- a small blocklist bundled inside the extension.

No network request is made. No browsing history is stored. The only
data written to storage is your settings (below) and a short-lived
in-memory cache of recent verdicts that is discarded when the browser
suspends the extension.

**Legal basis:** legitimate interest in network and information
security, GDPR Art. 6(1)(f) and Recital 49. A balancing test is
recorded in [`docs/LIA.md`](docs/LIA.md).

## Network lookups — ON by default, and how to turn them off

The three lookups below are **enabled when you install**, because
protection that has to be switched on protects almost nobody. They run
on the legitimate interest in network and information security
(GDPR Art. 6(1)(f), Recital 49), not on consent.

Because you are not asked first, two things matter:

- the options page opens automatically on first install, so you see
  what is running before you browse;
- **every one can be turned off individually**, and "Turn everything
  off" disables all of them at once. The on-device checks keep working,
  and with them off nothing about your browsing leaves your device.

You can object to this processing at any time (GDPR Art. 21) by
switching the relevant lookup off.

### 1. Google Safe Browsing check

- **What is sent:** for the current page, the extension derives host +
  path combinations (the query string and fragment are discarded),
  hashes each with SHA-256, and sends **only the first 4 bytes of each
  hash** to `https://safebrowsing.googleapis.com`. The full address is
  never transmitted.
- **What comes back:** a set of candidate full hashes. The exact match
  is completed locally. Google does not learn which URL you visited
  (this is the k-anonymity model Google Safe Browsing is designed
  around).
- **Recipient:** Google Ireland Ltd., acting as a processor. You should
  put a Data Processing Agreement (GDPR Art. 28) in place before
  distributing. Google's terms: <https://developers.google.com/safe-browsing>.
- **Retention by us:** none beyond the 10-minute in-memory cache.

### 2. DNS blocklist cross-check

- **What is sent:** the **hostname only** (no path, no query) of the
  current page, to `https://cloudflare-dns.com` and
  `https://dns.quad9.net`, as a standard encrypted DNS-over-HTTPS query
  (RFC 8484 wireformat).
- **Why:** Quad9 refuses to resolve domains on its malware/phishing
  feeds; Cloudflare does not filter. Disagreement is a strong signal.
- **Recipients:** Cloudflare, Inc. and the Quad9 Foundation, each an
  independent controller with its own policy
  (<https://www.cloudflare.com/privacypolicy/>,
  <https://quad9.net/privacy/policy/>).
- **Retention by us:** none beyond the 10-minute in-memory cache.

### 3. Domain age check (RDAP)

- **What is sent:** the **registrable domain only** — `example.com`, not
  the subdomain, path, query or fragment — to the RDAP service operated
  by that TLD's own registry (Verisign for `.com`/`.net`, Public
  Interest Registry for `.org`, CentralNic, Identity Digital, Radix,
  Nominet, Google Registry, ZDNS, GMO). The full endpoint list is in
  [`lib/rdap.js`](lib/rdap.js) and matches the host permissions
  requested.
- **Why:** phishing domains are typically registered days before use;
  the brands they imitate are years old. This is also the one check
  that works on brands absent from the built-in list.
- **Note on routing:** the extension queries each registry **directly**
  and deliberately does not use the `rdap.org` bootstrap redirector, so
  no third-party intermediary sees the lookups.
- **Recipients:** each domain registry, acting as an independent
  controller under its own policy. RDAP is a public registration-data
  service (the IETF successor to WHOIS).
- **Coverage:** partial. TLDs with no public RDAP (`.lv`, `.de`,
  `.io`, `.co`, `.ru`, `.eu` and many other country domains) are
  reported as unavailable and never count against a site.
- **Retention by us:** none beyond the 10-minute in-memory cache.

### 4. "Scan as I browse"

On by default. Lets the extension read the URL of pages you navigate to
so it can show a verdict on the toolbar badge. It only runs the checks
you have left enabled, and stores no history.

### 5. "Stop dangerous pages before they load" — OFF by default

The one feature that is **off until you switch it on**, because it needs
permission to see every address you navigate to
(`webNavigation` + all sites) and the browser will not grant that
without an explicit click.

- **What it does:** when the on-device engine rates a page dangerous,
  the browser is stopped **before it sends the request** and a warning
  page is shown instead, with a *Continue anyway* button.
- **What is sent:** nothing. The decision uses only the local engine —
  no network call is made, and none of the enabled lookups are consulted,
  because they are far too slow to hold a navigation open.
- **Why it matters:** against a link tracker, a warning that arrives
  after the page loads is already too late — the request itself is what
  records you.
- **What is stored:** if you choose *Continue anyway*, that address is
  remembered in memory for the rest of the browsing session so you are
  not asked twice. It is never written to disk.

## What we never do

- No browsing history, bookmarks, form data, or page content is read or
  stored.
- No analytics, telemetry, crash reporting, advertising, or
  fingerprinting.
- No data is sold or shared with anyone other than the recipients named
  above, and only as described.
- No third party used here (Google Safe Browsing, Cloudflare, Quad9,
  the domain registries) publishes or crowd-shares the queries URL
  Shield sends. Services that do (e.g. VirusTotal, urlscan.io public
  scans) are deliberately **not** integrated.

## Storage on your device (ePrivacy / § 25 TDDDG)

`chrome.storage.sync` holds your settings and, if you entered one, your
Safe Browsing API key. This is strictly necessary for the security
function you asked for, so no separate cookie-style consent banner is
used. There is no non-essential storage.

## Your rights

Access, rectification, erasure, restriction, objection, portability
(GDPR Art. 15–21). Because almost all processing is local and transient,
in practice: use the options page to turn features off and clear your
settings ("Turn everything off & revoke permissions"), or remove the
extension. For the hash-prefix queries already sent to Google/Cloudflare/
Quad9, exercise rights with those parties directly.

## Changes

Material changes will bump the "Last updated" date and the detection
logic version, and will be noted in the repository changelog.
