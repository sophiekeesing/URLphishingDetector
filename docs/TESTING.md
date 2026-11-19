# Testing chick-check

Run this list in **Chrome, Edge and Firefox** before merging to `main`
or making a release. It takes about 20 minutes per browser. Write down
the browser version and any step that fails.

## Test addresses

None of these exist. `.example` is a reserved ending that never
resolves (RFC 2606), so if a block ever fails, your browser contacts
nobody.

| Address | Expected verdict |
| --- | --- |
| `https://example.com/` | safe (0) |
| `instagram.co` | suspicious (48), only check it in the popup, don't open it |
| `https://paypal.com.secure-billing.example/` | dangerous (70) |
| `https://micros0ft.example/` | dangerous (55) |
| `https://bit.ly/chick-check-test` | safe (15), but **hides its destination** |

Don't use real IP-logger links (`grabify.link/…`) for testing. If
blocking is broken, opening one records your IP.

## 1. Load

- [ ] **Chrome/Edge:** `chrome://extensions` → Load unpacked. No errors
      on the card. The ID is `jaibknimhekfcnlhiidfeffbbfefglcf`.
- [ ] **Firefox:** `about:debugging` → *This Firefox* → Load Temporary
      Add-on → `manifest.json`. No errors. Click **Inspect** and check
      the console is clean.
- [ ] The options page opens on first install, **in a tab**.

## 2. Popup

- [ ] On a normal site, the popup checks the current tab automatically.
- [ ] Type each test address above: the verdict and score match the table.
- [ ] The source list shows each enabled lookup as clear, flagged,
      not run or unavailable.

## 3. Right-click check

- [ ] Right-click a link → *Check this link*: a card appears top right.
- [ ] Select the text `micros0ft.example` → right-click → *Check "…"*:
      dangerous.
- [ ] Right-click on the page itself → *Check this page*.
- [ ] On a page that can't be scripted, the result opens in a **new
      tab** (`result.html`) instead of a card. Try at least:
      - [ ] the extensions page (`chrome://extensions` / `about:addons`)
      - [ ] the add-on store (Chrome Web Store / `addons.mozilla.org`)
      - [ ] a PDF opened in the browser
      - [ ] Firefox only: a page in Reader View

## 4. Badge (auto-scan)

- [ ] Open `https://example.com/`: no badge text, tooltip "no threats".
- [ ] Badge text is **white** and readable on the red and amber badges
      (open a dangerous test address with blocking off).
- [ ] Switch tabs quickly between a safe and a dangerous page: the
      badge always matches the tab you're on (no stale badge).
- [ ] Turn auto-scan off in options: every badge clears.

## 5. Blocking

- [ ] Turn on *Stop dangerous pages before they load*: the browser asks
      for permission. Accept.
- [ ] Open `https://paypal.com.secure-billing.example/`: the block page
      appears instead.
- [ ] *Go back* works. On a fresh tab, it closes the tab.
- [ ] *Continue anyway* lets the page through (it then fails to load,
      which is expected for `.example`).
- [ ] Open `https://bit.ly/chick-check-test`: blocked as "hides where
      it goes". Turn off *Also stop links that hide where they go*, and
      it isn't blocked any more.
- [ ] Take the permission back in the browser's own UI (Chrome: the
      extension's *Details* → *Site access*; Firefox: `about:addons` →
      chick-check → *Permissions*). Options shows blocking as off with
      a "permission was revoked" message, and nothing is blocked.

## 6. After the background goes idle (important)

This catches the bug where a page loaded unblocked after the background
had stopped.

- [ ] Turn blocking on.
- [ ] Stop the background script:
      - **Chrome/Edge:** wait at least 30 s without using the extension,
        until the extensions page shows *service worker (inactive)*. Or
        stop it in `chrome://serviceworker-internals`.
      - **Firefox:** in `about:debugging`, click **Terminate background
        script**, or wait until it shows as stopped.
- [ ] Without opening the popup or options, open
      `https://micros0ft.example/` in a new tab: it **must be blocked**.
- [ ] Repeat with auto-scan on: the badge must appear on the first page
      after the idle period.

## 7. Online lookups

- [ ] Switch each lookup (Safe Browsing, DNS, domain age) off and on.
      The popup's source list follows.
- [ ] Safe Browsing with a key: **Test** says the key works.
- [ ] Take back a lookup's host permission (Firefox: `about:addons` →
      chick-check → *Permissions*, switch off e.g. `dns.quad9.net`).
      - [ ] The popup shows that lookup as **not run**, not unavailable.
            Hovering it explains it's a permission issue.
      - [ ] The options page shows *Some lookups can't run* with a
            re-grant button. Clicking it asks for permission, and after
            accepting, the notice disappears.
- [ ] *Turn everything off*: all lookups off, blocking off, popup
      still gives local verdicts.

## 8. Settings sync

Needs two browser profiles signed into the same account. Firefox also
needs *Add-ons* ticked in its Sync settings.

- [ ] Change a toggle on profile 1. It shows on profile 2 after a sync.
- [ ] Chrome: both profiles show the same extension ID.
- [ ] Firefox: check whether this works with a **temporarily loaded**
      add-on. If not, use Developer Edition with
      `xpinstall.signatures.required = false` for this test.

## 9. Detection unchanged

Unless the change was meant to alter detection, scores must be the same
as before. The README examples to spot-check:

| Address | Expected |
| --- | --- |
| `instogram.com`, `gogole.com`, `netflx.com` | dangerous (58) |
| `paypal.com.secure-billing.ru` | dangerous (70) |
| `paypal-login-verify.com` | dangerous (64) |
| `https://google.com/url?q=https://instogram.com` | dangerous (55) |
| `https://login.microsoftonline.com`, `https://s3.amazonaws.com` | safe (0) |

## 10. Lint

- [ ] `npx web-ext lint` shows **0 errors**. Expected warnings, which
      are fine for now:
      - `data_collection_permissions` is missing (only needed for AMO).
      - `background.service_worker` is ignored by Firefox (by design: Firefox
        uses `background.scripts`).
      - `innerHTML` in `script.js` (only fixed icons; text goes through
        `textContent`).
