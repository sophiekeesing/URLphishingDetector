// ---------------------------------------------------------------------
// background.js — MV3 service worker
// ---------------------------------------------------------------------
// • Answers CHECK_URL messages from the popup.
// • Local heuristics always run (legitimate interest, GDPR Art. 6(1)(f)).
// • Cloud lookups run only if the user switched them on (consent,
//   Art. 6(1)(a)) — see reputation.js / options page.
// • "Scan as I browse" runs only if the user enabled it AND granted the
//   optional "tabs" permission. Otherwise the extension is scan-on-
//   demand and never watches your navigation (keeps it well clear of
//   "systematic monitoring", GDPR Art. 35).
// • The only stored data is your settings + a 10-minute in-memory
//   verdict cache. No history, no telemetry, no analytics.
// ---------------------------------------------------------------------

import { evaluate, BADGE, VERDICT_CONTENT } from "./lib/verdict.js";
import { parseUrl } from "./lib/heuristics.js";
import { checkReputation } from "./lib/reputation.js";
import {
  getSettings,
  cloudEnabled,
  onSettingsChanged,
  BLOCKING_PERMISSIONS,
} from "./lib/config.js";
import { cacheGet, cacheSet, cacheClear, coalesce } from "./lib/cache.js";
import { loadBackoffState } from "./lib/throttle.js";

async function assessUrl(rawUrl) {
  const offline = evaluate(rawUrl);
  if (offline.status === "error") return offline;

  const settings = await getSettings();
  if (!cloudEnabled(settings)) {
    return { ...offline, sources: [], cloud: false };
  }

  let hostname;
  try {
    hostname = new URL(offline.href).hostname;
  } catch {
    return { ...offline, sources: [], cloud: false };
  }

  const cached = await cacheGet(hostname);
  if (cached) return cached;

  // Restoring a session opens many tabs of the same site at once.
  // coalesce makes those share one set of lookups instead of each
  // firing its own.
  return coalesce(hostname, async () => {
    let reputation = { malicious: false, reasons: [], sources: [] };
    try {
      reputation = await checkReputation(offline.href, settings);
    } catch {
      // Network failure — fall back to the local verdict silently.
    }

    const result = {
      ...evaluate(rawUrl, { reputation }),
      sources: reputation.sources,
      cloud: true,
    };
    await cacheSet(hostname, result);
    return result;
  });
}

// Clear the cache whenever settings change (a toggle flip must take
// effect immediately, including withdrawal of consent).
onSettingsChanged(() => cacheClear());

// Back-off state is persisted, so a worker restart must not forget that
// a service asked us to stop.
loadBackoffState();

// --- Popup <-> worker messaging ---------------------------------
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "CHECK_URL") {
    assessUrl(msg.url).then(sendResponse);
    return true;
  }
  if (msg?.type === "ALLOW_ONCE") {
    allowOnce(msg.url);
    sendResponse({ ok: true });
  }
});

// --- Blocking a dangerous page before it loads -------------------
// Timing is the whole point here. webNavigation.onBeforeNavigate fires
// BEFORE the browser sends the request, which is the last moment an
// IP-logger link can still be stopped — once the request goes out, the
// logging has already happened and a warning is too late.
//
// That means the decision has to be made without waiting for anything,
// so only the LOCAL engine gates the block. It is synchronous and needs
// no network. The cloud checks still run afterwards and refine the
// badge, but they are far too slow to hold a navigation open.

// URLs the user chose to visit anyway. In memory only, so the decision
// lasts for the browsing session and is forgotten afterwards.
const allowed = new Set();

function allowOnce(url) {
  allowed.add(url);
}

// Settings are needed to decide, but reading storage is async and the
// navigation will not wait. Keep a synchronous copy, refreshed whenever
// they change.
let cachedSettings = null;

const INTERNAL = /^(chrome|edge|about|moz|extension|chrome-extension|devtools):/i;

function onBeforeNavigate(details) {
  // Only top-level navigations; a blocked iframe would replace a
  // fragment of someone else's page with our warning.
  if (details.frameId !== 0) return;
  const url = details.url;
  if (!url || INTERNAL.test(url) || !CHECKABLE.test(url)) return;
  if (allowed.has(url)) return;

  const verdict = evaluate(url); // local only — nothing awaited

  // Either it looks dangerous, or it refuses to say where it goes.
  // The second case is the one that catches a tracker chained behind
  // an innocent-looking shortener.
  const hidden =
    cachedSettings?.blockHiddenDestinations && verdict.hidesDestination;
  if (verdict.status !== "dangerous" && !hidden) return;

  const target =
    chrome.runtime.getURL("blocked.html") + "?url=" + encodeURIComponent(url);
  chrome.tabs.update(details.tabId, { url: target }).catch(() => {
    /* tab closed mid-navigation */
  });
}

async function syncBlocking() {
  const settings = await getSettings();
  cachedSettings = settings;
  const granted = await chrome.permissions.contains(BLOCKING_PERMISSIONS);
  const shouldBlock = settings.blockingEnabled && granted;

  // chrome.webNavigation is undefined until the permission is granted.
  if (!chrome.webNavigation) return;
  chrome.webNavigation.onBeforeNavigate.removeListener(onBeforeNavigate);
  if (shouldBlock) {
    chrome.webNavigation.onBeforeNavigate.addListener(onBeforeNavigate);
  }
}

// --- Optional "scan as I browse" -------------------------------
const CHECKABLE = /^https?:\/\//i;

const TITLES = {
  safe: "chick-check: no threats detected",
  suspicious: "chick-check: this page looks suspicious",
  dangerous: "chick-check: this page is likely phishing",
  error: "chick-check",
};

// The URL we are currently rendering a badge for, per tab. A cloud
// lookup can take seconds, and by then the user may have navigated on —
// without this guard a slow verdict would land on whatever page is open
// now, labelling an innocent page as phishing (or vice versa).
const inFlight = new Map(); // tabId -> url

// Badge writes race against the tab closing, which makes Chrome reject
// (and in some cases throw synchronously). Both are expected here, so
// the call itself goes inside the guard rather than being passed in
// already-invoked.
async function safe(fn) {
  try {
    await fn();
  } catch {
    /* tab closed before the badge could be written */
  }
}

async function updateBadgeForTab(tabId, url) {
  if (!url || !CHECKABLE.test(url)) {
    inFlight.delete(tabId);
    await safe(() => chrome.action.setBadgeText({ tabId, text: "" }));
    await safe(() => chrome.action.setTitle({ tabId, title: TITLES.error }));
    return;
  }

  inFlight.set(tabId, url);
  const { status } = await assessUrl(url);

  // Navigated away (or the tab closed) while we were checking — drop
  // this result instead of showing it against the wrong page.
  if (inFlight.get(tabId) !== url) return;
  inFlight.delete(tabId);

  const badge = BADGE[status] || BADGE.error;
  await safe(() => chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color }));
  await safe(() => chrome.action.setBadgeText({ tabId, text: badge.text }));
  await safe(() => chrome.action.setTitle({ tabId, title: TITLES[status] || TITLES.error }));
}

// Both listeners fire and forget, so each needs its own catch —
// an async function's rejection is not caught by the caller's
// try/catch once the call is not awaited.
function onTabUpdated(tabId, changeInfo, tab) {
  if (changeInfo.status === "complete" || changeInfo.url) {
    updateBadgeForTab(tabId, changeInfo.url || tab.url).catch(() => {});
  }
}

async function onTabActivated({ tabId }) {
  try {
    const tab = await chrome.tabs.get(tabId);
    await updateBadgeForTab(tabId, tab.url);
  } catch {
    /* tab gone before we could read or badge it */
  }
}

// Don't let the map grow for the life of the worker.
chrome.tabs.onRemoved.addListener((tabId) => inFlight.delete(tabId));

// Attach/detach the navigation listeners based on the setting + the
// "tabs" permission actually being granted.
async function syncAutoScan() {
  const settings = await getSettings();
  const hasTabs = await chrome.permissions.contains({ permissions: ["tabs"] });
  const shouldWatch = settings.autoScanEnabled && hasTabs;

  chrome.tabs.onUpdated.removeListener(onTabUpdated);
  chrome.tabs.onActivated.removeListener(onTabActivated);

  if (shouldWatch) {
    chrome.tabs.onUpdated.addListener(onTabUpdated);
    chrome.tabs.onActivated.addListener(onTabActivated);
  } else {
    // Make sure no stale badge is left behind.
    inFlight.clear();
    try {
      const tabs = await chrome.tabs.query({});
      await Promise.all(
        tabs.map((t) => safe(() => chrome.action.setBadgeText({ tabId: t.id, text: "" })))
      );
    } catch {
      /* no tabs permission — nothing to clear */
    }
  }
}


// --- Right-click "check this link" -------------------------------
// Answers the question you actually have at the moment you have it:
// before clicking a link, not after. Works on a link, on selected text
// that looks like an address, and on the page itself.

const MENU = {
  link: "chick-check-link",
  selection: "chick-check-selection",
  page: "chick-check-page",
};

function buildMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU.link,
      title: "Check this link with chick-check",
      contexts: ["link"],
    });
    chrome.contextMenus.create({
      id: MENU.selection,
      title: 'Check "%s" with chick-check',
      contexts: ["selection"],
    });
    chrome.contextMenus.create({
      id: MENU.page,
      title: "Check this page with chick-check",
      contexts: ["page"],
    });
    // create() reports failures through lastError rather than throwing.
    void chrome.runtime.lastError;
  });
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const raw =
    info.menuItemId === MENU.link
      ? info.linkUrl
      : info.menuItemId === MENU.selection
        ? (info.selectionText || "").trim()
        : info.pageUrl;
  if (!raw) return;

  // parseUrl forgives a missing scheme, so selected text like
  // "paypa1-login.com" is checked rather than rejected.
  const parsed = parseUrl(raw);
  if (!parsed) {
    await showResult(tab, raw, {
      status: "error",
      score: 0,
      reasons: [],
      href: null,
    });
    return;
  }

  const verdict = await assessUrl(parsed.href);
  await showResult(tab, parsed.href, verdict);
});

// Render into the page where the user is already looking. If that is
// not possible — a chrome:// page, the web store, a PDF — fall back to
// a normal tab so the answer is never simply lost.
async function showResult(tab, url, verdict) {
  const payload = {
    url,
    status: verdict.status,
    score: verdict.score ?? 0,
    label: (VERDICT_CONTENT[verdict.status] || VERDICT_CONTENT.error).label,
    message: (VERDICT_CONTENT[verdict.status] || VERDICT_CONTENT.error).message,
    reasons: verdict.reasons || [],
    markUrl: chrome.runtime.getURL("icons/mark.png"),
  };

  if (tab?.id != null) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: renderOverlay,
        args: [payload],
      });
      return;
    } catch {
      /* page refuses injection — fall through */
    }
  }
  chrome.tabs.create({
    url: chrome.runtime.getURL("result.html") + "?url=" + encodeURIComponent(url),
  });
}

// Runs in the page, not here: it must be entirely self-contained, and
// it is handed only plain serialisable data. Everything lives inside a
// shadow root so the host page's CSS cannot restyle a security warning
// and the page's scripts cannot read it through the normal DOM.
function renderOverlay(data) {
  const HOST_ID = "chick-check-overlay";
  document.getElementById(HOST_ID)?.remove();

  const palette = {
    safe: { accent: "#44b695", wash: "#eaf7f2", edge: "#bfe5d7", ink: "#1c7355" },
    suspicious: { accent: "#c98a1e", wash: "#fdf5e6", edge: "#f0dcae", ink: "#97670f" },
    dangerous: { accent: "#d05353", wash: "#fdeeee", edge: "#f3c4c4", ink: "#a83b3b" },
    error: { accent: "#8a9691", wash: "#f5f6f6", edge: "#e6ebe9", ink: "#5d6b66" },
  };
  const tone = palette[data.status] || palette.error;

  const host = document.createElement("div");
  host.id = HOST_ID;
  // "all:initial" must come FIRST: it resets every property declared
  // before it, which would otherwise wipe out the positioning.
  host.style.cssText =
    "all:initial;position:fixed;top:16px;right:16px;z-index:2147483647;";
  const root = host.attachShadow({ mode: "closed" });

  const style = document.createElement("style");
  style.textContent = `
    :host { all: initial; }
    .card {
      width: 330px; box-sizing: border-box;
      font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
      background: #fff; color: #1f2a27;
      border: 1px solid ${tone.edge}; border-radius: 14px;
      box-shadow: 0 14px 38px rgba(31,42,39,.18);
      overflow: hidden; animation: cc-in .16s ease-out;
    }
    @keyframes cc-in { from { opacity: 0; transform: translateY(-6px); } }
    .bar { height: 4px; background: ${tone.accent}; }
    .head { display: flex; align-items: center; gap: 9px; padding: 13px 14px 0; }
    .head img { width: 17px; height: 21px; display: block; }
    .name { font-size: 12px; font-weight: 700; color: #226756; flex: 1; }
    .x { border: 0; background: transparent; cursor: pointer; font-size: 17px;
         line-height: 1; color: #aab4b0; padding: 2px 4px; border-radius: 5px; }
    .x:hover { background: #f0f3f2; color: #5d6b66; }
    .body { padding: 10px 14px 14px; }
    .verdict { font-size: 14px; font-weight: 700; color: ${tone.ink}; margin-bottom: 7px; }
    .url { display: block; font-size: 11px; color: #8a9691; word-break: break-all;
           background: #f7f9f8; border-radius: 7px; padding: 6px 8px; margin-bottom: 9px; }
    .msg { font-size: 12.5px; line-height: 1.5; margin: 0; color: #33403b; }
    .meter { height: 5px; border-radius: 99px; background: rgba(31,42,39,.09);
             margin: 10px 0 4px; overflow: hidden; }
    .meter i { display: block; height: 100%; background: ${tone.accent}; }
    .score { font-size: 10px; color: #8a9691; text-align: right; }
    ul { margin: 9px 0 0; padding-left: 16px; font-size: 11.5px; line-height: 1.55; color: #4a5651; }
    li { margin-bottom: 3px; }
  `;

  const card = document.createElement("div");
  card.className = "card";
  card.innerHTML = `
    <div class="bar"></div>
    <div class="head">
      <img alt="" />
      <span class="name">chick-check</span>
      <button class="x" type="button" aria-label="Close">&times;</button>
    </div>
    <div class="body">
      <div class="verdict"></div>
      <code class="url"></code>
      <p class="msg"></p>
      <div class="meter"><i></i></div>
      <div class="score"></div>
      <ul></ul>
    </div>`;

  // Everything below is attacker-influenced text, so it is assigned as
  // textContent — never as markup.
  card.querySelector("img").src = data.markUrl;
  card.querySelector(".verdict").textContent = data.label;
  card.querySelector(".url").textContent = data.url;
  card.querySelector(".msg").textContent = data.message;

  if (data.status === "error") {
    card.querySelector(".meter").remove();
    card.querySelector(".score").remove();
  } else {
    card.querySelector(".meter i").style.width = Math.max(2, data.score) + "%";
    card.querySelector(".score").textContent = data.score + "/100 risk score";
  }

  const list = card.querySelector("ul");
  data.reasons.slice(0, 4).forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    list.appendChild(li);
  });

  const close = () => host.remove();
  card.querySelector(".x").addEventListener("click", close);
  root.append(style, card);
  document.documentElement.appendChild(host);

  clearTimeout(window.__chickCheckTimer);
  window.__chickCheckTimer = setTimeout(close, 12000);
}

function syncAll() {
  syncAutoScan();
  syncBlocking();
}

chrome.runtime.onInstalled.addListener(syncAll);
chrome.runtime.onStartup.addListener(syncAll);

// Menus are static, so they are built once per worker start rather than
// torn down and recreated on every settings change.
chrome.runtime.onInstalled.addListener(buildMenus);
chrome.runtime.onStartup.addListener(buildMenus);
buildMenus();
onSettingsChanged(syncAll);
chrome.permissions.onAdded.addListener(syncAll);
chrome.permissions.onRemoved.addListener(syncAll);
syncAll();

// Show what the extension does on first install rather than leaving the
// user to discover that network checks are already on.
chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === "install") chrome.runtime.openOptionsPage();
});
