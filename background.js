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

import { evaluate, BADGE } from "./lib/verdict.js";
import { checkReputation } from "./lib/reputation.js";
import {
  getSettings,
  cloudEnabled,
  onSettingsChanged,
  BLOCKING_PERMISSIONS,
} from "./lib/config.js";

const CACHE_TTL_MS = 10 * 60 * 1000;
const cache = new Map(); // hostname -> { result, expires } (memory only)

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

  const cached = cache.get(hostname);
  if (cached && cached.expires > Date.now()) return cached.result;

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
  cache.set(hostname, { result, expires: Date.now() + CACHE_TTL_MS });
  return result;
}

// Clear the cache whenever settings change (a toggle flip must take
// effect immediately, including withdrawal of consent).
onSettingsChanged(() => cache.clear());

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
  safe: "URL Shield: no threats detected",
  suspicious: "URL Shield: this page looks suspicious",
  dangerous: "URL Shield: this page is likely phishing",
  error: "URL Shield",
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

function syncAll() {
  syncAutoScan();
  syncBlocking();
}

chrome.runtime.onInstalled.addListener(syncAll);
chrome.runtime.onStartup.addListener(syncAll);
onSettingsChanged(syncAll);
chrome.permissions.onAdded.addListener(syncAll);
chrome.permissions.onRemoved.addListener(syncAll);
syncAll();

// Show what the extension does on first install rather than leaving the
// user to discover that network checks are already on.
chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === "install") chrome.runtime.openOptionsPage();
});
