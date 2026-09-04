// ---------------------------------------------------------------------
// background.js — MV3 service worker
// ---------------------------------------------------------------------
// • Answers CHECK_URL messages from the popup with a full verdict
//   (offline heuristics + live Google Safe Browsing + DNS blocklist).
// • Automatically checks every page you navigate to and shows the
//   result on the toolbar badge.
// • Caches verdicts per hostname for a few minutes so we don't hammer
//   the APIs on every click within a site.
// ---------------------------------------------------------------------

import { evaluate, BADGE } from "./lib/verdict.js";
import { checkReputation } from "./lib/reputation.js";

const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const cache = new Map(); // hostname -> { result, expires }

async function getApiKey() {
  const { safeBrowsingApiKey } = await chrome.storage.sync.get("safeBrowsingApiKey");
  return safeBrowsingApiKey || "";
}

// Full verdict for a URL: offline first, then fold in the online checks.
async function assessUrl(rawUrl) {
  const offline = evaluate(rawUrl);
  if (offline.status === "error") return offline;

  let hostname;
  try {
    hostname = new URL(offline.href).hostname;
  } catch {
    return offline;
  }

  const cached = cache.get(hostname);
  if (cached && cached.expires > Date.now()) return cached.result;

  let reputation = { malicious: false, reasons: [], sources: [] };
  try {
    reputation = await checkReputation(offline.href, { apiKey: await getApiKey() });
  } catch {
    // Network failure — fall back to the offline verdict silently.
  }

  const result = { ...evaluate(rawUrl, { reputation }), sources: reputation.sources };
  cache.set(hostname, { result, expires: Date.now() + CACHE_TTL_MS });
  return result;
}

// --- Popup <-> worker messaging -----------------------------------
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "CHECK_URL") {
    assessUrl(msg.url).then(sendResponse);
    return true; // keep the channel open for the async reply
  }
});

// --- Toolbar badge for the active tab ----------------------------
const CHECKABLE = /^https?:\/\//i;

async function updateBadgeForTab(tabId, url) {
  if (!url || !CHECKABLE.test(url)) {
    await chrome.action.setBadgeText({ tabId, text: "" });
    await chrome.action.setTitle({ tabId, title: "URL Shield" });
    return;
  }

  const { status } = await assessUrl(url);
  const badge = BADGE[status] || BADGE.error;

  await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
  await chrome.action.setBadgeText({ tabId, text: badge.text });

  const titles = {
    safe: "URL Shield: no threats detected",
    suspicious: "URL Shield: this page looks suspicious",
    dangerous: "URL Shield: this page is likely phishing",
    error: "URL Shield",
  };
  await chrome.action.setTitle({ tabId, title: titles[status] || "URL Shield" });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" || changeInfo.url) {
    updateBadgeForTab(tabId, changeInfo.url || tab.url);
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    updateBadgeForTab(tabId, tab.url);
  } catch {
    /* tab already gone */
  }
});
