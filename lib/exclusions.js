// ---------------------------------------------------------------------
// exclusions.js — sites the user does not want scanned
// ---------------------------------------------------------------------
// On an excluded site the badge pauses, no online lookup is sent and
// blocking is not applied. A check the user asks for (popup, right-click)
// still runs.
//
// Storage: one key per site, "x:" + ASCII host, e.g. "x:example.com",
// value { m: "domain" | "host", t: <ms since epoch> }.
//   • One key per site rather than one array: an array hits the 8 KB
//     per-item limit of storage.sync at ~200 sites, and two devices
//     editing it at once overwrite each other. Separate keys merge.
//   • Hosts are stored as the browser gives them (lowercase ASCII,
//     punycode for IDNs), so a look-alike in another script can never
//     match a real entry. lib/punycode.js turns them back for display.
//
// The matching half (normalizeHost, validateEntry, isExcluded, …) uses
// no browser API and is tested in Node (test/exclusions.test.js).
// ---------------------------------------------------------------------

import { MULTI_SUFFIXES } from "./brands.js";
import { IP_LOGGERS, SHORTENERS } from "./trackers.js";
import { registrableDomain } from "./heuristics.js";
import { api } from "./browser.js";

export const KEY_PREFIX = "x:";

// storage.sync allows 512 items. Settings use about ten, so 400 leaves
// room for future settings and is a number people can read.
export const MAX_EXCLUSIONS = 400;

export const MODES = ["domain", "host"];

// Shared hosting suffixes: everything under them belongs to a different
// owner, so excluding the suffix as a whole would exclude strangers.
// MULTI_SUFFIXES (brands.js) covers country suffixes like co.uk.
const SHARED_SUFFIXES = new Set([
  "github.io", "gitlab.io", "pages.dev", "workers.dev", "netlify.app",
  "vercel.app", "herokuapp.com", "web.app", "firebaseapp.com",
  "appspot.com", "blogspot.com", "wordpress.com", "azurewebsites.net",
  "cloudfront.net", "s3.amazonaws.com", "glitch.me", "repl.co",
  "onrender.com", "fly.dev", "ngrok.io", "ngrok-free.app",
]);

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const isIp = (host) => IPV4.test(host) || host.startsWith("[");

// ---------------------------------------------------------------------
// Pure matching
// ---------------------------------------------------------------------

// A URL, a bare hostname or a pasted "host/path" → lowercase ASCII host
// without port or trailing dot. null if it is not a web address.
export function normalizeHost(input) {
  if (typeof input !== "string" && !(input instanceof URL)) return null;
  let text = String(input).trim();
  if (!text) return null;
  text = text.replace(/^\*\./, ""); // "*.example.com" means the domain
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) text = "http://" + text;

  let url;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;

  // The URL parser already lowercases and converts IDNs to punycode.
  const host = url.hostname.replace(/\.+$/, "");
  if (!host || host.includes("..")) return null;
  return host;
}

// The host an entry is stored under. A whole-domain entry for
// "www.example.com" means example.com — nobody wants only the www.
// subtree. IP addresses can only be matched exactly.
export function entryHost(host, mode) {
  if (mode === "domain" && host.startsWith("www.") && host.split(".").length > 2) {
    return host.slice(4);
  }
  return host;
}

function isPublicSuffix(host) {
  return !host.includes(".") || MULTI_SUFFIXES.has(host) || SHARED_SUFFIXES.has(host);
}

// Rules for what may be excluded:
//   • never a public suffix (com, co.uk, github.io) as a whole domain;
//   • a warning, not a refusal, when the site is risky right now: rated
//     dangerous, a known IP logger, or a link shortener.
// `status` is the site's current local verdict, if the caller has one.
//
// Returns { ok, host, mode, error?, warning? } with host and mode
// normalised to what would be stored.
export function validateEntry(input, mode = "domain", { status } = {}) {
  const raw = normalizeHost(input);
  if (!raw) return { ok: false, error: "That doesn't look like a web address." };
  if (!MODES.includes(mode)) mode = "domain";
  if (isIp(raw)) mode = "host"; // an IP has no subdomains

  const host = entryHost(raw, mode);
  if (!host.includes(".") && !isIp(host)) {
    return { ok: false, host, mode, error: `"${host}" is not a website address.` };
  }
  if (mode === "domain" && isPublicSuffix(host)) {
    return {
      ok: false,
      host,
      mode,
      error: `"${host}" is shared by many unrelated sites, so it can't be excluded as a whole. Add the specific site instead.`,
    };
  }

  const registrable = isIp(host) ? host : registrableDomain(host);
  const warnings = [];
  if (IP_LOGGERS.has(host) || IP_LOGGERS.has(registrable)) {
    warnings.push(
      `${registrable} is a known IP logger. Excluding it means its links are no longer flagged or stopped, and opening one records your IP address and rough location.`
    );
  } else if (status === "dangerous") {
    warnings.push(
      "chick-check currently rates this site dangerous. Excluding it turns off the badge, the online checks and blocking for it."
    );
  }
  if (SHORTENERS.has(host) || SHORTENERS.has(registrable)) {
    warnings.push(
      `Excluding ${registrable} turns off the hidden-destination check for every ${registrable} link, including ones that lead to a tracker.`
    );
  }

  return warnings.length
    ? { ok: true, host, mode, warning: warnings.join(" ") }
    : { ok: true, host, mode };
}

// The entry that covers this URL, or null. Exact host entries match only
// themselves; whole-domain entries also match every subdomain.
// `list` is a Map of host → { m, t }.
export function matchingEntry(url, list) {
  if (!list || list.size === 0) return null;
  const host = normalizeHost(url instanceof URL ? url.href : url);
  if (!host) return null;

  const exact = list.get(host);
  if (exact) return { host, ...exact };

  const labels = host.split(".");
  for (let i = 1; i < labels.length - 1; i++) {
    const parent = labels.slice(i).join(".");
    const entry = list.get(parent);
    if (entry && entry.m === "domain") return { host: parent, ...entry };
  }
  return null;
}

export function isExcluded(url, list) {
  return matchingEntry(url, list) !== null;
}

// An exclusion covers the site, never where a link on it sends you.
// With google.com excluded, google.com/url?q=https://phish.example is
// still checked, because the familiar name in front is exactly what
// makes that link work. `verdict` is the local verdict for `url`.
const REDIRECT_SIGNALS = new Set(["openRedirect", "openRedirectToImpersonator"]);

export function scanPaused(url, verdict, list) {
  if (!isExcluded(url, list)) return false;
  return !(verdict?.signals || []).some((s) => REDIRECT_SIGNALS.has(s.id));
}

// Storage items → Map. Ignores anything malformed rather than failing.
export function parseItems(items) {
  const list = new Map();
  for (const [key, value] of Object.entries(items || {})) {
    if (!key.startsWith(KEY_PREFIX) || !value || typeof value !== "object") continue;
    const host = key.slice(KEY_PREFIX.length);
    if (!host) continue;
    list.set(host, { m: value.m === "host" ? "host" : "domain", t: Number(value.t) || 0 });
  }
  return list;
}

// ---------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------
// The list lives in storage.sync, or storage.local when the user turns
// "Sync my exclusion list" off. That switch itself is a normal setting
// (syncExclusions, in config.js) and always lives in sync.

const SYNC_SETTING = "syncExclusions";

async function syncOn() {
  try {
    const { [SYNC_SETTING]: on } = await api.storage.sync.get({ [SYNC_SETTING]: true });
    return on !== false;
  } catch {
    return true;
  }
}

async function activeArea() {
  return (await syncOn()) ? api.storage.sync : api.storage.local;
}

export async function loadExclusions() {
  if (!api?.storage) return new Map();
  try {
    const area = await activeArea();
    return parseItems(await area.get(null));
  } catch {
    return new Map();
  }
}

// Adds (or re-scopes) one site. Returns the validateEntry result, with
// ok:false and an error when the list is full or the write fails.
export async function addExclusion(input, mode = "domain", options = {}) {
  const check = validateEntry(input, mode, options);
  if (!check.ok) return check;

  const list = await loadExclusions();
  if (!list.has(check.host) && list.size >= MAX_EXCLUSIONS) {
    return {
      ...check,
      ok: false,
      error: `Your exclusion list is full (${MAX_EXCLUSIONS} sites). Remove a site you no longer need first.`,
    };
  }

  try {
    const area = await activeArea();
    // A whole-domain entry makes exact entries below it redundant.
    if (check.mode === "domain") {
      const covered = [...list.keys()].filter((h) => h.endsWith("." + check.host));
      if (covered.length) await area.remove(covered.map((h) => KEY_PREFIX + h));
    }
    await area.set({ [KEY_PREFIX + check.host]: { m: check.mode, t: Date.now() } });
  } catch {
    return { ...check, ok: false, error: "The browser didn't save the change. Try again." };
  }
  return check;
}

export async function removeExclusion(host) {
  const area = await activeArea();
  await area.remove(KEY_PREFIX + host);
}

export async function clearExclusions() {
  const area = await activeArea();
  const keys = Object.keys(await area.get(null)).filter((k) => k.startsWith(KEY_PREFIX));
  if (keys.length) await area.remove(keys);
}

// Moves the list to the other storage area when the sync switch flips.
// One set() call, so a large list is not throttled by write limits.
// Order matters: copy, then switch, then clean up — so whatever area is
// active at any moment already holds the full list, and an excluded
// site never briefly counts as not excluded.
export async function setExclusionSync(on) {
  const from = (await syncOn()) ? api.storage.sync : api.storage.local;
  const to = on ? api.storage.sync : api.storage.local;
  if (from === to) {
    await api.storage.sync.set({ [SYNC_SETTING]: on });
    return;
  }
  const items = await from.get(null);
  const mine = Object.fromEntries(
    Object.entries(items).filter(([k]) => k.startsWith(KEY_PREFIX))
  );
  if (Object.keys(mine).length) await to.set(mine);
  await api.storage.sync.set({ [SYNC_SETTING]: on });
  if (Object.keys(mine).length) await from.remove(Object.keys(mine));
}

// Calls back on any change to the list, whichever device made it, and
// when the sync switch moves the list between areas.
export function onExclusionsChanged(callback) {
  api.storage.onChanged.addListener((changes, area) => {
    if (area !== "sync" && area !== "local") return;
    const keys = Object.keys(changes);
    if (keys.some((k) => k.startsWith(KEY_PREFIX)) || (area === "sync" && keys.includes(SYNC_SETTING))) {
      callback();
    }
  });
}
