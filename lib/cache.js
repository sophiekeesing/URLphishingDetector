// ---------------------------------------------------------------------
// cache.js — verdict cache that survives the service worker dying
// ---------------------------------------------------------------------
// MV3 stops the worker after roughly 30 seconds of inactivity, which
// wipes anything held in a plain Map. A 10-minute TTL in memory was
// therefore mostly fiction: in real browsing the same hostname was
// re-fetched again and again.
//
// Two tiers:
//   L1  an in-memory Map — free, and enough within one burst of activity
//   L2  chrome.storage.session — survives worker restarts, is cleared
//       when the browser closes, and is never written to disk, so it
//       does not turn into a browsing history on the user's machine
//
// Also here: per-hostname request coalescing. Twenty tabs opening the
// same site should produce one set of lookups, not twenty.
// ---------------------------------------------------------------------

// Longer than the old 10 minutes because the cache now actually holds.
// A warning tool can tolerate a verdict being up to half an hour stale;
// what it cannot tolerate is being rate-limited into saying nothing.
export const CACHE_TTL_MS = 30 * 60 * 1000;

const PREFIX = "cc:";
const MAX_ENTRIES = 500;

const memory = new Map(); // hostname -> { result, expires }
const inFlight = new Map(); // hostname -> Promise<result>

function fresh(entry) {
  return entry && entry.expires > Date.now();
}

export async function cacheGet(hostname) {
  const hit = memory.get(hostname);
  if (fresh(hit)) return hit.result;
  if (hit) memory.delete(hostname);

  if (typeof chrome === "undefined" || !chrome.storage?.session) return null;
  try {
    const key = PREFIX + hostname;
    const { [key]: stored } = await chrome.storage.session.get(key);
    if (fresh(stored)) {
      memory.set(hostname, stored); // promote to L1
      return stored.result;
    }
    if (stored) await chrome.storage.session.remove(key);
  } catch {
    /* storage unavailable — behave as a miss */
  }
  return null;
}

export async function cacheSet(hostname, result) {
  const entry = { result, expires: Date.now() + CACHE_TTL_MS };
  memory.set(hostname, entry);

  if (typeof chrome === "undefined" || !chrome.storage?.session) return;
  try {
    await chrome.storage.session.set({ [PREFIX + hostname]: entry });
    if (memory.size > MAX_ENTRIES) await prune();
  } catch {
    // Quota exceeded is the likely cause, so make room and move on.
    await prune().catch(() => {});
  }
}

// Drop expired entries, then the oldest, to stay under the session
// storage quota.
async function prune() {
  const now = Date.now();
  for (const [host, entry] of memory) {
    if (entry.expires <= now) memory.delete(host);
  }
  if (typeof chrome === "undefined" || !chrome.storage?.session) return;

  const all = await chrome.storage.session.get(null);
  const mine = Object.entries(all).filter(([k]) => k.startsWith(PREFIX));
  const dead = mine.filter(([, v]) => !v || v.expires <= now).map(([k]) => k);

  const alive = mine.filter(([, v]) => v && v.expires > now);
  if (alive.length > MAX_ENTRIES) {
    alive.sort((a, b) => a[1].expires - b[1].expires);
    dead.push(...alive.slice(0, alive.length - MAX_ENTRIES).map(([k]) => k));
  }
  if (dead.length) await chrome.storage.session.remove(dead);
}

export async function cacheClear() {
  memory.clear();
  inFlight.clear();
  if (typeof chrome === "undefined" || !chrome.storage?.session) return;
  try {
    const all = await chrome.storage.session.get(null);
    const keys = Object.keys(all).filter((k) => k.startsWith(PREFIX));
    if (keys.length) await chrome.storage.session.remove(keys);
  } catch {
    /* nothing to clear */
  }
}

// Run `work` for this hostname, or join the run already in progress.
// This is what stops a 20-tab restore of one site from firing 20
// identical sets of lookups.
export function coalesce(hostname, work) {
  const existing = inFlight.get(hostname);
  if (existing) return existing;

  const p = (async () => work())().finally(() => inFlight.delete(hostname));
  inFlight.set(hostname, p);
  return p;
}

export function inFlightCount() {
  return inFlight.size;
}

// ---------------------------------------------------------------------
// Domain-age cache
// ---------------------------------------------------------------------
// A registration date is effectively immutable, so re-asking a registry
// for one is pure waste — and registries are the tightest budget we
// have. Caching it for the session turns RDAP into roughly one query
// per distinct domain per browser session.
//
// Deliberately session storage, not local: a registration date on disk
// would amount to a record of the domains this person visited, which is
// exactly what PRIVACY.md promises not to keep.
const AGE_PREFIX = "age:";
const AGE_TTL_MS = 24 * 60 * 60 * 1000;
// A miss ("no RDAP for this TLD", "registry did not answer") is worth
// remembering too, but for less long, in case it was transient.
const AGE_MISS_TTL_MS = 60 * 60 * 1000;

const ageMemory = new Map();

export async function ageGet(domain) {
  const hit = ageMemory.get(domain);
  if (fresh(hit)) return { hit: true, value: hit.value };

  if (typeof chrome === "undefined" || !chrome.storage?.session) return { hit: false };
  try {
    const key = AGE_PREFIX + domain;
    const { [key]: stored } = await chrome.storage.session.get(key);
    if (fresh(stored)) {
      ageMemory.set(domain, stored);
      return { hit: true, value: stored.value };
    }
  } catch {
    /* treat as a miss */
  }
  return { hit: false };
}

export async function ageSet(domain, value) {
  const entry = {
    value,
    expires: Date.now() + (value ? AGE_TTL_MS : AGE_MISS_TTL_MS),
  };
  ageMemory.set(domain, entry);
  if (typeof chrome === "undefined" || !chrome.storage?.session) return;
  try {
    await chrome.storage.session.set({ [AGE_PREFIX + domain]: entry });
  } catch {
    /* quota — the in-memory tier still helps */
  }
}
