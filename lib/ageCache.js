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

function fresh(entry) {
  return entry && entry.expires > Date.now();
}

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