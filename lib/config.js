// ---------------------------------------------------------------------
// config.js — constants, defaults, and settings helpers
// ---------------------------------------------------------------------
// Privacy-by-design defaults: every network feature is OFF until the
// user explicitly turns it on (GDPR Art. 6(1)(a) consent for the
// optional cloud lookups; the local scan runs on legitimate interest,
// Art. 6(1)(f) + Recital 49).
// ---------------------------------------------------------------------

// Bump this whenever the detection logic changes. It is attached to
// every verdict so a disputed result can be reconstructed later
// (accountability, GDPR Art. 5(2)).
import { RDAP_ORIGINS } from "./rdap.js";

export const DETECTION_VERSION = "4.1.0";

// Where "report a false positive" points. Change to your own address or
// a hosted form before distributing.
export const FALSE_POSITIVE_CONTACT =
  "https://github.com/sophiekeesing/URLphishingDetector/issues/new?title=False+positive&labels=false-positive";

// Optional permissions we request at runtime, only when the matching
// feature is switched on. Declared in manifest.json under
// optional_permissions / optional_host_permissions.
export const CLOUD_HOSTS = {
  safeBrowsing: "https://safebrowsing.googleapis.com/*",
  dns: ["https://cloudflare-dns.com/*", "https://dns.quad9.net/*"],
  // Derived from the endpoint map in rdap.js so the permission request
  // and the URLs actually fetched can never drift apart.
  rdap: RDAP_ORIGINS,
};

export const DEFAULT_SETTINGS = {
  // Google Safe Browsing lookup via k-anonymity hash prefixes.
  safeBrowsingEnabled: false,
  safeBrowsingApiKey: "",

  // DNS blocklist cross-check. Sends the hostname (not the full URL) to
  // two public resolvers over HTTPS.
  dnsCheckEnabled: false,

  // Domain age lookup. Sends the registrable domain (example.com — not
  // the subdomain, path or query) to that TLD's official registry.
  domainAgeEnabled: false,

  // Check every page as you browse (needs the "tabs" permission).
  // When false, the extension only scans when you click it.
  autoScanEnabled: false,

  // Consent bookkeeping — when the user last accepted cloud processing.
  cloudConsentAt: null,
};

const STORAGE_AREA = "sync";

export async function getSettings() {
  const stored = await chrome.storage[STORAGE_AREA].get(DEFAULT_SETTINGS);
  return { ...DEFAULT_SETTINGS, ...stored };
}

export async function setSettings(patch) {
  await chrome.storage[STORAGE_AREA].set(patch);
}

export function onSettingsChanged(callback) {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === STORAGE_AREA) callback(changes);
  });
}

// True if any cloud lookup is switched on (i.e. consent was given).
export function cloudEnabled(settings) {
  return Boolean(
    settings.safeBrowsingEnabled || settings.dnsCheckEnabled || settings.domainAgeEnabled
  );
}
