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

// What "stop the page before it loads" needs. webNavigation reports a
// navigation before the network request goes out, which is the only
// point at which an IP-logger link can still be stopped — once the
// request is sent, the logging has already happened. Seeing navigations
// to arbitrary sites requires <all_urls>, so this is deliberately a
// separate, explicit grant.
export const BLOCKING_PERMISSIONS = {
  permissions: ["webNavigation"],
  origins: ["<all_urls>"],
};

// Network checks are ON by default: protection that has to be switched
// on protects almost nobody. They run on the legitimate interest in
// network and information security (GDPR Art. 6(1)(f), Recital 49)
// rather than on consent, which makes the opt-OUT switches and the
// disclosure in PRIVACY.md load-bearing. Every one can be turned off,
// and the local engine keeps working when they are.
export const DEFAULT_SETTINGS = {
  // Google Safe Browsing lookup via k-anonymity hash prefixes. Stays
  // dormant until the user supplies an API key — only they can.
  safeBrowsingEnabled: true,
  safeBrowsingApiKey: "",

  // DNS blocklist cross-check. Sends the hostname (not the full URL) to
  // two public resolvers over HTTPS.
  dnsCheckEnabled: true,

  // Domain age lookup. Sends the registrable domain (example.com — not
  // the subdomain, path or query) to that TLD's official registry.
  domainAgeEnabled: true,

  // Check every page as you browse and show the verdict on the badge.
  autoScanEnabled: true,

  // Stop a dangerous page before it loads and show a warning instead.
  // Needs the optional webNavigation + <all_urls> permissions, which
  // the browser will not grant without an explicit click, so this one
  // cannot default to on.
  blockingEnabled: false,

  // Also stop links whose destination cannot be seen at all — short
  // links and unknown redirectors. This is what defeats chaining one
  // shortener behind another to hide a tracker, since it does not
  // matter what is behind the link if nothing is ever sent to it.
  // Only has an effect while blockingEnabled is on.
  blockHiddenDestinations: true,

  // When the user last reviewed the cloud-processing settings.
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
