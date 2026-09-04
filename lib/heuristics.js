// ---------------------------------------------------------------------
// heuristics.js — offline URL inspection
// ---------------------------------------------------------------------
// Pure functions with no network access. They give an instant first
// opinion about a URL and keep working even if every online check
// fails. Shared by the popup and the background service worker.
// ---------------------------------------------------------------------

// A tiny simulated blocklist. The live Google Safe Browsing / DNS checks
// in reputation.js are the real defence; this list just guarantees the
// bundled demo URLs always trip something, even fully offline.
export const KNOWN_BAD_DOMAINS = [
  "paypal-secure-login.com",
  "amaz0n-support.net",
  "appleid-verify.info",
  "secure-appleid.top",
  "login-microsoft-online.com",
  "netflix-billing-update.com",
  "chase-bank-alert.com",
  "wellsfargo-verify-account.com",
  "facebook-security-check.net",
  "instagram-copyright-appeal.com",
  "bankofamerica-alert.info",
  "dhl-parcel-tracking.top",
  "irs-tax-refund-online.com",
  "coinbase-wallet-support.net",
  "linkedin-account-verify.com",
];

// 2a. Raw IP address instead of a domain name.
function checkIpAddress(url) {
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Pattern.test(url.hostname)) {
    return "The address uses a raw IP number instead of a normal web address — real companies don't send you to plain IPs.";
  }
  return null;
}

// 2b. Unencrypted connection (http instead of https).
function checkHttp(url) {
  if (url.protocol === "http:") {
    return "This site doesn't use a secure (https) connection, so anything you type could be read in transit.";
  }
  return null;
}

// 2c. Unusually deep subdomain chain.
function checkSubdomains(url) {
  const labels = url.hostname.split(".").filter(Boolean);
  if (labels.length > 4) {
    return "The web address is a long chain of subdomains, a common trick to hide the real destination.";
  }
  return null;
}

// 2d. Lookalike ("typosquat") version of a well-known brand.
const BRANDS = ["paypal", "google", "amazon", "apple", "microsoft", "facebook", "netflix", "bank"];
const LEET_MAP = { 0: "o", 1: "l", 3: "e", 4: "a", 5: "s", 7: "t", "@": "a" };

function normalizeLeetSpeak(text) {
  return text
    .split("")
    .map((ch) => LEET_MAP[ch] || ch)
    .join("")
    .replace(/rn/g, "m");
}

function checkTyposquat(url) {
  const hostname = url.hostname.toLowerCase();
  const normalized = normalizeLeetSpeak(hostname);
  for (const brand of BRANDS) {
    const containsRealBrand = hostname.includes(brand);
    const containsDisguisedBrand = normalized.includes(brand) && !containsRealBrand;
    if (containsDisguisedBrand) {
      return `The address looks like it's imitating "${brand}" with look-alike characters (0 for o, 1 for l) — a classic phishing trick.`;
    }
  }
  return null;
}

// 2e. Cheap / heavily-abused top-level domain.
const SUSPICIOUS_TLDS = [".zip", ".top", ".xyz", ".click", ".support", ".gq", ".tk", ".info", ".win"];

function checkSuspiciousTld(url) {
  const hostname = url.hostname.toLowerCase();
  const matchedTld = SUSPICIOUS_TLDS.find((tld) => hostname.endsWith(tld));
  if (matchedTld) {
    return `The address ends in "${matchedTld}", a domain ending that's cheap to register and common in scam sites.`;
  }
  return null;
}

// 2f. Exact match (or subdomain) against the simulated blocklist.
function checkBlocklist(url) {
  const hostname = url.hostname.toLowerCase();
  const isListed = KNOWN_BAD_DOMAINS.some(
    (bad) => hostname === bad || hostname.endsWith("." + bad)
  );
  return isListed
    ? "This exact address is on a bundled list of known phishing sites."
    : null;
}

// ---------------------------------------------------------------------
// Parse user input into a URL, forgiving a missing "https://" prefix.
// Returns null if it can't be understood as a web address at all.
// ---------------------------------------------------------------------
export function parseUrl(rawInput) {
  const trimmed = String(rawInput || "").trim();
  if (!trimmed) return null;

  const candidate = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  try {
    const url = new URL(candidate);
    const looksLikeHost =
      url.hostname.includes(".") || /^(\d{1,3}\.){3}\d{1,3}$/.test(url.hostname);
    return looksLikeHost ? url : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------
// Run every heuristic. Returns:
//   { blocklistReason: string|null, heuristicReasons: string[] }
// ---------------------------------------------------------------------
export function runHeuristics(url) {
  return {
    blocklistReason: checkBlocklist(url),
    heuristicReasons: [
      checkIpAddress(url),
      checkHttp(url),
      checkSubdomains(url),
      checkTyposquat(url),
      checkSuspiciousTld(url),
    ].filter(Boolean),
  };
}
