// ---------------------------------------------------------------------
// reputation.js — optional online reputation checks
// ---------------------------------------------------------------------
// Nothing here runs unless the user has switched the matching feature
// on (see options page / config.js). Two independent signals:
//
//   1. Google Safe Browsing (k-anonymity)   — needs a free API key
//      Only 4-byte SHA-256 hash prefixes of the host+path leave the
//      device. The server returns candidate full hashes; the exact
//      match is done locally. The URL itself is never transmitted.
//
//   2. DNS blocklist cross-check             — no key
//      Sends the HOSTNAME ONLY (not the path or query) to two public
//      DNS-over-HTTPS resolvers: Cloudflare 1.1.1.1 (unfiltered) and
//      Quad9 9.9.9.9 (blocks known-malicious domains). If Cloudflare
//      resolves it but Quad9 refuses, the domain is on a threat feed.
//
// Both run from the background service worker, which holds the relevant
// host permission only after the user opted in.
// ---------------------------------------------------------------------

import { canonicalize } from "./canonicalize.js";
import { hashExpressions } from "./hash.js";
import { registrableDomain } from "./heuristics.js";
import { lookupDomainAge, scoreDomainAge, rdapSupports } from "./rdap.js";

const SAFE_BROWSING_ENDPOINT =
  "https://safebrowsing.googleapis.com/v4/fullHashes:find";
const CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query";
const QUAD9_DOH = "https://dns.quad9.net/dns-query";
const FETCH_TIMEOUT_MS = 6000;

function fetchWithTimeout(resource, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  return fetch(resource, { ...options, signal: controller.signal }).finally(() =>
    clearTimeout(timer)
  );
}

function prettyThreat(type) {
  switch (type) {
    case "SOCIAL_ENGINEERING":
      return "phishing / social engineering";
    case "MALWARE":
      return "malware";
    case "UNWANTED_SOFTWARE":
      return "unwanted software";
    case "POTENTIALLY_HARMFUL_APPLICATION":
      return "harmful application";
    default:
      return (type || "threat").toLowerCase().replace(/_/g, " ");
  }
}

// --- 1. Google Safe Browsing (hash-prefix / k-anonymity) -----------
async function checkSafeBrowsing(rawUrl, settings) {
  if (!settings.safeBrowsingEnabled || !settings.safeBrowsingApiKey) {
    return { id: "safeBrowsing", checked: false, malicious: false };
  }

  const canon = canonicalize(rawUrl);
  if (!canon || canon.expressions.length === 0) {
    return { id: "safeBrowsing", checked: false, malicious: false };
  }

  try {
    const hashed = await hashExpressions(canon.expressions);
    const prefixes = [...new Set(hashed.map((h) => h.prefixB64))];
    const localFullHashes = new Set(hashed.map((h) => h.fullHashB64));

    const res = await fetchWithTimeout(
      `${SAFE_BROWSING_ENDPOINT}?key=${encodeURIComponent(settings.safeBrowsingApiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "url-shield", clientVersion: "3.0.0" },
          clientStates: [],
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            // Only truncated hash prefixes are sent — never the URL.
            threatEntries: prefixes.map((hash) => ({ hash })),
          },
        }),
      }
    );

    if (!res.ok) {
      const detail =
        res.status === 400 || res.status === 403
          ? "the API key looks invalid or the Safe Browsing API is not enabled"
          : `HTTP ${res.status}`;
      return {
        id: "safeBrowsing",
        checked: false,
        malicious: false,
        error: `Google Safe Browsing check failed (${detail}).`,
      };
    }

    const data = await res.json();
    const matches = Array.isArray(data.matches) ? data.matches : [];

    // A prefix match is only a real hit if a returned FULL hash matches
    // one we computed locally.
    const confirmed = matches.filter(
      (m) => m.threat && localFullHashes.has(m.threat.hash)
    );

    if (confirmed.length > 0) {
      const kinds = [...new Set(confirmed.map((m) => prettyThreat(m.threatType)))];
      return {
        id: "safeBrowsing",
        checked: true,
        malicious: true,
        reason: `Google Safe Browsing flags this address: ${kinds.join(", ")}.`,
      };
    }
    return { id: "safeBrowsing", checked: true, malicious: false };
  } catch (err) {
    return {
      id: "safeBrowsing",
      checked: false,
      malicious: false,
      error:
        err.name === "AbortError"
          ? "Google Safe Browsing check timed out."
          : "Google Safe Browsing check could not reach the server.",
    };
  }
}

// --- 2. DNS blocklist cross-check (hostname only) ------------------
async function resolveJson(endpoint, hostname) {
  const res = await fetchWithTimeout(
    `${endpoint}?name=${encodeURIComponent(hostname)}&type=A`,
    { headers: { Accept: "application/dns-json" } }
  );
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

const NOERROR = 0;
const NXDOMAIN = 3;

function hasAddresses(dns) {
  return (
    dns &&
    dns.Status === NOERROR &&
    Array.isArray(dns.Answer) &&
    dns.Answer.some((a) => a.type === 1 || a.type === 5)
  );
}

function isBlocked(dns) {
  if (!dns) return false;
  if (dns.Status === NXDOMAIN) return true;
  if (dns.Status === NOERROR && (!dns.Answer || dns.Answer.length === 0)) return true;
  return false;
}

async function checkDnsBlocklist(rawUrl, settings) {
  if (!settings.dnsCheckEnabled) {
    return { id: "dnsBlocklist", checked: false, malicious: false };
  }

  let hostname;
  try {
    hostname = new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return { id: "dnsBlocklist", checked: false, malicious: false };
  }
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    return { id: "dnsBlocklist", checked: false, malicious: false };
  }

  try {
    const [unfiltered, filtered] = await Promise.all([
      resolveJson(CLOUDFLARE_DOH, hostname),
      resolveJson(QUAD9_DOH, hostname),
    ]);

    if (hasAddresses(unfiltered) && isBlocked(filtered)) {
      return {
        id: "dnsBlocklist",
        checked: true,
        malicious: true,
        reason:
          "Quad9's threat-intelligence resolver refuses to load this domain — it is on a malware or phishing blocklist.",
      };
    }
    return { id: "dnsBlocklist", checked: true, malicious: false };
  } catch (err) {
    return {
      id: "dnsBlocklist",
      checked: false,
      malicious: false,
      error:
        err.name === "AbortError"
          ? "DNS blocklist check timed out."
          : "DNS blocklist check could not reach a resolver.",
    };
  }
}

// --- 3. Domain age via RDAP (registrable domain only) --------------
// Unlike the two checks above this is not a yes/no blocklist — it
// returns a weighted signal that is added to the risk score.
async function checkDomainAge(rawUrl, settings) {
  if (!settings.domainAgeEnabled) {
    return { id: "domainAge", checked: false, malicious: false };
  }

  let registrable;
  try {
    const host = new URL(rawUrl).hostname.toLowerCase();
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      return { id: "domainAge", checked: false, malicious: false };
    }
    registrable = registrableDomain(host);
  } catch {
    return { id: "domainAge", checked: false, malicious: false };
  }

  if (!rdapSupports(registrable)) {
    return {
      id: "domainAge",
      checked: false,
      malicious: false,
      note: `No public registry lookup exists for .${registrable.split(".").pop()} domains.`,
    };
  }

  const age = await lookupDomainAge(registrable);
  if (!age) {
    return {
      id: "domainAge",
      checked: false,
      malicious: false,
      error: "The domain registry did not answer the age lookup.",
    };
  }

  return {
    id: "domainAge",
    checked: true,
    malicious: false,
    signal: scoreDomainAge(age),
    detail: `registered ${age.registeredAt}`,
  };
}

// ---------------------------------------------------------------------
// Public entry point. Runs whichever checks the user has enabled.
// Returns { malicious, reasons[], signals[], sources[] }
//   sources[].state ∈ "clear" | "flagged" | "skipped" | "error"
//   signals[]      weighted {id, weight, message} added to the score
// ---------------------------------------------------------------------
export async function checkReputation(rawUrl, settings) {
  const [sb, dns, age] = await Promise.all([
    checkSafeBrowsing(rawUrl, settings),
    checkDnsBlocklist(rawUrl, settings),
    checkDomainAge(rawUrl, settings),
  ]);

  const meta = {
    safeBrowsing: "Google Safe Browsing (hash prefix)",
    dnsBlocklist: "Quad9 DNS blocklist (hostname)",
    domainAge: "Domain age (RDAP)",
  };

  const results = [sb, dns, age];
  const sources = [];
  const reasons = [];
  const signals = [];

  for (const r of results) {
    let state;
    if (r.error) state = "error";
    else if (!r.checked) state = "skipped";
    else if (r.malicious || (r.signal && r.signal.weight > 0)) state = "flagged";
    else state = "clear";

    sources.push({
      id: r.id,
      label: meta[r.id] || r.id,
      state,
      note: r.error || r.note,
      detail: r.detail,
    });

    if (r.malicious && r.reason) reasons.push(r.reason);
    if (r.signal) signals.push(r.signal);
  }

  return {
    malicious: results.some((r) => r.malicious),
    reasons,
    signals,
    sources,
  };
}
