// ---------------------------------------------------------------------
// reputation.js — live online reputation checks
// ---------------------------------------------------------------------
// Two independent signals:
//
//   1. Google Safe Browsing Lookup API  (optional — needs a free key)
//      The industry-standard phishing/malware list that Chrome itself
//      uses. Enabled only once the user saves an API key on the
//      options page.
//
//   2. DNS blocklist cross-check        (always on, no key required)
//      Resolve the hostname twice: once through Cloudflare 1.1.1.1
//      (an unfiltered resolver) and once through Quad9 9.9.9.9 (which
//      refuses to resolve domains on its threat-intelligence feeds).
//      If Cloudflare resolves it fine but Quad9 will not, that domain
//      is on a malware/phishing blocklist.
//
// Both run from the background service worker, which has host
// permissions for these endpoints (see manifest.json).
// ---------------------------------------------------------------------

const SAFE_BROWSING_ENDPOINT =
  "https://safebrowsing.googleapis.com/v4/threatMatches:find";
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

// --- 1. Google Safe Browsing ----------------------------------------
async function checkSafeBrowsing(href, apiKey) {
  if (!apiKey) {
    return { id: "safeBrowsing", checked: false, malicious: false };
  }

  try {
    const res = await fetchWithTimeout(
      `${SAFE_BROWSING_ENDPOINT}?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "url-shield", clientVersion: "2.0.0" },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: href }],
          },
        }),
      }
    );

    if (!res.ok) {
      const detail = res.status === 400 || res.status === 403
        ? "the API key looks invalid or is missing the Safe Browsing API"
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
    if (matches.length > 0) {
      const kinds = [...new Set(matches.map((m) => prettyThreat(m.threatType)))];
      return {
        id: "safeBrowsing",
        checked: true,
        malicious: true,
        reason: `Google Safe Browsing flags this URL: ${kinds.join(", ")}.`,
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

// --- 2. DNS blocklist cross-check ----------------------------------
async function resolveJson(endpoint, hostname) {
  const res = await fetchWithTimeout(
    `${endpoint}?name=${encodeURIComponent(hostname)}&type=A`,
    { headers: { Accept: "application/dns-json" } }
  );
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// DNS response status codes we care about.
const NOERROR = 0;
const NXDOMAIN = 3;

function hasAddresses(dns) {
  return (
    dns &&
    dns.Status === NOERROR &&
    Array.isArray(dns.Answer) &&
    dns.Answer.some((a) => a.type === 1 || a.type === 5) // A or CNAME
  );
}

function isBlocked(dns) {
  if (!dns) return false;
  // Quad9 answers a blocked name with NXDOMAIN, or NOERROR + empty answer.
  if (dns.Status === NXDOMAIN) return true;
  if (dns.Status === NOERROR && (!dns.Answer || dns.Answer.length === 0)) return true;
  return false;
}

async function checkDnsBlocklist(hostname) {
  // Skip raw IPs — nothing to resolve.
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

// ---------------------------------------------------------------------
// Public entry point. Runs both checks in parallel.
// Returns:
//   {
//     malicious: boolean,          // any source is confident it's bad
//     reasons: string[],           // human-readable hits
//     sources: [{ id, label, state }],  // per-source status for the UI
//   }
// state ∈ "clear" | "flagged" | "skipped" | "error"
// ---------------------------------------------------------------------
export async function checkReputation(href, { apiKey } = {}) {
  let hostname;
  try {
    hostname = new URL(href).hostname;
  } catch {
    return { malicious: false, reasons: [], sources: [] };
  }

  const [sb, dns] = await Promise.all([
    checkSafeBrowsing(href, apiKey),
    checkDnsBlocklist(hostname),
  ]);

  const results = [sb, dns];
  const reasons = [];
  const sources = [];

  const meta = {
    safeBrowsing: "Google Safe Browsing",
    dnsBlocklist: "Quad9 DNS blocklist",
  };

  for (const r of results) {
    let state;
    if (r.error) state = "error";
    else if (!r.checked) state = "skipped";
    else if (r.malicious) state = "flagged";
    else state = "clear";

    sources.push({ id: r.id, label: meta[r.id] || r.id, state, note: r.error });
    if (r.malicious && r.reason) reasons.push(r.reason);
  }

  return {
    malicious: results.some((r) => r.malicious),
    reasons,
    sources,
  };
}
