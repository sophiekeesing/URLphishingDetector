// =====================================================================
// URL Shield — Phishing URL Detector (prototype)
//
// This is a DEMO. Detection is done entirely in the browser using:
//   1. A hardcoded "known-bad" list (simulates a threat database).
//   2. A handful of simple heuristics (simulates the kind of checks
//      a real product would layer on top of live threat feeds).
//
// Nothing here calls out to the internet. See the "REAL API
// INTEGRATION POINT" comment below for where a production build
// would plug in a real lookup (Google Safe Browsing, PhishTank, etc).
// =====================================================================

// ---------------------------------------------------------------------
// 1. SIMULATED THREAT DATABASE
// A short, hardcoded list of "known-bad" domains/hosts, standing in for
// a real blocklist feed. Any exact hostname match (or subdomain of one
// of these) is treated as a confirmed phishing site.
// ---------------------------------------------------------------------
const KNOWN_BAD_DOMAINS = [
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

// ---------------------------------------------------------------------
// 2. HEURISTIC CHECKS
// Each function inspects the URL and, if it looks suspicious, returns
// a short plain-language explanation. If the check passes, it returns
// null. Keeping these small and independent makes it easy to see which
// specific rule fired.
// ---------------------------------------------------------------------

// 2a. Is the host a raw IP address instead of a domain name?
// Legitimate sites almost never ask you to visit a bare IP address.
function checkIpAddress(url) {
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Pattern.test(url.hostname)) {
    return "The address uses a raw IP number instead of a normal web address — real companies don't send you to plain IPs.";
  }
  return null;
}

// 2b. Is the connection unencrypted (http instead of https)?
function checkHttp(url) {
  if (url.protocol === "http:") {
    return "This site doesn't use a secure (https) connection, so any information you enter could be intercepted.";
  }
  return null;
}

// 2c. Does the hostname have an unusually large number of subdomains?
// e.g. "login.account.verify.paypal.example-security.com"
function checkSubdomains(url) {
  const labels = url.hostname.split(".").filter(Boolean);
  // A normal site is usually "www.example.com" or "example.com" (2-3 labels).
  if (labels.length > 4) {
    return "The web address is made of an unusually long chain of subdomains, a common trick to hide the real destination.";
  }
  return null;
}

// 2d. Does the hostname contain a "lookalike" version of a well-known brand?
// We watch for common character swaps (0 for o, 1 for l, rn for m, etc.)
// combined with the brand name NOT appearing in its normal spelling.
const BRANDS = ["paypal", "google", "amazon", "apple", "microsoft", "facebook", "netflix", "bank"];

// Map of lookalike substitutions back to the letter they're imitating.
const LEET_MAP = { 0: "o", 1: "l", 3: "e", 4: "a", 5: "s", 7: "t", "@": "a" };

function normalizeLeetSpeak(text) {
  return text
    .split("")
    .map((ch) => LEET_MAP[ch] || ch)
    .join("")
    .replace(/rn/g, "m"); // "rn" is a classic visual stand-in for "m"
}

function checkTyposquat(url) {
  const hostname = url.hostname.toLowerCase();
  const normalized = normalizeLeetSpeak(hostname);

  for (const brand of BRANDS) {
    const containsRealBrand = hostname.includes(brand);
    const containsDisguisedBrand = normalized.includes(brand) && !containsRealBrand;

    if (containsDisguisedBrand) {
      return `The address looks like it's imitating "${brand}" using look-alike characters (like 0 for o, or 1 for l) — a classic phishing trick.`;
    }
  }
  return null;
}

// 2e. Does the URL use a TLD that's cheap/unregulated and heavily abused
// for phishing campaigns?
const SUSPICIOUS_TLDS = [".zip", ".top", ".xyz", ".click", ".support", ".gq", ".tk", ".info", ".win"];

function checkSuspiciousTld(url) {
  const hostname = url.hostname.toLowerCase();
  const matchedTld = SUSPICIOUS_TLDS.find((tld) => hostname.endsWith(tld));
  if (matchedTld) {
    return `The address ends in "${matchedTld}", a domain ending that's cheap to register and frequently used in scam sites.`;
  }
  return null;
}

// 2f. Exact match (or subdomain of a match) against the simulated blocklist.
function checkBlocklist(url) {
  const hostname = url.hostname.toLowerCase();
  const isListed = KNOWN_BAD_DOMAINS.some(
    (bad) => hostname === bad || hostname.endsWith("." + bad)
  );
  if (isListed) {
    return "This exact address is on a known list of reported phishing sites.";
  }
  return null;
}

// ---------------------------------------------------------------------
// 3. VERDICT LOGIC
// Runs every check, tallies the results, and turns them into one of
// three plain-language verdicts: safe, suspicious, or dangerous.
// ---------------------------------------------------------------------
function evaluateUrl(rawInput) {
  const url = parseUrl(rawInput);
  if (!url) {
    return { status: "error" };
  }

  const blocklistReason = checkBlocklist(url);

  const heuristicReasons = [
    checkIpAddress(url),
    checkHttp(url),
    checkSubdomains(url),
    checkTyposquat(url),
    checkSuspiciousTld(url),
  ].filter(Boolean); // drop the nulls (passed checks)

  const allReasons = blocklistReason ? [blocklistReason, ...heuristicReasons] : heuristicReasons;

  // --------------------------------------------------------------
  // REAL API INTEGRATION POINT
  // --------------------------------------------------------------
  // In a production extension, this is where you'd replace/augment
  // the local blocklist + heuristics with a live lookup, e.g.:
  //
  //   const response = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=API_KEY", {
  //     method: "POST",
  //     headers: { "Content-Type": "application/json" },
  //     body: JSON.stringify({
  //       client: { clientId: "url-shield-demo", clientVersion: "1.0" },
  //       threatInfo: {
  //         threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
  //         platformTypes: ["ANY_PLATFORM"],
  //         threatEntryTypes: ["URL"],
  //         threatEntries: [{ url: url.href }],
  //       },
  //     }),
  //   });
  //   const result = await response.json();
  //   // result.matches (if present) would confirm the URL is malicious
  //
  // A similar call could be made to PhishTank's checkurl API. The
  // local checks above would still be useful as an instant, offline
  // first pass while the network request is in flight.
  // --------------------------------------------------------------

  let status;
  if (blocklistReason || heuristicReasons.length >= 2) {
    status = "dangerous";
  } else if (heuristicReasons.length === 1) {
    status = "suspicious";
  } else {
    status = "safe";
  }

  return { status, reasons: allReasons, href: url.href };
}

// Parses user input into a URL object, forgiving a missing "https://"
// prefix (so "example.com" works the same as "https://example.com").
// Returns null if the input can't be understood as a URL at all.
function parseUrl(rawInput) {
  const trimmed = rawInput.trim();
  if (!trimmed) return null;

  const candidate = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`;

  try {
    const url = new URL(candidate);
    // Require at least one "." in the hostname (or it be an IP) so that
    // plain junk text like "hello" isn't treated as a valid address.
    const looksLikeHost = url.hostname.includes(".") || /^(\d{1,3}\.){3}\d{1,3}$/.test(url.hostname);
    return looksLikeHost ? url : null;
  } catch (err) {
    return null;
  }
}

// ---------------------------------------------------------------------
// 4. UI CONTENT for each verdict (badge icon/label + friendly headline)
// ---------------------------------------------------------------------
const VERDICT_CONTENT = {
  safe: {
    icon: "✅",
    label: "Safe",
    message: "We didn't find anything suspicious about this address.",
  },
  suspicious: {
    icon: "⚠️",
    label: "Suspicious",
    message: "This address has a warning sign. Proceed carefully, especially before entering any personal info.",
  },
  dangerous: {
    icon: "⛔",
    label: "Dangerous – likely phishing",
    message: "This address shows strong signs of being a phishing scam. We recommend not visiting it or entering any information.",
  },
  error: {
    icon: "❓",
    label: "Couldn't check that",
    message: "That doesn't look like a web address we can check. Try something like \"example.com\" or \"https://example.com\".",
  },
};

// ---------------------------------------------------------------------
// 5. EXAMPLE URLS (for the clickable demo chips)
// ---------------------------------------------------------------------
const EXAMPLE_URLS = [
  { url: "https://www.wikipedia.org", kind: "safe" },
  { url: "https://github.com", kind: "safe" },
  { url: "http://192.168.12.44/login", kind: "bad" },
  { url: "http://paypa1-login.com", kind: "bad" },
  { url: "http://secure-appleid.top", kind: "bad" },
];

// ---------------------------------------------------------------------
// 6. DOM WIRING
// ---------------------------------------------------------------------
const inputEl = document.getElementById("url-input");
const checkBtn = document.getElementById("check-btn");
const resultPanel = document.getElementById("result-panel");
const resultBadge = document.getElementById("result-badge");
const resultIcon = document.getElementById("result-icon");
const resultLabel = document.getElementById("result-label");
const resultMessage = document.getElementById("result-message");
const resultReasons = document.getElementById("result-reasons");
const chipsContainer = document.getElementById("example-chips");
const useTabBtn = document.getElementById("use-tab-btn");

function runCheck() {
  const { status, reasons, href } = evaluateUrl(inputEl.value);
  renderResult(status, reasons);
}

function renderResult(status, reasons) {
  const content = VERDICT_CONTENT[status];

  resultPanel.hidden = false;
  resultPanel.className = `result result--${status}`;
  resultIcon.textContent = content.icon;
  resultLabel.textContent = content.label;
  resultMessage.textContent = content.message;

  resultReasons.innerHTML = "";
  if (reasons && reasons.length) {
    reasons.forEach((reason) => {
      const li = document.createElement("li");
      li.textContent = reason;
      resultReasons.appendChild(li);
    });
  }
}

function buildExampleChips() {
  EXAMPLE_URLS.forEach(({ url, kind }) => {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = `chip chip--${kind}`;
    chip.textContent = url;
    chip.addEventListener("click", () => {
      inputEl.value = url;
      runCheck();
    });
    chipsContainer.appendChild(chip);
  });
}

checkBtn.addEventListener("click", runCheck);
inputEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") runCheck();
});

buildExampleChips();

// ---------------------------------------------------------------------
// 7. EXTENSION-ONLY FEATURE: check the currently active tab's URL.
// chrome.tabs only exists when this page is running as an installed
// extension's popup (granted via the "activeTab" permission in
// manifest.json) — it's undefined if index.html is just opened as a
// plain file in the browser. We feature-detect so the same script.js
// works in both contexts, and only reveal the button when it'll work.
// ---------------------------------------------------------------------
const isExtensionContext = typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query;

if (isExtensionContext) {
  useTabBtn.hidden = false;
  useTabBtn.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs[0];
      if (activeTab && activeTab.url) {
        inputEl.value = activeTab.url;
        runCheck();
      }
    });
  });
}
