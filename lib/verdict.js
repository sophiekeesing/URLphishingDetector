// ---------------------------------------------------------------------
// verdict.js — turn the raw checks into one plain-language verdict
// ---------------------------------------------------------------------
// Shared by the background service worker (for the toolbar badge) and
// the popup (for the detailed panel), so both always agree.
// ---------------------------------------------------------------------

import { parseUrl, runHeuristics } from "./heuristics.js";
import { DETECTION_VERSION } from "./config.js";

// Risk-score thresholds. Scores come from heuristics.js, where each
// rule contributes points; a single strong signal (a one-character
// misspelling of a big brand) is enough to cross the danger line on
// its own, while several weak ones have to stack up.
export const SUSPICIOUS_AT = 22;
export const DANGEROUS_AT = 50;

export const VERDICT_CONTENT = {
  safe: {
    icon: "✅",
    label: "Looks safe",
    message: "Nothing about this address looks like an imitation, and no enabled blocklist flagged it.",
  },
  suspicious: {
    icon: "⚠️",
    label: "Suspicious",
    message: "This address has warning signs. Be careful — don't enter passwords or payment details unless you're sure.",
  },
  dangerous: {
    icon: "⛔",
    label: "Dangerous — likely phishing",
    message: "This address shows strong signs of impersonating a real site. We recommend not visiting it or entering any information.",
  },
  error: {
    icon: "❓",
    label: "Couldn't check that",
    message: "That doesn't look like a web address we can check. Try something like \"example.com\".",
  },
};

export const BADGE = {
  safe: { text: "", color: "#1e7e34" },
  suspicious: { text: "!", color: "#b58a00" },
  dangerous: { text: "!!", color: "#c62828" },
  error: { text: "", color: "#5b6472" },
};

// ---------------------------------------------------------------------
// evaluate(rawInput, { reputation })
//   rawInput   — string typed by the user, or a tab URL
//   reputation — optional result from reputation.js; omit for an
//                instant offline-only verdict
//
// Returns { status, score, reasons, signals, href, secure, official, … }
// ---------------------------------------------------------------------
export function evaluate(rawInput, { reputation } = {}) {
  const url = parseUrl(rawInput);
  if (!url) {
    return {
      status: "error",
      score: 0,
      reasons: [],
      signals: [],
      href: null,
      secure: null,
      official: false,
      detectionVersion: DETECTION_VERSION,
      checkedAt: new Date().toISOString(),
    };
  }

  const { score, signals, official } = runHeuristics(url);

  const reputationMalicious = reputation?.malicious ?? false;
  const reputationReasons = reputation?.reasons ?? [];

  // A confirmed blocklist hit maxes the score out.
  const finalScore = reputationMalicious ? 100 : score;

  const reasons = [...reputationReasons, ...signals.map((s) => s.message)];

  let status;
  if (finalScore >= DANGEROUS_AT) status = "dangerous";
  else if (finalScore >= SUSPICIOUS_AT) status = "suspicious";
  else status = "safe";

  return {
    status,
    score: finalScore,
    reasons,
    signals,
    href: url.href,
    secure: url.protocol === "https:",
    official,
    // Recorded so a disputed verdict can be reconstructed (GDPR Art. 5(2)).
    detectionVersion: DETECTION_VERSION,
    checkedAt: new Date().toISOString(),
  };
}
