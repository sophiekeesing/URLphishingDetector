// ---------------------------------------------------------------------
// verdict.js — turn raw checks into one plain-language verdict
// ---------------------------------------------------------------------
// Shared by the background service worker (for the toolbar badge) and
// the popup (for the detailed panel), so both always agree.
// ---------------------------------------------------------------------

import { parseUrl, runHeuristics } from "./heuristics.js";
import { DETECTION_VERSION } from "./config.js";

export const VERDICT_CONTENT = {
  safe: {
    icon: "✅", // ✅
    label: "Looks safe",
    message: "No online blocklist flagged this address and nothing about it looks suspicious.",
  },
  suspicious: {
    icon: "⚠️", // ⚠️
    label: "Suspicious",
    message: "This address has a warning sign. Be careful — don't enter passwords or payment details unless you're sure.",
  },
  dangerous: {
    icon: "⛔", // ⛔
    label: "Dangerous — likely phishing",
    message: "This address shows strong signs of being a scam. We recommend not visiting it or entering any information.",
  },
  error: {
    icon: "❓", // ❓
    label: "Couldn't check that",
    message: "That doesn't look like a web address we can check. Try something like \"example.com\".",
  },
};

// Badge shown on the toolbar icon per verdict.
export const BADGE = {
  safe: { text: "", color: "#1e7e34" },
  suspicious: { text: "!", color: "#b58a00" },
  dangerous: { text: "!!", color: "#c62828" },
  error: { text: "", color: "#5b6472" },
};

// ---------------------------------------------------------------------
// evaluate(rawInput, { reputation })
//   rawInput   — string typed by the user or a tab URL
//   reputation — optional result from reputation.js checkReputation();
//                omit it for an instant offline-only verdict
//
// Returns { status, reasons, href, secure }
//   status ∈ "safe" | "suspicious" | "dangerous" | "error"
// ---------------------------------------------------------------------
export function evaluate(rawInput, { reputation } = {}) {
  const url = parseUrl(rawInput);
  if (!url) return { status: "error", reasons: [], href: null, secure: null };

  const { blocklistReason, heuristicReasons } = runHeuristics(url);

  const reputationReasons = reputation?.reasons ?? [];
  const reputationMalicious = reputation?.malicious ?? false;

  const reasons = [
    ...reputationReasons,
    ...(blocklistReason ? [blocklistReason] : []),
    ...heuristicReasons,
  ];

  let status;
  if (reputationMalicious || blocklistReason || heuristicReasons.length >= 2) {
    status = "dangerous";
  } else if (heuristicReasons.length === 1) {
    status = "suspicious";
  } else {
    status = "safe";
  }

  return {
    status,
    reasons,
    href: url.href,
    secure: url.protocol === "https:",
    // Recorded so a disputed verdict can be reconstructed (GDPR Art. 5(2)).
    detectionVersion: DETECTION_VERSION,
    checkedAt: new Date().toISOString(),
  };
}
