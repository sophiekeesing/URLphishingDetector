// ---------------------------------------------------------------------
// result.js — standalone link report
// ---------------------------------------------------------------------
// Fallback for the right-click check when the page refuses injection
// (chrome:// pages, the web store, PDFs). Same verdict, ordinary tab.
// ---------------------------------------------------------------------

import { evaluate, VERDICT_CONTENT } from "./lib/verdict.js";
import { DETECTION_VERSION, FALSE_POSITIVE_CONTACT } from "./lib/config.js";

const target = new URLSearchParams(location.search).get("url") || "";

// Attacker-controlled: the address they wanted opened. Text, not markup.
document.getElementById("target-url").textContent = target;
document.getElementById("version").textContent = `logic v${DETECTION_VERSION}`;
document.getElementById("fp-link").href = FALSE_POSITIVE_CONTACT;

const verdict = evaluate(target);
const content = VERDICT_CONTENT[verdict.status] || VERDICT_CONTENT.error;

document.getElementById("title").textContent = `${content.icon} ${content.label}`;
document.getElementById("lead").textContent = content.message;

if (verdict.status === "dangerous") {
  document.getElementById("sheet").classList.add("sheet--danger");
}

const meter = document.getElementById("meter");
if (verdict.status === "error") {
  meter.hidden = true;
} else {
  const fill = document.getElementById("meter-fill");
  fill.style.width = `${Math.max(2, verdict.score)}%`;
  // Set the colour directly: the .result--* classes also carry a panel
  // background, which would wash out the meter track.
  fill.style.background =
    verdict.status === "dangerous"
      ? "var(--danger)"
      : verdict.status === "suspicious"
        ? "var(--warn)"
        : "var(--safe)";
  document.getElementById("meter-score").textContent = verdict.score;
}

const list = document.getElementById("reasons");
(verdict.reasons || []).forEach((reason) => {
  const li = document.createElement("li");
  li.textContent = reason;
  list.appendChild(li);
});
