// ---------------------------------------------------------------------
// blocked.js — the interstitial shown instead of a dangerous page
// ---------------------------------------------------------------------
// A warning with a way through, not a hard block: the user makes the
// final call, which is both better for autonomy and the safer position
// for us when a verdict turns out to be wrong.
//
// The blocked URL is re-evaluated here rather than passed in as text,
// so the reasons on screen always come from the current engine.
// ---------------------------------------------------------------------

import { evaluate } from "./lib/verdict.js";
import { DETECTION_VERSION, FALSE_POSITIVE_CONTACT } from "./lib/config.js";

const params = new URLSearchParams(location.search);
const target = params.get("url") || "";

const urlEl = document.getElementById("target-url");
const reasonsEl = document.getElementById("reasons");
const leadEl = document.getElementById("lead");
const noteEl = document.getElementById("note");

// Always assigned as text — never innerHTML. This string is attacker
// controlled: it is the address they wanted you to open.
urlEl.textContent = target;

document.getElementById("version").textContent = `Logic v${DETECTION_VERSION}`;
document.getElementById("fp-link").href = FALSE_POSITIVE_CONTACT;

const verdict = evaluate(target);
const isLogger = verdict.signals?.some(
  (s) => s.id === "ipLogger" || s.id === "redirectorShape"
);

leadEl.textContent = isLogger
  ? "This address is a link tracker. Opening it would have recorded your IP address, rough location, browser and device — and then forwarded you on, so nothing would have looked wrong."
  : "URL Shield judged this page likely to be a phishing or scam site, so the browser was stopped before it sent the request.";

noteEl.textContent = isLogger
  ? "Nothing has been sent yet. If you continue, the tracker records you."
  : "Nothing has been sent to this site yet.";

(verdict.reasons || []).forEach((reason) => {
  const li = document.createElement("li");
  li.textContent = reason;
  reasonsEl.appendChild(li);
});

document.getElementById("back-btn").addEventListener("click", () => {
  // history.back() would land on the page that linked here; if this is
  // the first entry there is nothing to go back to, so fall back to the
  // new-tab page rather than leaving the user stranded.
  if (history.length > 1) history.back();
  else chrome.tabs.getCurrent((tab) => tab && chrome.tabs.remove(tab.id));
});

document.getElementById("continue-btn").addEventListener("click", async () => {
  // Ask the worker to allow this URL for the rest of the session, then
  // navigate — otherwise the interstitial would immediately re-trigger.
  await chrome.runtime.sendMessage({ type: "ALLOW_ONCE", url: target });
  location.replace(target);
});
