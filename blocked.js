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

document.getElementById("version").textContent = `logic v${DETECTION_VERSION}`;
document.getElementById("fp-link").href = FALSE_POSITIVE_CONTACT;

const verdict = evaluate(target);
const isKnownLogger = verdict.signals?.some((s) => s.id === "ipLogger");

// A hidden destination is a different claim from "this is a scam", and
// the page should not pretend otherwise: we are stopping because we
// cannot check it, not because we know it is bad.
const onlyHidden = verdict.status !== "dangerous" && verdict.hidesDestination;

if (isKnownLogger) {
  document.getElementById("sheet-title").textContent =
    "This link is a tracker";
  leadEl.textContent =
    "Opening it would have recorded your IP address, rough location, browser and device — and then forwarded you to a real site, so nothing would have looked wrong.";
  noteEl.textContent = "Nothing has been sent yet. If you continue, it records you.";
} else if (onlyHidden) {
  // Not a confirmed threat — retone the page so it does not read as one.
  document.querySelector(".sheet").classList.replace("sheet--danger", "sheet--caution");
  document.getElementById("sheet-title").textContent =
    "This link hides where it goes";
  leadEl.textContent =
    "It is a short or redirecting link, so the real destination cannot be checked from the address alone. That is also how a tracker is hidden behind an ordinary-looking link — and finding out where it leads means sending the request, which is the part that records you.";
  noteEl.textContent =
    "Nothing has been sent yet. Only continue if you trust whoever gave you this link.";
} else {
  leadEl.textContent =
    "chick-check judged this page likely to be a phishing or scam site, so the browser was stopped before it sent the request.";
  noteEl.textContent = "Nothing has been sent to this site yet.";
}

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
