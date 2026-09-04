// ---------------------------------------------------------------------
// script.js — popup controller
// ---------------------------------------------------------------------
// As an installed extension it asks the background worker for a verdict
// (local heuristics always; cloud checks only if the user enabled
// them). Opened as a plain file it falls back to local heuristics so
// the UI is still demonstrable.
// ---------------------------------------------------------------------

import {
  evaluate,
  VERDICT_CONTENT,
  SUSPICIOUS_AT,
  DANGEROUS_AT,
} from "./lib/verdict.js";
import { DETECTION_VERSION, FALSE_POSITIVE_CONTACT } from "./lib/config.js";

const isExtensionContext =
  typeof chrome !== "undefined" && !!chrome.runtime && !!chrome.runtime.id;

const inputEl = document.getElementById("url-input");
const checkBtn = document.getElementById("check-btn");
const resultPanel = document.getElementById("result-panel");
const resultIcon = document.getElementById("result-icon");
const resultLabel = document.getElementById("result-label");
const resultMessage = document.getElementById("result-message");
const resultReasons = document.getElementById("result-reasons");
const sourcesEl = document.getElementById("result-sources");
const chipsContainer = document.getElementById("example-chips");
const useTabBtn = document.getElementById("use-tab-btn");
const cloudOffNote = document.getElementById("cloud-off-note");
const enableCloudLink = document.getElementById("enable-cloud-link");
const modeNote = document.getElementById("mode-note");
const versionEl = document.getElementById("detection-version");
const reportFpLink = document.getElementById("report-fp-link");
const meterEl = document.getElementById("meter");
const meterFill = document.getElementById("meter-fill");
const meterScore = document.getElementById("meter-score");

versionEl.textContent = `Logic v${DETECTION_VERSION}`;

// Place the threshold ticks so the meter explains its own bands.
document.getElementById("tick-sus").style.left = `${SUSPICIOUS_AT}%`;
document.getElementById("tick-dan").style.left = `${DANGEROUS_AT}%`;

const EXAMPLE_URLS = [
  { url: "https://www.wikipedia.org", kind: "safe" },
  { url: "https://mail.google.com", kind: "safe" },
  { url: "https://instogram.com", kind: "bad" }, // one-letter misspelling
  { url: "https://micros0ft.com", kind: "bad" }, // digit for a letter
  { url: "https://xn--pple-43d.com", kind: "bad" }, // Cyrillic homograph
  { url: "https://paypal.com.secure-billing.ru", kind: "bad" }, // brand in subdomain
  { url: "http://192.168.12.44/login", kind: "bad" },
];

const SOURCE_STATE = {
  clear: { icon: "✔", text: "clear", cls: "src--clear" },
  flagged: { icon: "✖", text: "flagged", cls: "src--flagged" },
  skipped: { icon: "–", text: "not run", cls: "src--skipped" },
  error: { icon: "!", text: "unavailable", cls: "src--error" },
};

async function getVerdict(rawInput) {
  if (isExtensionContext) {
    try {
      const res = await chrome.runtime.sendMessage({ type: "CHECK_URL", url: rawInput });
      if (res) return res;
    } catch {
      /* worker asleep — fall through to local-only */
    }
  }
  return evaluate(rawInput);
}

async function runCheck(rawInput) {
  const value = (rawInput ?? inputEl.value).trim();
  if (!value) return;
  setBusy(true);
  try {
    renderResult(await getVerdict(value));
  } finally {
    setBusy(false);
  }
}

function setBusy(busy) {
  checkBtn.disabled = busy;
  checkBtn.textContent = busy ? "Checking…" : "Check";
}

function renderResult({ status, reasons, sources, cloud, score }) {
  const content = VERDICT_CONTENT[status] || VERDICT_CONTENT.error;

  resultPanel.hidden = false;
  resultPanel.className = `result result--${status}`;
  resultIcon.textContent = content.icon;
  resultLabel.textContent = content.label;
  resultMessage.textContent = content.message;

  // Risk meter
  if (status === "error") {
    meterEl.hidden = true;
  } else {
    meterEl.hidden = false;
    meterFill.style.width = `${Math.max(2, score)}%`;
    meterScore.textContent = score;
  }

  resultReasons.innerHTML = "";
  (reasons || []).forEach((reason) => {
    const li = document.createElement("li");
    li.textContent = reason;
    resultReasons.appendChild(li);
  });

  sourcesEl.innerHTML = "";
  if (Array.isArray(sources) && sources.length) {
    sources.forEach((s) => {
      const meta = SOURCE_STATE[s.state] || SOURCE_STATE.skipped;
      const row = document.createElement("li");
      row.className = `src ${meta.cls}`;
      row.innerHTML =
        `<span class="src__icon">${meta.icon}</span>` +
        `<span class="src__label"></span>` +
        `<span class="src__state">${meta.text}</span>`;
      // s.detail / s.note are registry-supplied text — assign as text,
      // never as markup.
      row.querySelector(".src__label").textContent = s.detail
        ? `${s.label} — ${s.detail}`
        : s.label;
      if (s.note) row.title = s.note;
      sourcesEl.appendChild(row);
    });
    sourcesEl.hidden = false;
  } else {
    sourcesEl.hidden = true;
  }

  reportFpLink.hidden = !isExtensionContext || status === "error";

  // Nudge to enable online checks, unless they're already on.
  cloudOffNote.hidden = !isExtensionContext || status === "error" || cloud === true;
}

// Example chips
EXAMPLE_URLS.forEach(({ url, kind }) => {
  const chip = document.createElement("button");
  chip.type = "button";
  chip.className = `chip chip--${kind}`;
  chip.textContent = url;
  chip.addEventListener("click", () => {
    inputEl.value = url;
    runCheck(url);
  });
  chipsContainer.appendChild(chip);
});

checkBtn.addEventListener("click", () => runCheck());
inputEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") runCheck();
});

if (isExtensionContext) {
  useTabBtn.hidden = false;
  useTabBtn.addEventListener("click", checkActiveTab);

  reportFpLink.href = FALSE_POSITIVE_CONTACT;

  enableCloudLink.addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });

  checkActiveTab();
} else {
  modeNote.hidden = false;
  modeNote.textContent = "Offline preview — install as an extension for the full checks.";
}

async function checkActiveTab() {
  try {
    // activeTab: granted for the current tab while the popup is open,
    // no broad "tabs" permission needed.
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && /^https?:\/\//i.test(tab.url)) {
      inputEl.value = tab.url;
      runCheck(tab.url);
    }
  } catch {
    /* no access */
  }
}
