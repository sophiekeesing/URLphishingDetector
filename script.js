// ---------------------------------------------------------------------
// script.js — popup controller
// ---------------------------------------------------------------------
// As an installed extension it asks the background worker for a verdict
// (local engine always; network lookups if they are switched on).
// Opened as a plain file it falls back to the local engine so the UI is
// still demonstrable.
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
const cloudOffNote = document.getElementById("cloud-off-note");
const enableCloudLink = document.getElementById("enable-cloud-link");
const modeNote = document.getElementById("mode-note");
const versionEl = document.getElementById("detection-version");
const reportFpLink = document.getElementById("report-fp-link");
const meterEl = document.getElementById("meter");
const meterFill = document.getElementById("meter-fill");
const meterScore = document.getElementById("meter-score");

const version = isExtensionContext
  ? chrome.runtime.getManifest().version
  : DETECTION_VERSION;
versionEl.textContent = `v ${version}`;

// Place the threshold ticks so the meter explains its own bands.
document.getElementById("tick-sus").style.left = `${SUSPICIOUS_AT}%`;
document.getElementById("tick-dan").style.left = `${DANGEROUS_AT}%`;

const SOURCE_STATE = {
  clear: { icon: "✔", text: "clear", cls: "src--clear" },
  flagged: { icon: "✖", text: "flagged", cls: "src--flagged" },
  skipped: { icon: "–", text: "not run", cls: "src--skipped" },
  error: { icon: "!", text: "unavailable", cls: "src--error" },
};

// The URL the panel currently describes, so the button can offer
// "Re-check" for it and switch back to "Check" the moment the user
// types something else.
let shownUrl = null;

function setButtonMode() {
  const typed = inputEl.value.trim();
  const isRecheck = shownUrl !== null && typed === shownUrl;
  checkBtn.textContent = isRecheck ? "Re-check this URL" : "Check";
  checkBtn.classList.toggle("btn--ghost", isRecheck);
  checkBtn.classList.toggle("btn--primary", !isRecheck);
}

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

  checkBtn.disabled = true;
  checkBtn.textContent = "Checking…";
  try {
    renderResult(await getVerdict(value));
    shownUrl = value;
  } finally {
    checkBtn.disabled = false;
    setButtonMode();
  }
}

function renderResult({ status, reasons, sources, cloud, score }) {
  const content = VERDICT_CONTENT[status] || VERDICT_CONTENT.error;

  resultPanel.hidden = false;
  resultPanel.className = `result result--${status}`;
  resultIcon.textContent = content.icon;
  resultLabel.textContent = content.label;
  resultMessage.textContent = content.message;

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
      // Registry- and server-supplied text: assign as text, never markup.
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
  cloudOffNote.hidden = !isExtensionContext || status === "error" || cloud === true;
}

checkBtn.addEventListener("click", () => runCheck());
inputEl.addEventListener("input", setButtonMode);
inputEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") runCheck();
});

document.getElementById("close-btn").addEventListener("click", () => window.close());

document.getElementById("about-btn").addEventListener("click", () => {
  modeNote.hidden = !modeNote.hidden;
  modeNote.textContent =
    `chick-check v${version} · detection logic v${DETECTION_VERSION}. ` +
    "Checks happen on your device first; online lookups send only a hashed " +
    "fragment, a hostname, or a domain name — never the full address.";
});

if (isExtensionContext) {
  reportFpLink.href = FALSE_POSITIVE_CONTACT;

  const openOptions = (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  };
  document.getElementById("settings-btn").addEventListener("click", openOptions);
  enableCloudLink.addEventListener("click", openOptions);

  checkActiveTab();
} else {
  document.getElementById("settings-btn").hidden = true;
  modeNote.hidden = false;
  modeNote.textContent =
    "Offline preview — install as an extension for the full checks.";
}

async function checkActiveTab() {
  try {
    // activeTab: granted for the current tab while the popup is open,
    // so no broad "tabs" access is needed just to read this one URL.
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && /^https?:\/\//i.test(tab.url)) {
      inputEl.value = tab.url;
      runCheck(tab.url);
    }
  } catch {
    /* no access */
  }
}
