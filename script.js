// ---------------------------------------------------------------------
// script.js — popup controller
// ---------------------------------------------------------------------
// Running as an installed extension, this asks the background service
// worker for a full verdict (offline heuristics + Google Safe Browsing
// + DNS blocklist) and checks the current tab automatically on open.
//
// Opened as a plain file (no `chrome` APIs), it falls back to the
// offline heuristics only, so the UI is still demonstrable.
// ---------------------------------------------------------------------

import { evaluate, VERDICT_CONTENT } from "./lib/verdict.js";

const isExtensionContext =
  typeof chrome !== "undefined" && !!chrome.runtime && !!chrome.runtime.id;

// --- DOM ---------------------------------------------------------------
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
const optionsLink = document.getElementById("options-link");
const modeNote = document.getElementById("mode-note");

const EXAMPLE_URLS = [
  { url: "https://www.wikipedia.org", kind: "safe" },
  { url: "https://github.com", kind: "safe" },
  { url: "http://192.168.12.44/login", kind: "bad" },
  { url: "http://paypa1-login.com", kind: "bad" },
  { url: "http://secure-appleid.top", kind: "bad" },
];

const SOURCE_STATE = {
  clear: { icon: "✔", text: "clear", cls: "src--clear" },
  flagged: { icon: "✖", text: "flagged", cls: "src--flagged" },
  skipped: { icon: "–", text: "not run", cls: "src--skipped" },
  error: { icon: "!", text: "unavailable", cls: "src--error" },
};

// --- Verdict retrieval ----------------------------------------------
async function getVerdict(rawInput) {
  if (isExtensionContext) {
    try {
      const res = await chrome.runtime.sendMessage({ type: "CHECK_URL", url: rawInput });
      if (res) return res;
    } catch {
      /* service worker asleep or messaging failed — fall through */
    }
  }
  return evaluate(rawInput); // offline-only fallback
}

async function runCheck(rawInput) {
  const value = (rawInput ?? inputEl.value).trim();
  if (!value) return;

  setBusy(true);
  try {
    const verdict = await getVerdict(value);
    renderResult(verdict);
  } finally {
    setBusy(false);
  }
}

function setBusy(busy) {
  checkBtn.disabled = busy;
  checkBtn.textContent = busy ? "Checking…" : "Check";
}

// --- Rendering -----------------------------------------------------
function renderResult({ status, reasons, sources }) {
  const content = VERDICT_CONTENT[status] || VERDICT_CONTENT.error;

  resultPanel.hidden = false;
  resultPanel.className = `result result--${status}`;
  resultIcon.textContent = content.icon;
  resultLabel.textContent = content.label;
  resultMessage.textContent = content.message;

  // Reasons
  resultReasons.innerHTML = "";
  (reasons || []).forEach((reason) => {
    const li = document.createElement("li");
    li.textContent = reason;
    resultReasons.appendChild(li);
  });

  // Per-source breakdown
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
      row.querySelector(".src__label").textContent = s.label;
      if (s.note) row.title = s.note;
      sourcesEl.appendChild(row);
    });
    sourcesEl.hidden = false;
  } else {
    sourcesEl.hidden = true;
  }
}

// --- Example chips -----------------------------------------------
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

// --- Wiring -----------------------------------------------------
checkBtn.addEventListener("click", () => runCheck());
inputEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") runCheck();
});

if (isExtensionContext) {
  // "Check this tab" button + auto-check on open
  useTabBtn.hidden = false;
  useTabBtn.addEventListener("click", checkActiveTab);

  if (optionsLink) {
    optionsLink.hidden = false;
    optionsLink.addEventListener("click", (e) => {
      e.preventDefault();
      chrome.runtime.openOptionsPage();
    });
  }

  checkActiveTab();
} else {
  modeNote.hidden = false;
  modeNote.textContent =
    "Offline preview — install as an extension for live Safe Browsing + DNS checks.";
}

async function checkActiveTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && /^https?:\/\//i.test(tab.url)) {
      inputEl.value = tab.url;
      runCheck(tab.url);
    }
  } catch {
    /* no tab access */
  }
}
