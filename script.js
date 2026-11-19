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
import { api } from "./lib/browser.js";
import {
  loadExclusions,
  matchingEntry,
  normalizeHost,
  validateEntry,
  addExclusion,
  removeExclusion,
} from "./lib/exclusions.js";
import { registrableDomain } from "./lib/heuristics.js";
import { toUnicode } from "./lib/punycode.js";

const isExtensionContext = !!api?.runtime?.id;

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
  ? api.runtime.getManifest().version
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
      const res = await api.runtime.sendMessage({ type: "CHECK_URL", url: rawInput });
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
    const verdict = await getVerdict(value);
    renderResult(verdict);
    await renderExclusion(verdict);
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

// --- Pause / resume automatic scanning for a site ---------------
// Talks to lib/exclusions.js directly; the background notices the
// storage change and updates badges itself.
const exclPanel = document.getElementById("excl-panel");
const exclPaused = document.getElementById("excl-paused");
const exclResume = document.getElementById("excl-resume");
const exclStart = document.getElementById("excl-start");
const exclForm = document.getElementById("excl-form");
const exclDomainLabel = document.getElementById("excl-domain-label");
const exclHostOpt = document.getElementById("excl-host-opt");
const exclHostLabel = document.getElementById("excl-host-label");
const exclWarn = document.getElementById("excl-warn");
const exclConfirm = document.getElementById("excl-confirm");
const exclCancel = document.getElementById("excl-cancel");
const exclMsg = document.getElementById("excl-msg");
const modeInputs = [...document.querySelectorAll('input[name="excl-mode"]')];

// What the panel is about: { url, status, hosts: { domain, host }, entry }
let exclTarget = null;

const show = (host) => toUnicode(host);
const scopeText = (host, mode) =>
  mode === "domain" ? `${show(host)} and its subdomains` : `only ${show(host)}`;

// The whole-domain choice covers the registrable domain (example.com
// for mail.example.com) — unless that is a shared suffix such as
// github.io, where it falls back to the site's own host.
function scopeHosts(host) {
  // An IP address has no domain above it.
  if (validateEntry(host, "domain").mode === "host") return { domain: host, host };
  const registrable = registrableDomain(host);
  const domain = validateEntry(registrable, "domain").ok ? registrable : host;
  return { domain, host };
}

async function renderExclusion(verdict) {
  exclPanel.hidden = true;
  exclForm.hidden = true;
  exclMsg.textContent = "";
  exclTarget = null;
  if (!isExtensionContext || verdict.status === "error" || !verdict.href) return;
  const host = normalizeHost(verdict.href);
  if (!host) return;

  const entry = matchingEntry(verdict.href, await loadExclusions());
  exclTarget = { url: verdict.href, status: verdict.status, hosts: scopeHosts(host), entry };
  exclPanel.hidden = false;

  exclPaused.hidden = !entry;
  exclResume.hidden = !entry;
  exclStart.hidden = !!entry;
  if (entry) {
    exclPaused.textContent =
      `This site is on your exclusion list — automatic scanning is paused for ` +
      `${scopeText(entry.host, entry.m)}. Checked now because you asked.`;
  }
}

function selectedMode() {
  return modeInputs.find((i) => i.checked)?.value || "domain";
}

// Re-run the rules for the chosen scope: errors block, warnings ask.
function updateExclusionCheck() {
  const mode = selectedMode();
  const check = validateEntry(exclTarget.hosts[mode], mode, { status: exclTarget.status });
  exclWarn.hidden = !(check.error || check.warning);
  exclWarn.textContent = check.error || check.warning || "";
  exclConfirm.disabled = !check.ok;
  exclConfirm.textContent = check.warning ? "Exclude anyway" : "Stop scanning";
  exclConfirm.classList.toggle("excl__btn--risky", Boolean(check.warning));
}

exclStart.addEventListener("click", () => {
  if (!exclTarget) return;
  const { domain, host } = exclTarget.hosts;
  const ip = validateEntry(host, "domain").mode === "host";
  exclDomainLabel.textContent = scopeText(domain, "domain");
  exclHostLabel.textContent = `only this exact address (${show(host)})`;
  // Two choices only when they differ; an IP address has no subdomains.
  modeInputs[0].closest("label").hidden = ip;
  exclHostOpt.hidden = !ip && domain === host;
  modeInputs.find((i) => i.value === (ip ? "host" : "domain")).checked = true;
  exclStart.hidden = true;
  exclForm.hidden = false;
  updateExclusionCheck();
});

modeInputs.forEach((i) => i.addEventListener("change", updateExclusionCheck));

exclCancel.addEventListener("click", () => {
  exclForm.hidden = true;
  exclStart.hidden = false;
});

exclConfirm.addEventListener("click", async () => {
  const mode = selectedMode();
  const result = await addExclusion(exclTarget.hosts[mode], mode, { status: exclTarget.status });
  if (!result.ok) {
    exclWarn.hidden = false;
    exclWarn.textContent = result.error;
    return;
  }
  const { url, status } = exclTarget;
  await renderExclusion({ href: url, status });
  exclMsg.textContent = "Scanning paused. Manage the list in Settings.";
});

exclResume.addEventListener("click", async () => {
  if (!exclTarget?.entry) return;
  await removeExclusion(exclTarget.entry.host);
  const { url, status } = exclTarget;
  await renderExclusion({ href: url, status });
  exclMsg.textContent = "Scanning resumed for this site.";
});

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
    api.runtime.openOptionsPage();
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
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && /^https?:\/\//i.test(tab.url)) {
      inputEl.value = tab.url;
      runCheck(tab.url);
    }
  } catch {
    /* no access */
  }
}
