// ---------------------------------------------------------------------
// options.js — consent surface for the optional cloud features
// ---------------------------------------------------------------------
// Each toggle:
//   • requests the matching optional permission at runtime,
//   • stores the setting (and a consent timestamp) only on success,
//   • is fully reversible ("withdraw" button revokes permissions too).
// ---------------------------------------------------------------------

import {
  getSettings,
  setSettings,
  DEFAULT_SETTINGS,
  CLOUD_HOSTS,
} from "./lib/config.js";

const sbToggle = document.getElementById("sb-toggle");
const dnsToggle = document.getElementById("dns-toggle");
const ageToggle = document.getElementById("age-toggle");
const autoToggle = document.getElementById("auto-toggle");
const apiKeyInput = document.getElementById("api-key");
const toggleKeyBtn = document.getElementById("toggle-key");
const saveKeyBtn = document.getElementById("save-key");
const testKeyBtn = document.getElementById("test-key");
const withdrawBtn = document.getElementById("withdraw");

const sbStatus = document.getElementById("sb-status");
const dnsStatus = document.getElementById("dns-status");
const ageStatus = document.getElementById("age-status");
const autoStatus = document.getElementById("auto-status");

function status(el, text, kind = "") {
  el.textContent = text;
  el.className = `options__status ${kind ? "options__status--" + kind : ""}`;
}

// --- Load current state ------------------------------------------
async function refresh() {
  const s = await getSettings();
  sbToggle.checked = s.safeBrowsingEnabled;
  dnsToggle.checked = s.dnsCheckEnabled;
  ageToggle.checked = s.domainAgeEnabled;
  autoToggle.checked = s.autoScanEnabled;
  apiKeyInput.value = s.safeBrowsingApiKey || "";

  status(
    sbStatus,
    s.safeBrowsingEnabled
      ? s.safeBrowsingApiKey
        ? "On."
        : "On, but no API key saved yet."
      : "Off.",
    s.safeBrowsingEnabled && !s.safeBrowsingApiKey ? "err" : ""
  );
  status(dnsStatus, s.dnsCheckEnabled ? "On." : "Off.");
  status(ageStatus, s.domainAgeEnabled ? "On." : "Off.");
  status(autoStatus, s.autoScanEnabled ? "On." : "Off.");
}
refresh();

// --- Safe Browsing toggle --------------------------------------
sbToggle.addEventListener("change", async () => {
  if (sbToggle.checked) {
    const granted = await chrome.permissions.request({
      origins: [CLOUD_HOSTS.safeBrowsing],
    });
    if (!granted) {
      sbToggle.checked = false;
      status(sbStatus, "Permission denied — check not enabled.", "err");
      return;
    }
    await setSettings({ safeBrowsingEnabled: true, cloudConsentAt: Date.now() });
    status(sbStatus, apiKeyInput.value.trim() ? "On." : "On — now add an API key.", "ok");
  } else {
    await setSettings({ safeBrowsingEnabled: false });
    await maybeRevoke();
    status(sbStatus, "Off.", "");
  }
});

// --- DNS toggle ---------------------------------------------
dnsToggle.addEventListener("change", async () => {
  if (dnsToggle.checked) {
    const granted = await chrome.permissions.request({ origins: CLOUD_HOSTS.dns });
    if (!granted) {
      dnsToggle.checked = false;
      status(dnsStatus, "Permission denied — check not enabled.", "err");
      return;
    }
    await setSettings({ dnsCheckEnabled: true, cloudConsentAt: Date.now() });
    status(dnsStatus, "On.", "ok");
  } else {
    await setSettings({ dnsCheckEnabled: false });
    await maybeRevoke();
    status(dnsStatus, "Off.", "");
  }
});

// --- Domain age toggle ------------------------------------
ageToggle.addEventListener("change", async () => {
  if (ageToggle.checked) {
    const granted = await chrome.permissions.request({ origins: CLOUD_HOSTS.rdap });
    if (!granted) {
      ageToggle.checked = false;
      status(ageStatus, "Permission denied — check not enabled.", "err");
      return;
    }
    await setSettings({ domainAgeEnabled: true, cloudConsentAt: Date.now() });
    status(ageStatus, "On.", "ok");
  } else {
    await setSettings({ domainAgeEnabled: false });
    await maybeRevoke();
    status(ageStatus, "Off.", "");
  }
});

// --- Auto-scan toggle -------------------------------------
autoToggle.addEventListener("change", async () => {
  if (autoToggle.checked) {
    const granted = await chrome.permissions.request({ permissions: ["tabs"] });
    if (!granted) {
      autoToggle.checked = false;
      status(autoStatus, "Permission denied — still scan-on-demand.", "err");
      return;
    }
    await setSettings({ autoScanEnabled: true });
    status(autoStatus, "On.", "ok");
  } else {
    await setSettings({ autoScanEnabled: false });
    await chrome.permissions.remove({ permissions: ["tabs"] }).catch(() => {});
    status(autoStatus, "Off.", "");
  }
});

// --- API key -------------------------------------------
toggleKeyBtn.addEventListener("click", () => {
  apiKeyInput.type = apiKeyInput.type === "password" ? "text" : "password";
});

saveKeyBtn.addEventListener("click", async () => {
  await setSettings({ safeBrowsingApiKey: apiKeyInput.value.trim() });
  status(sbStatus, apiKeyInput.value.trim() ? "Key saved." : "Key cleared.", "ok");
});

testKeyBtn.addEventListener("click", async () => {
  const key = apiKeyInput.value.trim();
  if (!key) return status(sbStatus, "Enter a key first.", "err");
  const hasPerm = await chrome.permissions.contains({ origins: [CLOUD_HOSTS.safeBrowsing] });
  if (!hasPerm) return status(sbStatus, "Enable the check first (grants network access).", "err");

  status(sbStatus, "Testing…");
  try {
    // Sends one arbitrary 4-byte prefix. A 200 response (even an empty
    // one) proves the key is valid and the API is enabled.
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/fullHashes:find?key=${encodeURIComponent(key)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "url-shield", clientVersion: "3.0.0" },
          clientStates: [],
          threatInfo: {
            threatTypes: ["SOCIAL_ENGINEERING", "MALWARE"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ hash: "rBmn9A==" }],
          },
        }),
      }
    );
    if (res.ok) {
      status(sbStatus, "Key works — Safe Browsing responded.", "ok");
    } else if (res.status === 400 || res.status === 403) {
      status(sbStatus, "Rejected — key invalid or API not enabled.", "err");
    } else {
      status(sbStatus, `Unexpected response: HTTP ${res.status}.`, "err");
    }
  } catch {
    status(sbStatus, "Could not reach the Safe Browsing server.", "err");
  }
});

// --- Withdraw everything --------------------------------
withdrawBtn.addEventListener("click", async () => {
  await setSettings({
    ...DEFAULT_SETTINGS,
    safeBrowsingApiKey: apiKeyInput.value.trim(), // keep the key on file, unused
  });
  await chrome.permissions.remove({
    permissions: ["tabs"],
    origins: [CLOUD_HOSTS.safeBrowsing, ...CLOUD_HOSTS.dns, ...CLOUD_HOSTS.rdap],
  }).catch(() => {});
  await refresh();
  status(sbStatus, "All cloud features off. Local checks still active.", "ok");
});

// Revoke host permissions once no cloud check needs them.
async function maybeRevoke() {
  const s = await getSettings();
  const origins = [];
  if (!s.safeBrowsingEnabled) origins.push(CLOUD_HOSTS.safeBrowsing);
  if (!s.dnsCheckEnabled) origins.push(...CLOUD_HOSTS.dns);
  if (!s.domainAgeEnabled) origins.push(...CLOUD_HOSTS.rdap);
  if (origins.length) {
    await chrome.permissions.remove({ origins }).catch(() => {});
  }
}
