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
  BLOCKING_PERMISSIONS,
} from "./lib/config.js";

const sbToggle = document.getElementById("sb-toggle");
const dnsToggle = document.getElementById("dns-toggle");
const ageToggle = document.getElementById("age-toggle");
const blockToggle = document.getElementById("block-toggle");
const hiddenToggle = document.getElementById("hidden-toggle");
const autoToggle = document.getElementById("auto-toggle");
const apiKeyInput = document.getElementById("api-key");
const toggleKeyBtn = document.getElementById("toggle-key");
const saveKeyBtn = document.getElementById("save-key");
const testKeyBtn = document.getElementById("test-key");
const withdrawBtn = document.getElementById("withdraw");

const sbStatus = document.getElementById("sb-status");
const dnsStatus = document.getElementById("dns-status");
const ageStatus = document.getElementById("age-status");
const blockStatus = document.getElementById("block-status");
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

  // Blocking depends on a permission that can be revoked from Chrome's
  // own settings, so trust the permission, not just the stored flag.
  const canBlock = await chrome.permissions.contains(BLOCKING_PERMISSIONS);
  blockToggle.checked = s.blockingEnabled && canBlock;
  hiddenToggle.checked = s.blockHiddenDestinations;
  hiddenToggle.disabled = !blockToggle.checked;
  status(
    blockStatus,
    s.blockingEnabled && !canBlock
      ? "Off — the required permission was revoked. Switch it on again to re-grant."
      : blockToggle.checked
        ? "On — dangerous pages are stopped before loading."
        : "Off.",
    s.blockingEnabled && !canBlock ? "err" : ""
  );
}
refresh();

// The three lookup hosts are granted at install, so these toggles only
// flip a setting — there is no permission round-trip to fail.
function simpleToggle(input, key, statusEl, onLabel = "On.") {
  input.addEventListener("change", async () => {
    await setSettings({ [key]: input.checked, cloudConsentAt: Date.now() });
    status(statusEl, input.checked ? onLabel : "Off.", input.checked ? "ok" : "");
  });
}

sbToggle.addEventListener("change", async () => {
  await setSettings({ safeBrowsingEnabled: sbToggle.checked, cloudConsentAt: Date.now() });
  if (!sbToggle.checked) return status(sbStatus, "Off.", "");
  status(
    sbStatus,
    apiKeyInput.value.trim() ? "On." : "On, but no API key saved yet.",
    apiKeyInput.value.trim() ? "ok" : "err"
  );
});

simpleToggle(dnsToggle, "dnsCheckEnabled", dnsStatus);
simpleToggle(ageToggle, "domainAgeEnabled", ageStatus);
simpleToggle(autoToggle, "autoScanEnabled", autoStatus);

// --- Blocking toggle --------------------------------------
// This one does need a permission, and Chrome only grants it from a
// user gesture — which is why it cannot be on out of the box.
blockToggle.addEventListener("change", async () => {
  if (blockToggle.checked) {
    const granted = await chrome.permissions.request(BLOCKING_PERMISSIONS);
    if (!granted) {
      blockToggle.checked = false;
      status(blockStatus, "Permission denied — pages will not be blocked.", "err");
      return;
    }
    await setSettings({ blockingEnabled: true });
    hiddenToggle.disabled = false;
    status(blockStatus, "On — dangerous pages will be stopped before loading.", "ok");
  } else {
    await setSettings({ blockingEnabled: false });
    await chrome.permissions.remove(BLOCKING_PERMISSIONS).catch(() => {});
    hiddenToggle.disabled = true;
    status(blockStatus, "Off.", "");
  }
});

hiddenToggle.addEventListener("change", async () => {
  await setSettings({ blockHiddenDestinations: hiddenToggle.checked });
  status(
    blockStatus,
    hiddenToggle.checked
      ? "On — short and redirecting links will be stopped too."
      : "On — only pages judged dangerous will be stopped.",
    "ok"
  );
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

// --- Turn every network feature off ---------------------
// The lookup hosts are install-time permissions now and cannot be
// revoked without uninstalling, so this switches off the settings that
// decide whether anything is ever sent to them, and gives back the one
// permission that can be handed back.
withdrawBtn.addEventListener("click", async () => {
  await setSettings({
    safeBrowsingEnabled: false,
    dnsCheckEnabled: false,
    domainAgeEnabled: false,
    blockingEnabled: false,
    blockHiddenDestinations: DEFAULT_SETTINGS.blockHiddenDestinations,
    autoScanEnabled: false,
    safeBrowsingApiKey: apiKeyInput.value.trim(), // kept on file, unused
    cloudConsentAt: Date.now(),
  });
  await chrome.permissions.remove(BLOCKING_PERMISSIONS).catch(() => {});
  await refresh();
  status(
    sbStatus,
    "All network features off — nothing leaves your device. Local checks still active.",
    "ok"
  );
});
