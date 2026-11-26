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
  onSettingsChanged,
  DEFAULT_SETTINGS,
  BLOCKING_PERMISSIONS,
  CLOUD_HOSTS,
  EXTENSION_VERSION,
} from "./lib/config.js";
import { api } from "./lib/browser.js";
import {
  loadExclusions,
  addExclusion,
  removeExclusion,
  clearExclusions,
  setExclusionSync,
  onExclusionsChanged,
  validateEntry,
  normalizeHost,
  MAX_EXCLUSIONS,
} from "./lib/exclusions.js";
import { evaluate } from "./lib/verdict.js";
import { toUnicode } from "./lib/punycode.js";

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
const permCard = document.getElementById("perm-card");
const permList = document.getElementById("perm-list");
const permThose = document.getElementById("perm-those");
const permGrantBtn = document.getElementById("perm-grant");
const permStatus = document.getElementById("perm-status");

function status(el, text, kind = "") {
  el.textContent = text;
  el.className = `options__status ${kind ? "options__status--" + kind : ""}`;
}

// --- Load current state ------------------------------------------
async function refresh() {
  const s = await getSettings();
  refreshPermissions(s);
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

  // Blocking depends on a permission that can be revoked from the
  // browser's own settings, so trust the permission, not just the
  // stored flag.
  const canBlock = await api.permissions.contains(BLOCKING_PERMISSIONS);
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

// --- Lookup permissions the user has taken back -----------------
// The lookup hosts are granted at install, but Firefox (about:addons)
// and Chrome/Edge (Site access) both let the user switch them off
// later. The lookups then report "not run"; this says why, and offers
// to grant them again.
const SERVICES = [
  { setting: "safeBrowsingEnabled", name: "Google Safe Browsing", origins: [CLOUD_HOSTS.safeBrowsing] },
  { setting: "dnsCheckEnabled", name: "the DNS resolvers", origins: CLOUD_HOSTS.dns },
  { setting: "domainAgeEnabled", name: "the domain registries", origins: CLOUD_HOSTS.rdap },
];

// Kept up to date so the click handler can use it without awaiting.
let missingOrigins = [];

async function refreshPermissions(settings) {
  const s = settings || (await getSettings());
  const missing = [];
  const names = [];
  for (const service of SERVICES) {
    if (!s[service.setting]) continue; // off anyway, so nothing is lost
    // One origin at a time, so a single revoked registry still shows up.
    const lacking = [];
    for (const origin of service.origins) {
      const has = await api.permissions.contains({ origins: [origin] }).catch(() => true);
      if (!has) lacking.push(origin);
    }
    if (lacking.length) {
      missing.push(...lacking);
      names.push(service.name);
    }
  }
  missingOrigins = missing;
  permCard.hidden = missing.length === 0;
  permList.textContent = names.join(" and ").replace(/ and (?=.* and )/g, ", ");
  permThose.textContent = names.length === 1 ? "that check is" : "those checks are";
}

permGrantBtn.addEventListener("click", () => {
  // request() must be the first thing this click does. Browsers only
  // show a permission prompt in direct response to a user action, and
  // Firefox no longer counts it as one after an await.
  api.permissions
    .request({ origins: missingOrigins })
    .then((granted) => {
      status(
        permStatus,
        granted ? "Granted — the lookups will run again." : "Not granted — those lookups stay off.",
        granted ? "ok" : "err"
      );
      return refreshPermissions();
    })
    .catch(() => status(permStatus, "The browser refused the request.", "err"));
});

api.permissions.onAdded.addListener(() => refreshPermissions());
api.permissions.onRemoved.addListener(() => refreshPermissions());
// A lookup switched on or off changes which permissions matter.
onSettingsChanged(() => refreshPermissions());

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
// This one does need a permission, and the browser only grants it from
// a user gesture — which is why it cannot be on out of the box.
blockToggle.addEventListener("change", async () => {
  if (blockToggle.checked) {
    const granted = await api.permissions.request(BLOCKING_PERMISSIONS);
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
    await api.permissions.remove(BLOCKING_PERMISSIONS).catch(() => {});
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
          client: { clientId: "chick-check", clientVersion: EXTENSION_VERSION },
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

// --- Sites you don't want scanned -------------------------
const exclInput = document.getElementById("excl-input");
const exclMode = document.getElementById("excl-mode");
const exclAdd = document.getElementById("excl-add");
const exclWarn = document.getElementById("excl-warn");
const exclWarnActions = document.getElementById("excl-warn-actions");
const exclAddAnyway = document.getElementById("excl-add-anyway");
const exclAddCancel = document.getElementById("excl-add-cancel");
const exclStatus = document.getElementById("excl-status");
const exclList = document.getElementById("excl-list");
const exclCount = document.getElementById("excl-count");
const exclClear = document.getElementById("excl-clear");
const exclSync = document.getElementById("excl-sync");

async function renderExclusions() {
  const list = await loadExclusions();
  const rows = [...list.entries()]
    .map(([host, entry]) => ({ host, shown: toUnicode(host), ...entry }))
    .sort((a, b) => a.shown.localeCompare(b.shown));

  exclList.replaceChildren(
    ...rows.map(({ host, shown, m, t }) => {
      const li = document.createElement("li");
      const name = document.createElement("span");
      name.className = "excl-list__host";
      name.textContent = shown;
      if (shown !== host) name.title = host; // show the real (punycode) name too
      const meta = document.createElement("span");
      meta.className = "excl-list__meta";
      meta.textContent =
        (m === "domain" ? "and subdomains" : "exact address") +
        (t ? ` · added ${new Date(t).toLocaleDateString()}` : "");
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "ghost-btn";
      remove.textContent = "Remove";
      remove.addEventListener("click", async () => {
        await removeExclusion(host);
        status(exclStatus, `Removed ${shown} — it is scanned again.`, "ok");
      });
      li.append(name, meta, remove);
      return li;
    })
  );

  exclCount.textContent = `${rows.length} of ${MAX_EXCLUSIONS} sites`;
  exclClear.disabled = rows.length === 0;
  exclSync.checked = (await getSettings()).syncExclusions !== false;
}
renderExclusions();
onExclusionsChanged(renderExclusions);

function resetExclusionForm() {
  exclWarn.hidden = true;
  exclWarnActions.hidden = true;
}

// The site's current local verdict, so a dangerous site gets a warning.
function currentStatus(input) {
  const host = normalizeHost(input);
  return host ? evaluate("https://" + host + "/").status : undefined;
}

async function saveExclusion() {
  const input = exclInput.value;
  const result = await addExclusion(input, exclMode.value, { status: currentStatus(input) });
  resetExclusionForm();
  if (!result.ok) return status(exclStatus, result.error, "err");
  exclInput.value = "";
  status(exclStatus, `Added ${toUnicode(result.host)} (${result.mode === "domain" ? "and its subdomains" : "exact address only"}).`, "ok");
}

function tryAddExclusion() {
  resetExclusionForm();
  const input = exclInput.value;
  const check = validateEntry(input, exclMode.value, { status: currentStatus(input) });
  if (!check.ok) return status(exclStatus, check.error, "err");
  if (check.warning) {
    // Risky: say why and let the user decide.
    exclWarn.textContent = check.warning;
    exclWarn.hidden = false;
    exclWarnActions.hidden = false;
    status(exclStatus, "");
    return;
  }
  saveExclusion();
}

exclAdd.addEventListener("click", tryAddExclusion);
exclInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") tryAddExclusion();
});
exclInput.addEventListener("input", resetExclusionForm);
exclAddAnyway.addEventListener("click", saveExclusion);
exclAddCancel.addEventListener("click", () => {
  resetExclusionForm();
  status(exclStatus, "");
});

// Two clicks, so the whole list is not lost to one slip.
let clearArmed = null;
exclClear.addEventListener("click", async () => {
  if (!clearArmed) {
    exclClear.textContent = "Click again to remove all";
    clearArmed = setTimeout(() => {
      clearArmed = null;
      exclClear.textContent = "Remove all";
    }, 4000);
    return;
  }
  clearTimeout(clearArmed);
  clearArmed = null;
  exclClear.textContent = "Remove all";
  await clearExclusions();
  status(exclStatus, "List cleared — every site is scanned again.", "ok");
});

exclSync.addEventListener("change", async () => {
  try {
    await setExclusionSync(exclSync.checked);
    status(
      exclStatus,
      exclSync.checked
        ? "The list now syncs with your browser account."
        : "The list is now kept in this browser only.",
      "ok"
    );
  } catch {
    exclSync.checked = !exclSync.checked;
    status(exclStatus, "The browser didn't move the list. Try again.", "err");
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
  await api.permissions.remove(BLOCKING_PERMISSIONS).catch(() => {});
  await refresh();
  status(
    sbStatus,
    "All network features off — nothing leaves your device. Local checks still active.",
    "ok"
  );
});
