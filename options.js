// ---------------------------------------------------------------------
// options.js — save / test the Google Safe Browsing API key
// ---------------------------------------------------------------------

const keyInput = document.getElementById("api-key");
const toggleKeyBtn = document.getElementById("toggle-key");
const saveBtn = document.getElementById("save-btn");
const testBtn = document.getElementById("test-btn");
const statusEl = document.getElementById("status");

const STORAGE_KEY = "safeBrowsingApiKey";

function setStatus(text, kind = "") {
  statusEl.textContent = text;
  statusEl.className = `options__status ${kind ? "options__status--" + kind : ""}`;
}

// Load any saved key.
chrome.storage.sync.get(STORAGE_KEY).then(({ [STORAGE_KEY]: saved }) => {
  if (saved) {
    keyInput.value = saved;
    setStatus("A key is saved.", "ok");
  }
});

toggleKeyBtn.addEventListener("click", () => {
  keyInput.type = keyInput.type === "password" ? "text" : "password";
});

saveBtn.addEventListener("click", async () => {
  const key = keyInput.value.trim();
  await chrome.storage.sync.set({ [STORAGE_KEY]: key });
  setStatus(key ? "Saved." : "Key cleared — falling back to DNS + heuristics only.", "ok");
});

testBtn.addEventListener("click", async () => {
  const key = keyInput.value.trim();
  if (!key) {
    setStatus("Enter a key first.", "err");
    return;
  }
  setStatus("Testing…");
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "url-shield", clientVersion: "2.0.0" },
          threatInfo: {
            threatTypes: ["SOCIAL_ENGINEERING"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: "http://testsafebrowsing.appspot.com/s/phishing.html" }],
          },
        }),
      }
    );
    if (res.ok) {
      const data = await res.json();
      const hit = Array.isArray(data.matches) && data.matches.length > 0;
      setStatus(
        hit
          ? "Key works — Google's test phishing URL was correctly flagged."
          : "Key accepted, but the test URL wasn't flagged (Google may have retired it).",
        "ok"
      );
    } else if (res.status === 400 || res.status === 403) {
      setStatus("Rejected — check the key is valid and the Safe Browsing API is enabled.", "err");
    } else {
      setStatus(`Unexpected response: HTTP ${res.status}.`, "err");
    }
  } catch {
    setStatus("Could not reach the Safe Browsing server.", "err");
  }
});
