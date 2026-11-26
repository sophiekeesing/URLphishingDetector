// Unit tests for reputation request minimization. All network calls are mocked.

import { test } from "node:test";
import assert from "node:assert/strict";

const sessionData = new Map();
const session = {
  async get(keys) {
    if (keys === null) return Object.fromEntries(sessionData);
    if (typeof keys === "string") {
      return sessionData.has(keys) ? { [keys]: sessionData.get(keys) } : {};
    }
    const requested = Array.isArray(keys) ? keys : Object.keys(keys || {});
    return Object.fromEntries(requested.flatMap((key) =>
      sessionData.has(key) ? [[key, sessionData.get(key)]] : []
    ));
  },
  async set(items) {
    for (const [key, value] of Object.entries(items)) sessionData.set(key, value);
  },
  async remove(keys) {
    for (const key of [].concat(keys)) sessionData.delete(key);
  },
};

globalThis.browser = {
  permissions: { contains: async () => true },
  runtime: { getManifest: () => ({ version: "6.2.0" }) },
  storage: { session },
};

const requests = [];
const dnsNames = [];

function response({ json, bytes, status = 200 }) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => null },
    json: async () => json,
    arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  };
}

function decodeDnsName(encoded) {
  const packet = Buffer.from(encoded, "base64url");
  const labels = [];
  let offset = 12;
  while (packet[offset] !== 0) {
    const length = packet[offset++];
    labels.push(packet.subarray(offset, offset + length).toString("ascii"));
    offset += length;
  }
  return labels.join(".");
}

globalThis.fetch = async (input, options = {}) => {
  const url = new URL(input);
  requests.push({ url, options });

  if (url.hostname === "safebrowsing.googleapis.com") {
    return response({ json: { matches: [] } });
  }

  if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.quad9.net") {
    dnsNames.push(decodeDnsName(url.searchParams.get("dns")));
    const packet = new Uint8Array(12);
    packet[7] = 1;
    return response({ bytes: packet });
  }

  if (url.hostname === "rdap.verisign.com") {
    return response({
      json: { events: [{ eventAction: "registration", eventDate: "2020-01-01T00:00:00Z" }] },
    });
  }

  throw new Error(`Unexpected network request: ${url.origin}`);
};

const { checkReputation } = await import("../lib/reputation.js");

test("enabled lookups transmit only their minimized URL-derived inputs", async () => {
  requests.length = 0;
  dnsNames.length = 0;
  const rawUrl = "https://example.com/private/path?token=private-token#account";

  await checkReputation(rawUrl, {
    safeBrowsingEnabled: true,
    safeBrowsingApiKey: "test-key",
    dnsCheckEnabled: true,
    domainAgeEnabled: true,
  });

  const safeBrowsing = requests.find(({ url }) => url.hostname === "safebrowsing.googleapis.com");
  assert.ok(safeBrowsing);
  const payload = JSON.parse(safeBrowsing.options.body);
  assert.ok(payload.threatInfo.threatEntries.length > 0);
  assert.ok(payload.threatInfo.threatEntries.every((entry) =>
    Buffer.from(entry.hash, "base64").byteLength === 4
  ));
  assert.equal(JSON.stringify(payload).includes("/private/path"), false);
  assert.equal(JSON.stringify(payload).includes("private-token"), false);

  assert.deepEqual(dnsNames.sort(), ["example.com", "example.com"]);

  const rdap = requests.find(({ url }) => url.hostname === "rdap.verisign.com");
  assert.ok(rdap);
  assert.equal(rdap.url.pathname, "/com/v1/domain/example.com");
  assert.equal(rdap.url.href.includes("private"), false);
  assert.equal(rdap.url.href.includes("private-token"), false);
});

test("disabled reputation checks make no network requests", async () => {
  requests.length = 0;
  dnsNames.length = 0;

  const result = await checkReputation("https://example.com/path?token=private-token", {
    safeBrowsingEnabled: false,
    safeBrowsingApiKey: "test-key",
    dnsCheckEnabled: false,
    domainAgeEnabled: false,
  });

  assert.equal(requests.length, 0);
  assert.ok(result.sources.every((source) => source.state === "skipped"));
});