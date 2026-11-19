// Unit tests for the matching half of lib/exclusions.js.
// Run from the repository root with:  node --test
// No dependencies; needs Node 22 or newer.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  normalizeHost,
  validateEntry,
  isExcluded,
  matchingEntry,
  parseItems,
  entryHost,
  scanPaused,
} from "../lib/exclusions.js";
import { evaluate } from "../lib/verdict.js";

const list = (entries) => new Map(Object.entries(entries));

test("normalizeHost accepts URLs, hostnames and pasted paths", () => {
  assert.equal(normalizeHost("https://Example.COM/path?q=1"), "example.com");
  assert.equal(normalizeHost("example.com"), "example.com");
  assert.equal(normalizeHost("example.com/some/page"), "example.com");
  assert.equal(normalizeHost("  www.example.com  "), "www.example.com");
  assert.equal(normalizeHost("*.example.com"), "example.com");
});

test("normalizeHost drops port and trailing dot", () => {
  assert.equal(normalizeHost("http://example.com:8080/"), "example.com");
  assert.equal(normalizeHost("example.com."), "example.com");
  assert.equal(normalizeHost("https://example.com./x"), "example.com");
});

test("normalizeHost stores IDNs as punycode", () => {
  // Cyrillic "а" in place of Latin "a"
  assert.equal(normalizeHost("https://аpple.com/"), "xn--pple-43d.com");
  assert.equal(normalizeHost("xn--pple-43d.com"), "xn--pple-43d.com");
});

test("normalizeHost rejects what is not a web address", () => {
  assert.equal(normalizeHost(""), null);
  assert.equal(normalizeHost("   "), null);
  assert.equal(normalizeHost("ftp://example.com"), null);
  assert.equal(normalizeHost("javascript:alert(1)"), null);
  assert.equal(normalizeHost("http://exa mple.com"), null);
  assert.equal(normalizeHost(null), null);
});

test("entryHost strips www. only for whole-domain entries", () => {
  assert.equal(entryHost("www.example.com", "domain"), "example.com");
  assert.equal(entryHost("www.example.com", "host"), "www.example.com");
  assert.equal(entryHost("www.com", "domain"), "www.com");
});

test("validateEntry rejects public suffixes as whole domains", () => {
  for (const suffix of ["com", "co.uk", "com.au", "github.io", "blogspot.com"]) {
    const r = validateEntry(suffix, "domain");
    assert.equal(r.ok, false, suffix);
    assert.ok(r.error, suffix);
  }
});

test("validateEntry allows a site on a shared suffix", () => {
  assert.equal(validateEntry("someone.github.io", "domain").ok, true);
  assert.equal(validateEntry("barclays.co.uk", "domain").ok, true);
});

test("validateEntry rejects single-label hosts in any mode", () => {
  assert.equal(validateEntry("localhost", "host").ok, false);
  assert.equal(validateEntry("com", "host").ok, false);
});

test("validateEntry forces IP addresses to exact-host mode", () => {
  const r = validateEntry("192.168.0.10", "domain");
  assert.equal(r.ok, true);
  assert.equal(r.mode, "host");
  assert.equal(r.host, "192.168.0.10");
});

test("validateEntry warns for IP loggers, shorteners and dangerous sites", () => {
  const logger = validateEntry("grabify.link", "domain");
  assert.equal(logger.ok, true);
  assert.match(logger.warning, /IP logger/);

  const shortener = validateEntry("bit.ly", "domain");
  assert.equal(shortener.ok, true);
  assert.match(shortener.warning, /every bit\.ly link/);

  const dangerous = validateEntry("example.com", "domain", { status: "dangerous" });
  assert.match(dangerous.warning, /dangerous/);

  assert.equal(validateEntry("example.com", "domain").warning, undefined);
});

test("whole-domain entries cover subdomains, exact entries do not", () => {
  const l = list({ "example.com": { m: "domain", t: 1 }, "shop.test.org": { m: "host", t: 1 } });
  assert.equal(isExcluded("https://example.com/", l), true);
  assert.equal(isExcluded("https://www.example.com/", l), true);
  assert.equal(isExcluded("https://a.b.example.com/x", l), true);
  assert.equal(isExcluded("https://shop.test.org/", l), true);
  assert.equal(isExcluded("https://www.shop.test.org/", l), false);
  assert.equal(isExcluded("https://test.org/", l), false);
});

test("matching does not bleed into similar names", () => {
  const l = list({ "example.com": { m: "domain", t: 1 } });
  assert.equal(isExcluded("https://notexample.com/", l), false);
  assert.equal(isExcluded("https://example.com.evil.net/", l), false);
  assert.equal(isExcluded("https://example.co/", l), false);
});

test("a look-alike never matches the real entry", () => {
  const l = list({ "apple.com": { m: "domain", t: 1 } });
  assert.equal(isExcluded("https://аpple.com/", l), false); // Cyrillic а
  const idn = list({ "xn--pple-43d.com": { m: "domain", t: 1 } });
  assert.equal(isExcluded("https://аpple.com/", idn), true);
  assert.equal(isExcluded("https://apple.com/", idn), false);
});

test("matching ignores port, trailing dot and case", () => {
  const l = list({ "example.com": { m: "host", t: 1 } });
  assert.equal(isExcluded("https://EXAMPLE.com:8443/", l), true);
  assert.equal(isExcluded("https://example.com./", l), true);
});

test("IP entries match exactly", () => {
  const l = list({ "10.0.0.1": { m: "host", t: 1 } });
  assert.equal(isExcluded("http://10.0.0.1/admin", l), true);
  assert.equal(isExcluded("http://10.0.0.12/", l), false);
});

test("matchingEntry names the entry that covers the URL", () => {
  const l = list({ "example.com": { m: "domain", t: 5 } });
  assert.deepEqual(matchingEntry("https://mail.example.com/", l), { host: "example.com", m: "domain", t: 5 });
  assert.equal(matchingEntry("not a url", l), null);
  assert.equal(matchingEntry("https://x.example.com/", new Map()), null);
});

test("an exclusion never covers where a redirect sends you", () => {
  const l = list({ "google.com": { m: "domain", t: 1 } });
  const search = "https://www.google.com/search?q=cats";
  const redirect = "https://www.google.com/url?q=https://instogram.com/login";
  assert.equal(scanPaused(search, evaluate(search), l), true);
  assert.equal(scanPaused(redirect, evaluate(redirect), l), false);
  assert.equal(evaluate(redirect).status, "dangerous");
});

test("scanPaused is false for sites not on the list", () => {
  const url = "https://example.org/";
  assert.equal(scanPaused(url, evaluate(url), list({ "example.com": { m: "domain", t: 1 } })), false);
});

test("parseItems keeps only well-formed x: keys", () => {
  const l = parseItems({
    "x:example.com": { m: "host", t: 3 },
    "x:other.org": { m: "weird", t: "4" },
    "x:": { m: "domain", t: 1 },
    "x:broken.net": "nope",
    autoScanEnabled: true,
  });
  assert.deepEqual([...l.keys()].sort(), ["example.com", "other.org"]);
  assert.equal(l.get("other.org").m, "domain");
  assert.equal(l.get("other.org").t, 4);
});
