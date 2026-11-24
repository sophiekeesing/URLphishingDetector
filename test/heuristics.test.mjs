// Unit tests for local URL parsing and heuristic signals.

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseUrl, runHeuristics } from "../lib/heuristics.js";

const signalIds = (input) => runHeuristics(parseUrl(input)).signals.map((signal) => signal.id);

test("parseUrl accepts a hostname without a scheme", () => {
  assert.equal(parseUrl("instogram.com").href, "https://instogram.com/");
});

test("parseUrl rejects non-web schemes", () => {
  assert.equal(parseUrl("javascript:alert(1)"), null);
  assert.equal(parseUrl("ftp://example.com"), null);
});

test("IDN look-alikes receive homograph signals", () => {
  const parsed = parseUrl("https://аpple.com/");
  const ids = signalIds("https://аpple.com/");

  assert.equal(parsed.hostname, "xn--pple-43d.com");
  assert.ok(ids.includes("lookalikeChars"));
  assert.ok(ids.includes("punycode"));
  assert.ok(ids.includes("homoglyph"));
});

test("an official domain's open redirect to an impersonator is detected", () => {
  const parsed = parseUrl("https://google.com/url?q=https://instogram.com");
  const result = runHeuristics(parsed);

  assert.equal(result.official, true);
  assert.ok(result.signals.some((signal) => signal.id === "openRedirectToImpersonator"));
});

test("credentials embedded in a URL are flagged", () => {
  assert.ok(signalIds("https://user:secret@example.com/").includes("credentials"));
});