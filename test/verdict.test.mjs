// Unit tests for local verdict evaluation and privacy-safe lookup inputs.
// Run from the repository root with:  node --test

import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalize } from "../lib/canonicalize.js";
import { evaluate, DANGEROUS_AT, SUSPICIOUS_AT } from "../lib/verdict.js";

test("invalid input returns an error verdict without a URL", () => {
  const verdict = evaluate("javascript:alert(1)");

  assert.equal(verdict.status, "error");
  assert.equal(verdict.score, 0);
  assert.equal(verdict.href, null);
});

test("known official subdomains remain safe", () => {
  const verdict = evaluate("https://login.microsoftonline.com/");

  assert.equal(verdict.status, "safe");
  assert.equal(verdict.score, 0);
  assert.equal(verdict.official, true);
});

test("known misspellings produce the documented dangerous verdict", () => {
  const verdict = evaluate("instogram.com");

  assert.equal(verdict.status, "dangerous");
  assert.equal(verdict.score, 58);
  assert.equal(verdict.href, "https://instogram.com/");
});

test("risk thresholds distinguish suspicious from dangerous scores", () => {
  const suspicious = evaluate("example.com", {
    reputation: { signals: [{ id: "test", weight: SUSPICIOUS_AT, message: "test signal" }] },
  });
  const dangerous = evaluate("example.com", {
    reputation: { signals: [{ id: "test", weight: DANGEROUS_AT, message: "test signal" }] },
  });

  assert.equal(suspicious.status, "suspicious");
  assert.equal(suspicious.score, SUSPICIOUS_AT);
  assert.equal(dangerous.status, "dangerous");
  assert.equal(dangerous.score, DANGEROUS_AT);
});

test("a confirmed reputation hit forces the dangerous verdict", () => {
  const verdict = evaluate("example.com", {
    reputation: { malicious: true, reasons: ["Threat-list match"] },
  });

  assert.equal(verdict.status, "dangerous");
  assert.equal(verdict.score, 100);
  assert.ok(verdict.reasons.includes("Threat-list match"));
});

test("domain-age credit cannot reduce a brand impersonation score", () => {
  const verdict = evaluate("instogram.com", {
    reputation: {
      signals: [{ id: "domainAge", weight: -12, credit: true, message: "Old domain" }],
    },
  });

  assert.equal(verdict.score, 58);
  assert.equal(verdict.signals.some((signal) => signal.id === "domainAge"), false);
});

test("a hidden destination is flagged separately from the risk verdict", () => {
  const verdict = evaluate("https://bit.ly/chick-check-test");

  assert.equal(verdict.status, "safe");
  assert.equal(verdict.score, 15);
  assert.equal(verdict.hidesDestination, true);
});

test("Safe Browsing canonicalization drops query strings and fragments", () => {
  const withPrivateParts = canonicalize("https://example.com/path?token=secret#account");
  const withoutPrivateParts = canonicalize("https://example.com/path");

  assert.deepEqual(withPrivateParts, withoutPrivateParts);
  assert.equal(JSON.stringify(withPrivateParts).includes("secret"), false);
  assert.equal(JSON.stringify(withPrivateParts).includes("account"), false);
});