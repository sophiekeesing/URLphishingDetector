// Unit tests for the session verdict cache and request coalescing.

import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";

const sessionData = new Map();
globalThis.browser = {
  storage: {
    session: {
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
    },
  },
};

const { cacheClear, cacheGet, cacheSet, coalesce } = await import("../lib/cache.js");

beforeEach(async () => {
  await cacheClear();
  sessionData.clear();
});

test("verdicts are stored in session storage and survive a worker restart", async () => {
  const verdict = { status: "safe", href: "https://example.com/" };
  await cacheSet("example.com", verdict);

  const restartedWorker = await import(`../lib/cache.js?worker=${Date.now()}`);
  assert.deepEqual(await restartedWorker.cacheGet("example.com"), verdict);
  assert.ok(sessionData.has("cc:example.com"));
});

test("expired session entries are removed instead of returned", async () => {
  sessionData.set("cc:expired.example", {
    result: { status: "dangerous" },
    expires: Date.now() - 1,
  });

  assert.equal(await cacheGet("expired.example"), null);
  assert.equal(sessionData.has("cc:expired.example"), false);
});

test("concurrent checks for one hostname share a single operation", async () => {
  let release;
  let calls = 0;
  const pending = new Promise((resolve) => {
    release = resolve;
  });
  const work = async () => {
    calls++;
    await pending;
    return { status: "safe" };
  };

  const first = coalesce("example.com", work);
  const second = coalesce("example.com", work);
  assert.strictEqual(first, second);
  assert.equal(calls, 1);
  release();
  assert.deepEqual(await Promise.all([first, second]), [
    { status: "safe" },
    { status: "safe" },
  ]);
});