// ---------------------------------------------------------------------
// throttle.js — keep bursts inside what the free services allow
// ---------------------------------------------------------------------
// Opening a saved session of 40 tabs asks for 40 hostname checks at
// once. Left alone that is ~160 requests in a couple of seconds, which
// is comfortably over what a public DNS resolver or a domain registry
// will tolerate from one IP.
//
// Two mechanisms:
//
//   Limiter  smooths a burst into a queue with a concurrency cap and a
//            minimum gap between starts. Crucially it also has a
//            maxWait: a check that cannot get a turn quickly is
//            ABANDONED rather than queued forever, because a verdict
//            that arrives two minutes late is worse than a verdict that
//            honestly says one source did not run.
//
//   Backoff  after an error, stop asking for a while. Google Safe
//            Browsing *requires* this and specifies the formula; the
//            other services do not mandate one, so they get a gentler
//            curve and honour Retry-After when it is sent.
//
// Nothing here touches chrome.* at module scope: these files are also
// imported by extension pages that may run without that API.
// ---------------------------------------------------------------------

export class QueueBusy extends Error {
  constructor(name) {
    super(`${name} skipped: too many checks at once`);
    this.name = "QueueBusy";
  }
}

export class Limiter {
  constructor({ name, concurrency = 4, minIntervalMs = 0, maxWaitMs = 5000 }) {
    this.name = name;
    this.concurrency = concurrency;
    this.minIntervalMs = minIntervalMs;
    this.maxWaitMs = maxWaitMs;
    this.active = 0;
    this.lastStart = 0;
    this.queue = [];
  }

  run(fn) {
    return new Promise((resolve, reject) => {
      this.queue.push({ fn, resolve, reject, queuedAt: Date.now() });
      this.#pump();
    });
  }

  #pump() {
    if (this.active >= this.concurrency || this.queue.length === 0) return;

    // Drop anything that has already waited longer than it is worth.
    const now = Date.now();
    while (this.queue.length && now - this.queue[0].queuedAt > this.maxWaitMs) {
      this.queue.shift().reject(new QueueBusy(this.name));
    }
    if (this.queue.length === 0) return;

    const wait = Math.max(0, this.lastStart + this.minIntervalMs - now);
    if (wait > 0) {
      if (!this.timer) {
        this.timer = setTimeout(() => {
          this.timer = null;
          this.#pump();
        }, wait);
      }
      return;
    }

    const task = this.queue.shift();
    this.active++;
    this.lastStart = Date.now();
    Promise.resolve()
      .then(task.fn)
      .then(task.resolve, task.reject)
      .finally(() => {
        this.active--;
        this.#pump();
      });
    this.#pump();
  }
}

// One limiter per service, created on demand.
const limiters = new Map();
export function limiterFor(name, options) {
  if (!limiters.has(name)) limiters.set(name, new Limiter({ name, ...options }));
  return limiters.get(name);
}

// ---------------------------------------------------------------------
// Back-off
// ---------------------------------------------------------------------
// Google's documented rule, which applies to Safe Browsing:
//   MIN((2^(N-1) * 15 minutes) * (RAND + 1), 24 hours)
function googleBackoff(failures) {
  const base = Math.pow(2, failures - 1) * 15 * 60 * 1000;
  return Math.min(base * (Math.random() + 1), 24 * 60 * 60 * 1000);
}

// Gentler curve for services that do not specify one: 30s, 1m, 2m …
// capped at 30 minutes, so a transient blip does not disable a check
// for the rest of the day.
function gentleBackoff(failures) {
  const base = Math.pow(2, failures - 1) * 30 * 1000;
  return Math.min(base * (Math.random() * 0.5 + 1), 30 * 60 * 1000);
}

const CURVES = { google: googleBackoff, gentle: gentleBackoff };

export class Backoff {
  constructor(name, curve = "gentle") {
    this.name = name;
    this.curve = CURVES[curve] || gentleBackoff;
    this.failures = 0;
    this.until = 0;
  }

  // Remaining milliseconds, or 0 when it is fine to proceed.
  blockedFor() {
    return Math.max(0, this.until - Date.now());
  }

  // retryAfterMs, when a server sent Retry-After, always wins: it is the
  // service telling us exactly how long to wait.
  fail(retryAfterMs = null) {
    this.failures++;
    const wait = retryAfterMs ?? this.curve(this.failures);
    this.until = Date.now() + wait;
    return wait;
  }

  succeed() {
    this.failures = 0;
    this.until = 0;
  }

  toJSON() {
    return { failures: this.failures, until: this.until };
  }

  restore(state) {
    if (!state) return;
    this.failures = state.failures || 0;
    this.until = state.until || 0;
  }
}

const backoffs = new Map();
export function backoffFor(name, curve) {
  if (!backoffs.has(name)) backoffs.set(name, new Backoff(name, curve));
  return backoffs.get(name);
}

// Parse Retry-After, which may be seconds or an HTTP date.
export function retryAfterMs(header) {
  if (!header) return null;
  const secs = Number(header);
  if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
  const when = Date.parse(header);
  return Number.isNaN(when) ? null : Math.max(0, when - Date.now());
}

// --- persistence -----------------------------------------------------
// Back-off state must outlive the service worker, which Chrome stops
// after ~30 seconds idle. Without this, every restart would forget that
// a service asked us to stop and we would immediately resume hammering.
const STORE_KEY = "backoffState";

export async function loadBackoffState() {
  if (typeof chrome === "undefined" || !chrome.storage?.session) return;
  try {
    const { [STORE_KEY]: saved } = await chrome.storage.session.get(STORE_KEY);
    if (!saved) return;
    for (const [name, state] of Object.entries(saved)) {
      backoffFor(name).restore(state);
    }
  } catch {
    /* storage unavailable — carry on with a clean slate */
  }
}

export async function saveBackoffState() {
  if (typeof chrome === "undefined" || !chrome.storage?.session) return;
  try {
    const out = {};
    for (const [name, b] of backoffs) {
      if (b.until > Date.now()) out[name] = b.toJSON();
    }
    await chrome.storage.session.set({ [STORE_KEY]: out });
  } catch {
    /* not fatal */
  }
}
