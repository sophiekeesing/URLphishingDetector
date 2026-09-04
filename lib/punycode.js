// ---------------------------------------------------------------------
// punycode.js — decode IDN "xn--" labels back to Unicode (RFC 3492)
// ---------------------------------------------------------------------
// The URL parser converts an international domain to its ASCII form, so
// "аррӏе.com" (Cyrillic) arrives as "xn--80ak6aa92e.com". Without
// decoding we cannot see that it is a homograph attack on "apple.com".
// ---------------------------------------------------------------------

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const DELIMITER = "-";

function adapt(delta, numPoints, firstTime) {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) >> 1) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

function basicToDigit(cp) {
  if (cp >= 0x30 && cp <= 0x39) return cp - 0x30 + 26; // 0-9
  if (cp >= 0x61 && cp <= 0x7a) return cp - 0x61; // a-z
  if (cp >= 0x41 && cp <= 0x5a) return cp - 0x41; // A-Z
  return BASE;
}

function decodeLabel(input) {
  const output = [];
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;

  let basic = input.lastIndexOf(DELIMITER);
  if (basic < 0) basic = 0;

  for (let j = 0; j < basic; j++) {
    const cp = input.charCodeAt(j);
    if (cp >= 0x80) throw new Error("not-basic");
    output.push(cp);
  }

  for (let index = basic > 0 ? basic + 1 : 0; index < input.length; ) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) throw new Error("invalid-input");
      const digit = basicToDigit(input.charCodeAt(index++));
      if (digit >= BASE) throw new Error("invalid-input");
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    n += Math.floor(i / out);
    i %= out;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

// Convert a hostname to its Unicode form. Labels that are not valid
// punycode are passed through unchanged.
export function toUnicode(hostname) {
  return hostname
    .split(".")
    .map((label) => {
      if (!/^xn--/i.test(label)) return label;
      try {
        return decodeLabel(label.slice(4).toLowerCase());
      } catch {
        return label;
      }
    })
    .join(".");
}

export function hasPunycode(hostname) {
  return /(^|\.)xn--/i.test(hostname);
}
