// ---------------------------------------------------------------------
// similarity.js — how close is this domain to a brand name?
// ---------------------------------------------------------------------
// Damerau-Levenshtein edit distance catches the four typo families that
// squatters actually use:
//   substitution  instagram -> inst*o*gram
//   deletion      instagram -> instagam
//   insertion     instagram -> instaggram
//   transposition google    -> gogole
// plus a confusables pass that folds look-alike characters (Cyrillic о,
// digit 0, "rn" for "m") down to plain ASCII first.
// ---------------------------------------------------------------------

// Unicode characters that render like ASCII letters. Used after a
// punycode label has been decoded back to Unicode.
const CONFUSABLES = {
  // Cyrillic
  а: "a", в: "b", е: "e", ѕ: "s", і: "i", ј: "j", к: "k", м: "m", н: "h",
  о: "o", р: "p", с: "c", т: "t", у: "y", х: "x", һ: "h", ԁ: "d", ԛ: "q",
  ԝ: "w", ѡ: "w", ӏ: "l", ғ: "f", ә: "e", ұ: "y",
  // Greek
  α: "a", β: "b", γ: "y", ε: "e", ζ: "z", η: "n", ι: "i", κ: "k", μ: "u",
  ν: "v", ο: "o", π: "n", ρ: "p", σ: "o", τ: "t", υ: "u", χ: "x", ω: "w",
  // Latin extended / diacritics commonly used to fake ASCII
  á: "a", à: "a", â: "a", ä: "a", ã: "a", å: "a", ā: "a", ă: "a", ą: "a",
  ç: "c", ć: "c", č: "c", ĉ: "c", ď: "d", đ: "d",
  é: "e", è: "e", ê: "e", ë: "e", ē: "e", ĕ: "e", ė: "e", ę: "e", ě: "e",
  ğ: "g", ĝ: "g", ģ: "g", ĥ: "h", ħ: "h",
  í: "i", ì: "i", î: "i", ï: "i", ī: "i", į: "i", ı: "i", ĩ: "i",
  ĵ: "j", ķ: "k", ĺ: "l", ļ: "l", ľ: "l", ł: "l",
  ń: "n", ņ: "n", ň: "n", ñ: "n",
  ó: "o", ò: "o", ô: "o", ö: "o", õ: "o", ø: "o", ō: "o", ŏ: "o", ő: "o",
  ŕ: "r", ř: "r", ś: "s", ş: "s", š: "s", ŝ: "s",
  ţ: "t", ť: "t", ŧ: "t",
  ú: "u", ù: "u", û: "u", ü: "u", ū: "u", ŭ: "u", ů: "u", ű: "u", ų: "u",
  ŵ: "w", ý: "y", ÿ: "y", ŷ: "y", ź: "z", ż: "z", ž: "z",
  // Digits and symbols used as letters
  0: "o", 1: "l", 3: "e", 4: "a", 5: "s", 6: "g", 7: "t", 8: "b", 9: "g",
  "@": "a", $: "s", "!": "i", "|": "l",
};

// Fold look-alikes down to plain ASCII letters.
export function normalizeConfusables(text) {
  let out = "";
  for (const ch of text.toLowerCase()) {
    out += CONFUSABLES[ch] ?? ch;
  }
  // Multi-character look-alikes.
  return out.replace(/rn/g, "m").replace(/vv/g, "w").replace(/nn/g, "m");
}

// Damerau-Levenshtein with an early bail-out once the distance exceeds
// `max` (we never care about far-apart strings).
export function editDistance(a, b, max = 3) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;

  const prev2 = new Array(b.length + 1);
  let prev = new Array(b.length + 1);
  let curr = new Array(b.length + 1);

  for (let j = 0; j <= b.length; j++) prev[j] = j;

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    let rowMin = curr[0];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let d = Math.min(
        curr[j - 1] + 1, // insertion
        prev[j] + 1, // deletion
        prev[j - 1] + cost // substitution
      );
      // transposition
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d = Math.min(d, prev2[j - 2] + cost);
      }
      curr[j] = d;
      if (d < rowMin) rowMin = d;
    }
    if (rowMin > max) return max + 1;
    prev2.length = 0;
    prev2.push(...prev);
    const swap = prev;
    prev = curr;
    curr = swap;
  }
  return prev[b.length];
}

// How many edits are tolerable before we stop calling it a look-alike?
// Short names need a tighter bound or every 4-letter domain matches.
export function allowedDistance(brand) {
  if (brand.length <= 4) return 0; // exact only
  if (brand.length <= 7) return 1;
  return 2;
}
