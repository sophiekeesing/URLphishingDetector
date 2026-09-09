// ---------------------------------------------------------------------
// trackers.js — link services that hide or harvest
// ---------------------------------------------------------------------
// A different threat family from brand impersonation. These links look
// completely ordinary — many redirect you to the real site afterwards,
// so nothing seems wrong — while recording who clicked.
//
// What an IP logger actually gets with no prompt: your IP address (and
// from it a city/ISP-level guess at your location), browser, operating
// system, screen size, language and the time. What it CANNOT get
// silently is precise GPS location, camera or microphone — those need
// the browser's own permission dialog.
// ---------------------------------------------------------------------

// Known IP-logger / click-tracker services, including the "innocent
// looking" custom domains Grabify and friends hand out so the link does
// not read as a logger. Necessarily incomplete: any new domain is
// invisible to a list like this.
export const IP_LOGGERS = new Set([
  // The services themselves
  "grabify.link", "grabify.org", "iplogger.org", "iplogger.com",
  "iplogger.ru", "iplogger.co", "iplogger.info", "iplogger.cn",
  "2no.co", "yip.su", "iplis.ru", "ipgrabber.ru", "ipgraber.ru",
  "ipgeolocation.io", "blasze.com", "blasze.tk", "whatstheirip.com",
  "02ip.ru", "ipgs.su", "maper.info", "ps3cfw.com",
  // Grabify custom domains — deliberately harmless-sounding
  "bmwforum.co", "leancoding.co", "spottyfly.com", "spotifysong.com",
  "youtubeshort.watch", "fortnitechat.site", "freegiftcards.co",
  "dontclick.this", "joinmy.site", "curiouscat.club",
  "catsnthings.fun", "catsnthing.com", "gaming-at-my.best",
  "gaming-at-my.site", "mypic.icu", "screenshare.host",
  "imageshare.best", "gamingfun.me", "trulove.guru", "dateing.club",
  "shrekis.life", "headshot.monster", "yourmakingme.gay",
  "stopify.co", "quickmessage.io", "durpz.com", "ur2.pw",
  // Other logger / "who clicked my link" services
  "urlto.me", "iplogger.cc", "ipgrab.io", "grabify.pro",
  "logger.click", "clickstat.link", "whoclicked.me", "iptrack.me",
  "ipfind.link", "seeip.link", "trackurl.me", "urltracker.link",
]);

// Hosts that legitimately hand out short random paths, so the generic
// "looks like a redirector" rule below must not fire on them.
export const SHORT_CODE_HOSTS = new Set([
  "imgur.com", "pastebin.com", "hastebin.com", "codepen.io",
  "jsfiddle.net", "replit.com", "codesandbox.io", "stackblitz.com",
  "figma.com", "miro.com", "trello.com", "notion.so", "coda.io",
  "airtable.com", "typeform.com", "calendly.com", "meet.google.com",
  "zoom.us", "discord.gg", "spotify.com", "prnt.sc", "gyazo.com",
  "streamable.com", "gfycat.com", "redd.it", "flic.kr", "wetransfer.com",
]);

// Link shorteners. Not malicious in themselves — but the real
// destination is hidden until you have already arrived, which is why
// phishing campaigns like them.
export const SHORTENERS = new Set([
  // Most widely used
  "bit.ly", "j.mp", "bitly.is", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
  "buff.ly", "is.gd", "v.gd", "cutt.ly", "cutt.us", "shorturl.at",
  "rb.gy", "rebrand.ly", "bl.ink", "short.io", "short.gy", "t.ly",
  "s.id", "tiny.cc", "bit.do", "b.link", "u.nu", "shrtco.de", "da.gd",
  "soo.gd", "gg.gg", "snipurl.com", "tny.im", "kutt.it", "spoo.me",
  "po.st", "to.ly", "tr.im", "v.ht", "waa.ai", "qr.net", "safe.mn",
  "fur.ly", "fff.to", "lc.cx", "minu.me", "zapit.nu", "url5.org",
  "doiop.com", "sor.bz", "trck.me", "hopp.co", "swiy.co", "urlr.me",
  "clc.to", "tinu.be", "reduced.to", "x.co", "mcaf.ee", "db.tt",
  "qr.ae", "su.pr", "dlvr.it", "trib.al", "hubs.ly", "lnkd.in",

  // German / DACH. t1p.de, ogy.de, 0cn.de, kurzelinks.de, kurzlinks.de,
  // bab.si, j0b.de, 3x7.de and kurzlink.ch are all one German provider.
  "t1p.de", "ogy.de", "0cn.de", "kurzelinks.de", "kurzlinks.de",
  "kurzlink.ch", "bab.si", "j0b.de", "3x7.de", "kurzly.de", "lmy.de",
  "miur.li", "tnyurl.de", "shrnk.de", "kurz.gd", "nicou.ch",

  // Rest of Europe
  "ej.uz", "saii.lv", "nkl.lt", "tiny.lt", "sina.lt", "trum.pl",
  "tiny.pl", "krat.si", "lnk.sk", "abbr.sk", "1url.cz", "zkrat.me",
  "sux.cz", "hadej.co", "chk.li", "lien.li", "korta.nu", "tinyurl.hu",
  "url.ie", "urlz.fr", "a0.fr", "m1p.fr", "couic.fr", "icit.fr",
  "bzh.me", "oua.be", "l-k.be", "mut.lu", "clck.ru", "vk.cc", "u.to",
  "goo.su", "qps.ru", "sq6.ru", "chilp.it", "rdz.me",

  // Asia
  "t.cn", "7vd.cn", "ppt.cc", "shorturl.asia", "2ad.in", "asso.in",

  // Americas
  "migre.me", "ecra.se", "4view.me", "cbug.cc", "sy.pe", "p.pw",

  // Link monetisation — these interpose an ad page before forwarding
  "adf.ly", "shorte.st", "sh.st", "bc.vc", "ouo.io", "linkvertise.com",
  "cf.ly", "parky.tv",

  // Brand-run shorteners. Deliberately listed here even though some
  // (goo.gl) also appear in that brand's OFFICIAL_DOMAINS: the two lists
  // answer different questions. Being Google-owned exempts goo.gl from
  // the impersonation rules, and hiding its destination still earns the
  // shortener note. Both are true at once — not a collision to fix.
  "amzn.to", "ebay.us", "etsy.me", "spoti.fi", "fb.me", "wa.me",
  "ig.me", "pin.it", "msft.it", "aka.ms", "go.microsoft.com", "dai.ly",

  // News
  "nyti.ms", "wapo.st", "cnn.it", "reut.rs", "bbc.in", "econ.st",
  "n.pr", "huff.to", "apne.ws", "usat.ly", "cbsn.ws", "abcn.ws",
  "flip.it", "gu.com",
]);

// Query parameters that conventionally carry a redirect target. A URL
// on a trusted domain whose parameter points somewhere else is an open
// redirect — the visible domain is genuine, the destination is not.
//
// Unambiguous names: an external URL in one of these is a redirect.
export const REDIRECT_PARAMS = new Set([
  "url", "uri", "redirect", "redirect_uri", "redirect_url", "redir",
  "next", "target", "dest", "destination", "goto", "continue",
  "returnurl", "return_to", "returnto", "out", "away", "forward",
  "jump", "exit",
]);

// Names that are usually something else — "q" is the universal search
// parameter, so google.com/search?q=https://example.com is a search,
// not a redirect. These only count when the PATH also looks like a
// redirect endpoint (google.com/url?q=…, facebook.com/l.php?u=…).
export const WEAK_REDIRECT_PARAMS = new Set([
  "q", "u", "r", "to", "link", "return", "load", "window", "view",
]);

export const REDIRECT_PATH_HINT =
  /\/(url|redirect|redir|out|away|link|go|jump|exit|leave|click|l)\b/i;
