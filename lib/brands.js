// ---------------------------------------------------------------------
// brands.js — reference data for the detection engine
// ---------------------------------------------------------------------

// Brands that phishing campaigns impersonate, with their real
// registrable domains. `anyTld: true` means the company legitimately
// operates the same label on many country domains (google.de,
// amazon.co.uk …) so an exact label match there is NOT suspicious.
//
// `d` is the allow-list: if the page's registrable domain is in it, the
// site is treated as the genuine brand and no look-alike rule fires.
export const BRANDS = [
  // --- Social / messaging ---
  { n: "instagram", d: ["instagram.com", "cdninstagram.com"] },
  { n: "facebook", d: ["facebook.com", "fb.com", "fbcdn.net", "meta.com"] },
  { n: "whatsapp", d: ["whatsapp.com"] },
  { n: "messenger", d: ["messenger.com"] },
  { n: "linkedin", d: ["linkedin.com"] },
  { n: "twitter", d: ["twitter.com", "x.com"] },
  { n: "tiktok", d: ["tiktok.com"] },
  { n: "snapchat", d: ["snapchat.com"] },
  { n: "pinterest", d: ["pinterest.com"] },
  { n: "reddit", d: ["reddit.com"] },
  { n: "discord", d: ["discord.com", "discord.gg"] },
  { n: "telegram", d: ["telegram.org", "t.me"] },
  { n: "twitch", d: ["twitch.tv"] },
  { n: "youtube", d: ["youtube.com", "youtu.be"] },

  // --- Big tech / cloud ---
  {
    n: "google",
    d: [
      "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
      "withgoogle.com", "goo.gl", "google-analytics.com",
    ],
    anyTld: true,
  },
  { n: "gmail", d: ["gmail.com", "googlemail.com"] },
  {
    n: "microsoft",
    d: [
      "microsoft.com", "microsoftonline.com", "microsoft365.com",
      "windows.com", "windowsupdate.com", "msn.com", "bing.com",
      "live.com", "msftauth.net", "msauth.net",
    ],
    anyTld: true,
  },
  { n: "outlook", d: ["outlook.com", "live.com", "hotmail.com"] },
  { n: "office", d: ["office.com", "office365.com", "officeapps.live.com"] },
  { n: "onedrive", d: ["onedrive.com", "onedrive.live.com"] },
  { n: "sharepoint", d: ["sharepoint.com"] },
  { n: "azure", d: ["azure.com", "azure.net", "azurewebsites.net", "azureedge.net"] },
  { n: "apple", d: ["apple.com", "icloud.com", "me.com", "itunes.com", "cdn-apple.com"], anyTld: true },
  { n: "icloud", d: ["icloud.com", "apple.com"] },
  { n: "appleid", d: ["apple.com"] },
  { n: "adobe", d: ["adobe.com"] },
  { n: "dropbox", d: ["dropbox.com"] },
  { n: "zoom", d: ["zoom.us", "zoom.com"] },
  { n: "slack", d: ["slack.com"] },
  { n: "notion", d: ["notion.so", "notion.com"] },
  { n: "atlassian", d: ["atlassian.com", "atlassian.net"] },
  { n: "github", d: ["github.com", "github.io"] },
  { n: "gitlab", d: ["gitlab.com"] },
  { n: "oracle", d: ["oracle.com"] },
  { n: "salesforce", d: ["salesforce.com"] },
  { n: "docusign", d: ["docusign.com", "docusign.net"] },
  { n: "cloudflare", d: ["cloudflare.com"] },
  { n: "wikipedia", d: ["wikipedia.org"], anyTld: true },
  { n: "mozilla", d: ["mozilla.org"] },
  { n: "godaddy", d: ["godaddy.com"] },
  { n: "namecheap", d: ["namecheap.com"] },
  { n: "wordpress", d: ["wordpress.com", "wordpress.org"] },
  { n: "mailchimp", d: ["mailchimp.com"] },
  { n: "hubspot", d: ["hubspot.com"] },
  { n: "zendesk", d: ["zendesk.com"] },

  // --- Security / identity ---
  { n: "okta", d: ["okta.com"] },
  { n: "lastpass", d: ["lastpass.com"] },
  { n: "bitwarden", d: ["bitwarden.com"] },
  { n: "dashlane", d: ["dashlane.com"] },
  { n: "norton", d: ["norton.com"] },
  { n: "mcafee", d: ["mcafee.com"] },
  { n: "kaspersky", d: ["kaspersky.com"] },
  { n: "malwarebytes", d: ["malwarebytes.com"] },

  // --- Payments ---
  { n: "paypal", d: ["paypal.com", "paypal.me", "paypalobjects.com"] },
  { n: "stripe", d: ["stripe.com"] },
  { n: "venmo", d: ["venmo.com"] },
  { n: "cashapp", d: ["cash.app"] },
  { n: "zelle", d: ["zellepay.com"] },
  { n: "wise", d: ["wise.com", "transferwise.com"] },
  { n: "revolut", d: ["revolut.com"] },
  { n: "westernunion", d: ["westernunion.com"] },
  { n: "klarna", d: ["klarna.com"] },
  { n: "skrill", d: ["skrill.com"] },
  { n: "payoneer", d: ["payoneer.com"] },

  // --- Banks ---
  { n: "chase", d: ["chase.com"] },
  { n: "wellsfargo", d: ["wellsfargo.com"] },
  { n: "bankofamerica", d: ["bankofamerica.com"] },
  { n: "citibank", d: ["citi.com", "citibank.com"] },
  { n: "hsbc", d: ["hsbc.com"], anyTld: true },
  { n: "barclays", d: ["barclays.co.uk", "barclays.com"] },
  { n: "santander", d: ["santander.com"], anyTld: true },
  { n: "lloyds", d: ["lloydsbank.com"] },
  { n: "natwest", d: ["natwest.com"] },
  { n: "monzo", d: ["monzo.com"] },
  { n: "starling", d: ["starlingbank.com"] },
  { n: "deutschebank", d: ["db.com"] },
  { n: "commerzbank", d: ["commerzbank.de"] },
  { n: "sparkasse", d: ["sparkasse.de"] },
  { n: "rabobank", d: ["rabobank.nl"] },
  { n: "abnamro", d: ["abnamro.nl"] },
  { n: "swedbank", d: ["swedbank.com"], anyTld: true },
  { n: "nordea", d: ["nordea.com"], anyTld: true },
  { n: "danskebank", d: ["danskebank.com"], anyTld: true },
  { n: "citadele", d: ["citadele.lv"] },
  { n: "luminor", d: ["luminor.lv", "luminor.com"] },

  // --- Crypto ---
  { n: "coinbase", d: ["coinbase.com"] },
  { n: "binance", d: ["binance.com"] },
  { n: "kraken", d: ["kraken.com"] },
  { n: "metamask", d: ["metamask.io"] },
  { n: "trustwallet", d: ["trustwallet.com"] },
  { n: "ledger", d: ["ledger.com"] },
  { n: "trezor", d: ["trezor.io"] },
  { n: "blockchain", d: ["blockchain.com"] },
  { n: "bitfinex", d: ["bitfinex.com"] },
  { n: "kucoin", d: ["kucoin.com"] },

  // --- Shopping ---
  { n: "amazon", d: ["amazon.com", "amazonaws.com", "media-amazon.com", "a2z.com"], anyTld: true },
  { n: "ebay", d: ["ebay.com"], anyTld: true },
  { n: "etsy", d: ["etsy.com"] },
  { n: "alibaba", d: ["alibaba.com"] },
  { n: "aliexpress", d: ["aliexpress.com"] },
  { n: "walmart", d: ["walmart.com"] },
  { n: "target", d: ["target.com"] },
  { n: "bestbuy", d: ["bestbuy.com"] },
  { n: "shopify", d: ["shopify.com"] },
  { n: "temu", d: ["temu.com"] },
  { n: "shein", d: ["shein.com"] },
  { n: "ikea", d: ["ikea.com"], anyTld: true },
  { n: "zalando", d: ["zalando.com"], anyTld: true },

  // --- Streaming / gaming ---
  { n: "netflix", d: ["netflix.com"] },
  { n: "spotify", d: ["spotify.com"] },
  { n: "disney", d: ["disney.com", "disneyplus.com"] },
  { n: "hulu", d: ["hulu.com"] },
  { n: "steam", d: ["steampowered.com", "steamcommunity.com"] },
  { n: "steamcommunity", d: ["steamcommunity.com"] },
  { n: "epicgames", d: ["epicgames.com"] },
  { n: "roblox", d: ["roblox.com"] },
  { n: "minecraft", d: ["minecraft.net"] },
  { n: "playstation", d: ["playstation.com"] },
  { n: "xbox", d: ["xbox.com"] },
  { n: "nintendo", d: ["nintendo.com"] },
  { n: "battlenet", d: ["battle.net"] },
  { n: "blizzard", d: ["blizzard.com"] },

  // --- Shipping / post ---
  { n: "dhl", d: ["dhl.com"], anyTld: true },
  { n: "fedex", d: ["fedex.com"] },
  { n: "usps", d: ["usps.com"] },
  { n: "royalmail", d: ["royalmail.com"] },
  { n: "postnl", d: ["postnl.nl"] },
  { n: "omniva", d: ["omniva.lv", "omniva.ee"] },

  // --- Travel / transport ---
  { n: "booking", d: ["booking.com"] },
  { n: "airbnb", d: ["airbnb.com"] },
  { n: "expedia", d: ["expedia.com"] },
  { n: "ryanair", d: ["ryanair.com"] },
  { n: "lufthansa", d: ["lufthansa.com"] },
  { n: "tripadvisor", d: ["tripadvisor.com"] },
  { n: "uber", d: ["uber.com"] },
  { n: "bolt", d: ["bolt.eu"] },

  // --- Telecom ---
  { n: "verizon", d: ["verizon.com"] },
  { n: "vodafone", d: ["vodafone.com"], anyTld: true },
  { n: "tmobile", d: ["t-mobile.com"] },
  { n: "telekom", d: ["telekom.de", "telekom.com"] },

  // --- Government / tax ---
  { n: "irs", d: ["irs.gov"] },
  { n: "hmrc", d: ["hmrc.gov.uk"] },
  { n: "intuit", d: ["intuit.com"] },
  { n: "turbotax", d: ["turbotax.com"] },
];

// Fast lookup of every known-good registrable domain.
export const OFFICIAL_DOMAINS = new Set(BRANDS.flatMap((b) => b.d));

// Words that appear in the hostname of credential-harvesting pages far
// more often than in ordinary sites. Individually weak — they only add
// up alongside a brand or another signal.
export const PHISH_KEYWORDS = [
  // credential harvesting
  "login", "signin", "sign-in", "logon", "verify", "verification",
  "secure", "security", "account", "accounts", "update", "confirm",
  "recovery", "recover", "unlock", "suspended", "authenticate",
  "validation", "myaccount", "webscr",
  // money
  "billing", "payment", "invoice", "refund", "wallet",
  // parcel / delivery scams
  "tracking", "parcel", "delivery", "package", "shipment", "customs",
  // lure words
  "alert", "prize", "winner", "giveaway", "bonus", "claim", "gift",
];

// Top-level domains weighted by how heavily they are abused. Cheap or
// free registries score higher.
export const TLD_RISK = {
  ".tk": 25, ".ml": 25, ".ga": 25, ".cf": 25, ".gq": 25,
  ".zip": 25, ".mov": 25, ".cyou": 25, ".sbs": 25, ".cfd": 25,
  ".top": 20, ".xyz": 18, ".click": 20, ".link": 18, ".win": 20,
  ".bid": 20, ".loan": 20, ".quest": 20, ".rest": 18, ".icu": 20,
  ".buzz": 18, ".monster": 20, ".work": 15, ".fit": 15, ".pw": 20,
  ".su": 18, ".cc": 12, ".online": 10, ".site": 12, ".website": 12,
  ".space": 12, ".fun": 12, ".life": 10, ".today": 10, ".shop": 10,
  ".store": 10, ".live": 10, ".info": 10, ".biz": 10, ".support": 15,
};

// Multi-label public suffixes, so the registrable domain of
// "login.barclays.co.uk" is "barclays.co.uk", not "co.uk".
export const MULTI_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "net.nz", "org.nz", "co.za", "org.za",
  "com.br", "net.br", "org.br", "gov.br",
  "com.mx", "com.ar", "com.co", "com.pe", "com.uy", "com.ve", "com.ec",
  "co.in", "net.in", "org.in", "gov.in",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
  "com.cn", "net.cn", "org.cn", "gov.cn",
  "com.tw", "com.hk", "com.sg", "com.my", "co.id", "co.th",
  "com.tr", "com.ua", "com.pl", "com.ru", "com.es", "com.pt", "com.gr",
  "co.il", "com.sa", "com.eg", "co.ke", "com.ng", "com.gh",
  "com.ph", "com.vn", "com.pk", "com.bd",
  "co.kr", "or.kr", "ne.kr",
  "com.cy", "com.mt", "co.ug", "co.tz", "com.na", "co.bw",
]);
