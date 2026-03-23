/**
 * QUIT THE DISTRACTS — BLOCKLIST DATABASE
 * Based on EasyList, EasyPrivacy, uBlock Origin filters, and Peter Lowe's list.
 * This is a curated representative sample used for domain scanning.
 */

window.BLOCKLIST = {

  // ─── AD NETWORKS ────────────────────────────────────────────────────────────
  adNetworks: [
    { domain: "doubleclick.net",          name: "Google DoubleClick",      type: "Ad Network",     risk: "high" },
    { domain: "googlesyndication.com",    name: "Google AdSense",          type: "Ad Network",     risk: "high" },
    { domain: "googleadservices.com",     name: "Google Ad Services",      type: "Ad Network",     risk: "high" },
    { domain: "adnxs.com",               name: "AppNexus / Xandr",        type: "Ad Network",     risk: "high" },
    { domain: "moatads.com",             name: "Oracle Moat",             type: "Ad Measurement", risk: "medium" },
    { domain: "taboola.com",             name: "Taboola",                 type: "Content Ads",    risk: "high" },
    { domain: "outbrain.com",            name: "Outbrain",                type: "Content Ads",    risk: "high" },
    { domain: "revcontent.com",          name: "RevContent",              type: "Content Ads",    risk: "high" },
    { domain: "criteo.com",              name: "Criteo",                  type: "Retargeting",    risk: "high" },
    { domain: "criteo.net",              name: "Criteo Network",          type: "Retargeting",    risk: "high" },
    { domain: "rubiconproject.com",      name: "Magnite (Rubicon)",       type: "Programmatic",   risk: "high" },
    { domain: "pubmatic.com",            name: "PubMatic",                type: "Programmatic",   risk: "high" },
    { domain: "openx.net",               name: "OpenX",                   type: "Programmatic",   risk: "high" },
    { domain: "advertising.com",         name: "Yahoo Advertising",       type: "Ad Network",     risk: "high" },
    { domain: "media.net",               name: "Media.net",               type: "Ad Network",     risk: "high" },
    { domain: "33across.com",            name: "33Across",                type: "Ad Network",     risk: "medium" },
    { domain: "a-ads.com",              name: "A-Ads",                   type: "Ad Network",     risk: "high" },
    { domain: "adroll.com",             name: "AdRoll",                  type: "Retargeting",    risk: "high" },
    { domain: "amazon-adsystem.com",    name: "Amazon DSP",              type: "Ad Network",     risk: "medium" },
    { domain: "adsafeprotected.com",    name: "IAS Ad Safety",           type: "Ad Measurement", risk: "medium" },
    { domain: "smartadserver.com",      name: "Smart AdServer",          type: "Programmatic",   risk: "high" },
    { domain: "yieldmo.com",            name: "Yieldmo",                 type: "Ad Network",     risk: "high" },
    { domain: "gumgum.com",             name: "GumGum",                  type: "Contextual Ads", risk: "medium" },
    { domain: "triplelift.com",         name: "TripleLift",              type: "Native Ads",     risk: "high" },
    { domain: "indexexchange.com",      name: "Index Exchange",          type: "Programmatic",   risk: "high" },
    { domain: "sharethrough.com",       name: "Sharethrough",            type: "Native Ads",     risk: "high" },
    { domain: "bidswitch.net",          name: "BidSwitch",               type: "Programmatic",   risk: "high" },
    { domain: "lijit.com",              name: "Lijit (Sovrn)",           type: "Ad Network",     risk: "high" },
    { domain: "sovrn.com",              name: "Sovrn",                   type: "Ad Network",     risk: "high" },
    { domain: "undertone.com",          name: "Undertone",               type: "Ad Network",     risk: "high" },
  ],

  // ─── TRACKERS ───────────────────────────────────────────────────────────────
  trackers: [
    { domain: "google-analytics.com",     name: "Google Analytics",       type: "Analytics",      risk: "medium" },
    { domain: "googletagmanager.com",     name: "Google Tag Manager",     type: "Tag Manager",    risk: "medium" },
    { domain: "facebook.net",            name: "Facebook Pixel",         type: "Social Tracker", risk: "high" },
    { domain: "connect.facebook.net",    name: "Facebook Connect",       type: "Social Tracker", risk: "high" },
    { domain: "analytics.twitter.com",   name: "Twitter Analytics",      type: "Social Tracker", risk: "medium" },
    { domain: "t.co",                    name: "Twitter Link Tracker",   type: "Link Tracker",   risk: "medium" },
    { domain: "hotjar.com",              name: "Hotjar",                  type: "Session Replay", risk: "high" },
    { domain: "mouseflow.com",           name: "Mouseflow",               type: "Session Replay", risk: "high" },
    { domain: "fullstory.com",           name: "FullStory",               type: "Session Replay", risk: "high" },
    { domain: "segment.io",             name: "Segment",                 type: "CDP",            risk: "medium" },
    { domain: "segment.com",            name: "Segment Analytics",       type: "CDP",            risk: "medium" },
    { domain: "mixpanel.com",           name: "Mixpanel",                type: "Analytics",      risk: "medium" },
    { domain: "amplitude.com",          name: "Amplitude",               type: "Analytics",      risk: "medium" },
    { domain: "heap.io",                name: "Heap Analytics",          type: "Analytics",      risk: "medium" },
    { domain: "heapanalytics.com",      name: "Heap",                    type: "Analytics",      risk: "medium" },
    { domain: "intercom.io",            name: "Intercom",                type: "CRM Tracker",    risk: "medium" },
    { domain: "intercom.com",           name: "Intercom",                type: "Chat/Tracker",   risk: "medium" },
    { domain: "hubspot.com",            name: "HubSpot",                 type: "CRM Tracker",    risk: "medium" },
    { domain: "hs-scripts.com",         name: "HubSpot Scripts",         type: "CRM Tracker",    risk: "medium" },
    { domain: "marketo.net",            name: "Marketo",                 type: "Marketing",      risk: "medium" },
    { domain: "mktoresp.com",           name: "Marketo Resp",            type: "Marketing",      risk: "medium" },
    { domain: "pardot.com",             name: "Salesforce Pardot",       type: "Marketing",      risk: "medium" },
    { domain: "optimizely.com",         name: "Optimizely",              type: "A/B Testing",    risk: "low" },
    { domain: "newrelic.com",           name: "New Relic",               type: "APM",            risk: "low" },
    { domain: "nr-data.net",            name: "New Relic Data",          type: "APM",            risk: "low" },
    { domain: "datadoghq.com",          name: "Datadog",                 type: "APM",            risk: "low" },
    { domain: "quantserve.com",         name: "Quantcast",               type: "Audience",       risk: "high" },
    { domain: "scorecardresearch.com",  name: "Comscore",                type: "Audience",       risk: "high" },
    { domain: "chartbeat.com",          name: "Chartbeat",               type: "Analytics",      risk: "medium" },
    { domain: "omtrdc.net",             name: "Adobe Analytics",         type: "Analytics",      risk: "medium" },
    { domain: "demdex.net",             name: "Adobe Audience Manager",  type: "DMP",            risk: "high" },
    { domain: "2o7.net",                name: "Adobe Measurement",       type: "Analytics",      risk: "medium" },
    { domain: "krxd.net",               name: "Krux (Salesforce DMP)",   type: "DMP",            risk: "high" },
    { domain: "bluekai.com",            name: "Oracle BlueKai",          type: "DMP",            risk: "high" },
    { domain: "addthis.com",            name: "AddThis",                 type: "Social Share",   risk: "high" },
    { domain: "sharethis.com",          name: "ShareThis",               type: "Social Share",   risk: "high" },
    { domain: "disqus.com",             name: "Disqus",                  type: "Comments",       risk: "medium" },
    { domain: "livefyre.com",           name: "Livefyre",                type: "Comments",       risk: "medium" },
    { domain: "braze.com",              name: "Braze",                   type: "Push/Marketing", risk: "medium" },
    { domain: "onesignal.com",          name: "OneSignal",               type: "Push Notif.",    risk: "medium" },
    { domain: "clearbits.net",          name: "Clearbit",                type: "Enrichment",     risk: "medium" },
    { domain: "clearbit.com",           name: "Clearbit",                type: "Enrichment",     risk: "medium" },
  ],

  // ─── FINGERPRINTERS ─────────────────────────────────────────────────────────
  fingerprinters: [
    { domain: "fingerprintjs.com",     name: "FingerprintJS",     type: "Fingerprinting", risk: "high" },
    { domain: "cdn.jsdelivr.net",      name: "jsDelivr CDN",      type: "CDN",            risk: "low" },
    { domain: "maxmind.com",           name: "MaxMind",           type: "IP Geolocation", risk: "medium" },
    { domain: "ipdata.co",             name: "IPData",            type: "IP Geolocation", risk: "medium" },
    { domain: "ipinfo.io",             name: "IPInfo",            type: "IP Geolocation", risk: "medium" },
  ],

  // ─── KNOWN AD-HEAVY SITES AND THEIR LIKELY NETWORKS ─────────────────────────
  siteProfiles: {
    "reddit.com":      { ads: ["googlesyndication.com","adnxs.com","moatads.com"],        trackers: ["google-analytics.com","segment.io","hotjar.com"] },
    "cnn.com":         { ads: ["doubleclick.net","outbrain.com","taboola.com"],            trackers: ["chartbeat.com","scorecardresearch.com","omtrdc.net","demdex.net"] },
    "forbes.com":      { ads: ["doubleclick.net","criteo.com","rubiconproject.com"],       trackers: ["google-analytics.com","quantserve.com","addthis.com","bluekai.com"] },
    "msn.com":         { ads: ["advertising.com","media.net","a-ads.com","adnxs.com"],    trackers: ["google-analytics.com","omtrdc.net","facebook.net"] },
    "dailymail.co.uk": { ads: ["doubleclick.net","openx.net","pubmatic.com"],             trackers: ["scorecardresearch.com","chartbeat.com","hotjar.com"] },
    "buzzfeed.com":    { ads: ["googlesyndication.com","criteo.com","taboola.com"],       trackers: ["google-analytics.com","segment.io","amplitude.com"] },
    "huffpost.com":    { ads: ["doubleclick.net","rubiconproject.com","outbrain.com"],    trackers: ["scorecardresearch.com","omtrdc.net","demdex.net"] },
    "default":         { ads: ["googlesyndication.com","doubleclick.net","adnxs.com","taboola.com"], trackers: ["google-analytics.com","googletagmanager.com","facebook.net","hotjar.com"] },
  },

  // ─── COSMETIC SELECTORS (DOM element hiding) ────────────────────────────────
  cosmeticSelectors: [
    "[id*='ad-']", "[class*='ad-']", "[id*='-ad']", "[class*='-ad']",
    "[id*='ads-']", "[class*='ads-']", "[id*='advert']", "[class*='advert']",
    "[id*='banner']", "[class*='banner']", "[id*='sponsor']", "[class*='sponsor']",
    "[class*='promo']", "[id*='promo']", "[class*='outbrain']", "[class*='taboola']",
    "iframe[src*='doubleclick']", "iframe[src*='adnxs']",
    "div[data-google-query-id]", ".adsbygoogle",
    "[class*='popup']", "[id*='popup']", "[class*='overlay']",
    "[class*='newsletter-modal']", "[class*='cookie-banner']",
  ],
};

/**
 * Checks a URL's domain against all blocklists
 * Returns { isBlocked, category, entry }
 */
window.checkDomain = function(urlString) {
  try {
    const hostname = new URL(urlString.startsWith('http') ? urlString : 'https://' + urlString).hostname.replace(/^www\./, '');
    const all = [
      ...BLOCKLIST.adNetworks.map(e => ({ ...e, category: 'ad' })),
      ...BLOCKLIST.trackers.map(e => ({ ...e, category: 'tracker' })),
      ...BLOCKLIST.fingerprinters.map(e => ({ ...e, category: 'fingerprinter' })),
    ];
    const match = all.find(e => hostname === e.domain || hostname.endsWith('.' + e.domain));
    return match ? { isBlocked: true, ...match } : { isBlocked: false };
  } catch { return { isBlocked: false }; }
};

/**
 * Gets the site profile for a given hostname
 */
window.getSiteProfile = function(hostname) {
  const clean = hostname.replace(/^www\./, '');
  return BLOCKLIST.siteProfiles[clean] || BLOCKLIST.siteProfiles['default'];
};
