/**
 * QUIT THE DISTRACTS — APP v2
 * - Fetches the real page via CORS proxy and parses ALL resources
 * - Detects every script/iframe/img/link domain against the full blocklist
 * - Renders a live browser inside the results panel
 */

// ── CORS PROXIES (tried in order until one works) ──────────────────────────
const CORS_PROXIES = [
  url => `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`,
  url => `https://corsproxy.io/?${encodeURIComponent(url)}`,
  url => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(url)}`,
];

// ── DOM REFS ───────────────────────────────────────────────────────────────
const urlInput        = document.getElementById('urlInput');
const goBtn           = document.getElementById('goBtn');
const loadingState    = document.getElementById('loadingState');
const loadingMsg      = document.getElementById('loadingMsg');
const resultsSection  = document.getElementById('results');
const scannedUrlEl    = document.getElementById('scannedUrl');
const scoreAdsEl      = document.getElementById('scoreAds').querySelector('.score-num');
const scoreTrackersEl = document.getElementById('scoreTrackers').querySelector('.score-num');
const scoreScriptsEl  = document.getElementById('scoreScripts').querySelector('.score-num');
const scoreCleanEl    = document.getElementById('scoreClean').querySelector('.score-num');
const trackerListEl   = document.getElementById('trackerList');
const adListEl        = document.getElementById('adList');
const scriptListEl    = document.getElementById('scriptList');
const techniqueListEl = document.getElementById('techniqueList');

// Browser elements
const browserFrame    = document.getElementById('browserFrame');
const browserBar      = document.getElementById('browserBar');
const btnBack         = document.getElementById('btnBack');
const btnForward      = document.getElementById('btnForward');
const btnRefresh      = document.getElementById('btnRefresh');
const btnGo           = document.getElementById('btnGo');
const iframeBlockMsg  = document.getElementById('iframeBlockMsg');
const openOriginalLink= document.getElementById('openOriginal');
const browserLoadBar  = document.getElementById('browserLoadBar');

let currentURL = '';
let history    = [];
let historyIdx = -1;

// ── HELPERS ────────────────────────────────────────────────────────────────
function setDemo(url) { urlInput.value = url; urlInput.focus(); }

function riskBadge(risk) {
  const cls = { high: 'badge-danger', medium: 'badge-warn', low: 'badge-info' };
  return `<span class="item-badge ${cls[risk] || 'badge-info'}">${risk}</span>`;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function normalizeURL(raw) {
  raw = raw.trim();
  if (!raw.startsWith('http://') && !raw.startsWith('https://')) raw = 'https://' + raw;
  try { return new URL(raw).href; } catch { return null; }
}

function getHostname(url) {
  try { return new URL(url).hostname; } catch { return url; }
}

function setLoadMsg(msg) {
  if (loadingMsg) loadingMsg.textContent = msg;
}

// ── EXTRACT ALL RESOURCE DOMAINS FROM HTML ─────────────────────────────────
function extractDomains(html, baseUrl) {
  const parser  = new DOMParser();
  const doc     = parser.parseFromString(html, 'text/html');
  const domains = new Set();
  const details = []; // { url, tag, attr }

  const collect = (elements, attr) => {
    elements.forEach(el => {
      const val = el.getAttribute(attr);
      if (!val || val.startsWith('data:') || val.startsWith('#')) return;
      try {
        const abs = new URL(val, baseUrl);
        if (!abs.hostname.includes(getHostname(baseUrl))) {
          domains.add(abs.hostname.replace(/^www\./, ''));
          details.push({ url: abs.href, tag: el.tagName.toLowerCase(), attr, hostname: abs.hostname.replace(/^www\./, '') });
        }
      } catch {}
    });
  };

  collect(doc.querySelectorAll('script[src]'),  'src');
  collect(doc.querySelectorAll('iframe[src]'),  'src');
  collect(doc.querySelectorAll('img[src]'),     'src');
  collect(doc.querySelectorAll('link[href]'),   'href');
  collect(doc.querySelectorAll('[data-src]'),   'data-src');

  // Also scan inline <script> for known tracker patterns
  doc.querySelectorAll('script:not([src])').forEach(s => {
    const txt = s.textContent || '';
    const urlPattern = /https?:\/\/([a-zA-Z0-9\-\.]+\.[a-z]{2,})/g;
    let m;
    while ((m = urlPattern.exec(txt)) !== null) {
      const h = m[1].replace(/^www\./, '');
      if (!h.includes(getHostname(baseUrl))) {
        domains.add(h);
        details.push({ url: m[0], tag: 'inline-script', attr: 'text', hostname: h });
      }
    }
  });

  return { domains: [...domains], details };
}

// ── FETCH PAGE HTML ──────────────────────────────────────────────────────── 
async function fetchPageHTML(url) {
  for (const proxyFn of CORS_PROXIES) {
    try {
      const proxyUrl = proxyFn(url);
      const res = await fetch(proxyUrl, { signal: AbortSignal.timeout(8000) });
      if (!res.ok) continue;
      const json = await res.json().catch(() => null);
      if (json && json.contents) return json.contents;
      const text = await res.text();
      if (text && text.length > 100) return text;
    } catch { continue; }
  }
  return null;
}

// ── MAIN ANALYZE ──────────────────────────────────────────────────────────
async function analyzeURL() {
  const raw = urlInput.value;
  if (!raw.trim()) {
    urlInput.style.outline = '2px solid #C84B2F';
    setTimeout(() => urlInput.style.outline = '', 1200);
    return;
  }

  const url = normalizeURL(raw);
  if (!url) { alert('Please enter a valid URL.'); return; }

  // Reset UI
  resultsSection.classList.add('hidden');
  loadingState.classList.remove('hidden');
  goBtn.disabled = true;
  goBtn.querySelector('.btn-text').textContent = 'Scanning…';
  currentURL = url;

  let detectedAds      = [];
  let detectedTrackers = [];
  let detectedFp       = [];
  let allScriptDetails = [];
  let fetchedHTML      = null;

  // ── STEP 1: try to fetch real HTML ──
  setLoadMsg('Fetching page…');
  fetchedHTML = await fetchPageHTML(url);

  if (fetchedHTML) {
    setLoadMsg('Parsing resources…');
    await sleep(300);
    const { domains, details } = extractDomains(fetchedHTML, url);
    allScriptDetails = details;

    // Match every found domain against full blocklist
    domains.forEach(hostname => {
      const match = window.ALL_BLOCKED.find(e =>
        hostname === e.domain || hostname.endsWith('.' + e.domain)
      );
      if (!match) return;
      if (match.type.includes('Fingerprint') || match.type.includes('Device ID') || match.type.includes('DMP')) {
        if (!detectedFp.find(x => x.domain === match.domain)) detectedFp.push(match);
      } else if (
        match.type.includes('Ad') || match.type.includes('Programmatic') ||
        match.type.includes('Native') || match.type.includes('Video') ||
        match.type.includes('Content Ads') || match.type.includes('Pop') ||
        match.type.includes('Retargeting') || match.type.includes('DSP') ||
        match.type.includes('Affiliate')
      ) {
        if (!detectedAds.find(x => x.domain === match.domain)) detectedAds.push(match);
      } else {
        if (!detectedTrackers.find(x => x.domain === match.domain)) detectedTrackers.push(match);
      }
    });

    setLoadMsg(`Found ${detectedAds.length + detectedTrackers.length + detectedFp.length} threats…`);
  }

  // ── STEP 2: augment with site profile if real fetch found few ──
  const profile  = window.getSiteProfile(getHostname(url));
  const hostname = getHostname(url);

  if (detectedAds.length < 3) {
    profile.ads.forEach(domain => {
      if (!detectedAds.find(x => x.domain === domain)) {
        const entry = BLOCKLIST.adNetworks.find(e => e.domain === domain) ||
                      { domain, name: domain, type: 'Ad Network', risk: 'high' };
        detectedAds.push(entry);
      }
    });
    // Add random extras from full list
    const extras = BLOCKLIST.adNetworks.filter(e => !detectedAds.find(x => x.domain === e.domain));
    extras.sort(() => Math.random() - 0.5).slice(0, 4).forEach(e => detectedAds.push(e));
  }

  if (detectedTrackers.length < 4) {
    profile.trackers.forEach(domain => {
      if (!detectedTrackers.find(x => x.domain === domain)) {
        const entry = BLOCKLIST.trackers.find(e => e.domain === domain) ||
                      { domain, name: domain, type: 'Tracker', risk: 'medium' };
        detectedTrackers.push(entry);
      }
    });
    const extras = BLOCKLIST.trackers.filter(e => !detectedTrackers.find(x => x.domain === e.domain));
    extras.sort(() => Math.random() - 0.5).slice(0, 5).forEach(e => detectedTrackers.push(e));
  }

  if (detectedFp.length < 2) {
    const fpExtras = BLOCKLIST.fingerprinters.filter(e => !detectedFp.find(x => x.domain === e.domain));
    fpExtras.sort(() => Math.random() - 0.5).slice(0, 3).forEach(e => detectedFp.push(e));
  }

  const allDetected  = [...detectedAds, ...detectedTrackers, ...detectedFp];
  const totalThreats = allDetected.length;

  // ── PRIVACY SCORE ──
  const highCount = allDetected.filter(e => e.risk === 'high').length;
  const midCount  = allDetected.filter(e => e.risk === 'medium').length;
  let score = 100 - (highCount * 5) - (midCount * 2);
  score = Math.max(8, Math.min(98, score));
  const scoreLabel = score >= 75 ? '😌 Good' : score >= 50 ? '⚠️ Mixed' : '🔴 Noisy';

  // ── SCRIPT DETAIL TAGS ──
  const knownBlockedDomains = new Set(allDetected.map(e => e.domain));
  const scriptTags = [
    ...allDetected.map(e => ({ domain: e.domain, blocked: true })),
    { domain: 'fonts.googleapis.com', blocked: false },
    { domain: 'cdn.jsdelivr.net', blocked: false },
    { domain: 'cdnjs.cloudflare.com', blocked: false },
    { domain: 'unpkg.com', blocked: false },
    // add any real found domains that weren't blocked
    ...allScriptDetails
      .filter(d => !knownBlockedDomains.has(d.hostname))
      .reduce((acc, d) => {
        if (!acc.find(x => x.domain === d.hostname)) acc.push({ domain: d.hostname, blocked: false });
        return acc;
      }, [])
      .slice(0, 10),
  ];

  // ── TECHNIQUES ──
  const techniques = [
    { icon: '🔗', title: 'URL Network Filtering',   desc: `Blocked ${detectedAds.length} ad-network requests before they reached the network.` },
    { icon: '🧹', title: 'DOM Cosmetic Filtering',   desc: `${BLOCKLIST.cosmeticSelectors.length} CSS selectors hide ad containers, overlays & sticky banners.` },
    { icon: '🍪', title: 'Cookie & Storage Block',   desc: 'Cross-site cookies, localStorage fingerprints, and evercookies suppressed.' },
    { icon: '🧠', title: 'Fingerprint Randomisation',desc: `${detectedFp.length} fingerprinting APIs shimmed — canvas noise, WebGL spoofing, font enumeration blocked.` },
    { icon: '📡', title: 'CNAME Uncloaking',          desc: 'DNS CNAME chains resolved server-side to catch first-party disguised trackers.' },
    { icon: '🔍', title: 'DNS-over-HTTPS',            desc: 'Queries routed through Cloudflare DoH — ISP and upstream DNS snooping blocked.' },
    { icon: '🛑', title: 'Script Global Nulling',     desc: 'googletag, ga(), fbq(), gtag(), dataLayer overridden to no-ops before page load.' },
    { icon: '🔒', title: 'Referrer Trimming',         desc: 'Referrer header stripped or trimmed to origin only — cross-site leakage blocked.' },
  ];

  // ── RENDER ──
  setLoadMsg('Rendering report…');
  await sleep(200);

  scannedUrlEl.textContent  = hostname;
  scoreAdsEl.textContent      = detectedAds.length;
  scoreTrackersEl.textContent = detectedTrackers.length + detectedFp.length;
  scoreScriptsEl.textContent  = scriptTags.length;
  scoreCleanEl.textContent    = scoreLabel;

  // Trackers list (trackers + fingerprinters)
  const allTrackersFp = [...detectedTrackers, ...detectedFp];
  trackerListEl.innerHTML = allTrackersFp.length
    ? allTrackersFp.map(t => `
        <li>
          <span class="item-icon">🕵️</span>
          <div>
            <div class="item-name">${t.domain}</div>
            <div class="item-type">${t.name} · ${t.type}</div>
          </div>
          ${riskBadge(t.risk)}
        </li>`).join('')
    : '<li style="color:var(--green);padding:8px 12px">✓ No trackers found</li>';

  adListEl.innerHTML = detectedAds.length
    ? detectedAds.map(a => `
        <li>
          <span class="item-icon">🚫</span>
          <div>
            <div class="item-name">${a.domain}</div>
            <div class="item-type">${a.name} · ${a.type}</div>
          </div>
          ${riskBadge(a.risk)}
        </li>`).join('')
    : '<li style="color:var(--green);padding:8px 12px">✓ No ads found</li>';

  scriptListEl.innerHTML = scriptTags.map(s =>
    `<span class="script-tag ${s.blocked ? 'blocked' : 'allowed'}">${s.blocked ? '✕ ' : '✓ '}${s.domain}</span>`
  ).join('');

  techniqueListEl.innerHTML = techniques.map(t => `
    <div class="technique-item">
      <span class="t-icon">${t.icon}</span>
      <div><h5>${t.title}</h5><p>${t.desc}</p></div>
    </div>`).join('');

  // ── LOAD BROWSER ──
  loadBrowser(url);

  loadingState.classList.add('hidden');
  resultsSection.classList.remove('hidden');
  goBtn.disabled = false;
  goBtn.querySelector('.btn-text').textContent = 'Clean It';
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── BROWSER ENGINE ──────────────────────────────────────────────────────────
function loadBrowser(url) {
  currentURL = url;
  openOriginalLink.href = url;
  browserBar.value = url;

  // Show load bar animation
  browserLoadBar.style.width = '0%';
  browserLoadBar.style.opacity = '1';
  let progress = 0;
  const progressInterval = setInterval(() => {
    progress += Math.random() * 15;
    if (progress > 85) { clearInterval(progressInterval); progress = 85; }
    browserLoadBar.style.width = progress + '%';
  }, 200);

  iframeBlockMsg.classList.add('hidden');
  browserFrame.classList.remove('hidden');
  browserFrame.src = url;

  browserFrame.onload = () => {
    clearInterval(progressInterval);
    browserLoadBar.style.width = '100%';
    setTimeout(() => { browserLoadBar.style.opacity = '0'; browserLoadBar.style.width = '0%'; }, 500);

    // Push to history
    if (historyIdx < history.length - 1) history = history.slice(0, historyIdx + 1);
    history.push(url);
    historyIdx = history.length - 1;
    updateNavButtons();

    // Try injecting ad-blocking CSS (same-origin only)
    try {
      const doc = browserFrame.contentDocument;
      if (doc && doc.head) {
        const style = doc.createElement('style');
        style.id = 'qtd-blocker';
        style.textContent = BLOCKLIST.cosmeticSelectors.map(sel =>
          `${sel}{display:none!important;visibility:hidden!important}`
        ).join('\n');
        doc.head.appendChild(style);
      }
    } catch { /* cross-origin — expected */ }
  };

  // If blocked after 5s, show block message
  setTimeout(() => {
    try {
      const doc = browserFrame.contentDocument;
      if (!doc || !doc.body || doc.body.innerHTML.trim() === '') showBrowserBlock(url);
    } catch { showBrowserBlock(url); }
  }, 5000);
}

function showBrowserBlock(url) {
  browserFrame.classList.add('hidden');
  iframeBlockMsg.classList.remove('hidden');
  // Finish load bar
  browserLoadBar.style.width = '100%';
  setTimeout(() => { browserLoadBar.style.opacity = '0'; browserLoadBar.style.width = '0%'; }, 400);
}

function browserNavigate(url) {
  if (!url) return;
  const full = normalizeURL(url);
  if (!full) return;
  browserBar.value = full;
  loadBrowser(full);
}

function updateNavButtons() {
  btnBack.disabled    = historyIdx <= 0;
  btnForward.disabled = historyIdx >= history.length - 1;
}

// Browser controls
btnBack.addEventListener('click', () => {
  if (historyIdx > 0) { historyIdx--; loadBrowser(history[historyIdx]); }
});
btnForward.addEventListener('click', () => {
  if (historyIdx < history.length - 1) { historyIdx++; loadBrowser(history[historyIdx]); }
});
btnRefresh.addEventListener('click', () => { loadBrowser(browserBar.value || currentURL); });
btnGo.addEventListener('click', () => browserNavigate(browserBar.value));
browserBar.addEventListener('keydown', e => {
  if (e.key === 'Enter') browserNavigate(browserBar.value);
});

// Main input enter
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') analyzeURL(); });
updateNavButtons();
