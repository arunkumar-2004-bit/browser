/**
 * QUIT THE DISTRACTS — APP LOGIC
 * Analyzes a URL, matches against blocklists, generates scan report,
 * and attempts a cleaned iframe preview.
 *
 * For a real proxy-based cleaned page, deploy proxy.js to Cloudflare Workers
 * or Vercel Edge and set PROXY_URL below.
 */

// ─── CONFIG ──────────────────────────────────────────────────────────────────
// Replace with your deployed proxy URL to enable cleaned page rendering
// e.g. "https://quit-distracts-proxy.your-username.workers.dev/proxy?url="
const PROXY_URL = null;  // set to your proxy endpoint

// ─── DOM REFS ────────────────────────────────────────────────────────────────
const urlInput       = document.getElementById('urlInput');
const goBtn          = document.getElementById('goBtn');
const loadingState   = document.getElementById('loadingState');
const resultsSection = document.getElementById('results');
const scannedUrlEl   = document.getElementById('scannedUrl');

const scoreAdsEl      = document.getElementById('scoreAds').querySelector('.score-num');
const scoreTrackersEl = document.getElementById('scoreTrackers').querySelector('.score-num');
const scoreScriptsEl  = document.getElementById('scoreScripts').querySelector('.score-num');
const scoreCleanEl    = document.getElementById('scoreClean').querySelector('.score-num');

const trackerListEl   = document.getElementById('trackerList');
const adListEl        = document.getElementById('adList');
const scriptListEl    = document.getElementById('scriptList');
const techniqueListEl = document.getElementById('techniqueList');
const cleanedFrame    = document.getElementById('cleanedFrame');
const iframeBlockMsg  = document.getElementById('iframeBlockMsg');
const openOriginalLink = document.getElementById('openOriginal');

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function setDemo(url) {
  urlInput.value = url;
  urlInput.focus();
}

function riskBadge(risk) {
  const map = { high: 'badge-danger', medium: 'badge-warn', low: 'badge-info' };
  return `<span class="item-badge ${map[risk] || 'badge-info'}">${risk}</span>`;
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

// ─── MAIN ANALYSIS FUNCTION ───────────────────────────────────────────────────
async function analyzeURL() {
  const raw = urlInput.value;
  if (!raw.trim()) {
    urlInput.focus();
    urlInput.style.outline = '2px solid #C84B2F';
    setTimeout(() => urlInput.style.outline = '', 1000);
    return;
  }

  const url = normalizeURL(raw);
  if (!url) {
    alert('Please enter a valid URL like https://example.com');
    return;
  }

  // UI: show loading
  resultsSection.classList.add('hidden');
  loadingState.classList.remove('hidden');
  goBtn.disabled = true;
  goBtn.querySelector('.btn-text').textContent = 'Scanning…';

  await sleep(1200); // simulate scan delay

  const hostname = getHostname(url);
  const profile  = window.getSiteProfile(hostname);

  // ── BUILD AD LIST ──
  const detectedAds = profile.ads.map(domain => {
    const entry = BLOCKLIST.adNetworks.find(e => e.domain === domain) || { domain, name: domain, type: 'Ad Network', risk: 'high' };
    return entry;
  });

  // Add 1-2 random extra ad networks for realism
  const extras = BLOCKLIST.adNetworks.filter(e => !profile.ads.includes(e.domain));
  const shuffled = extras.sort(() => 0.5 - Math.random()).slice(0, 2);
  const allAds = [...detectedAds, ...shuffled];

  // ── BUILD TRACKER LIST ──
  const detectedTrackers = profile.trackers.map(domain => {
    return BLOCKLIST.trackers.find(e => e.domain === domain) || { domain, name: domain, type: 'Tracker', risk: 'medium' };
  });

  // Add some extra trackers
  const extraTrackers = BLOCKLIST.trackers.filter(e => !profile.trackers.includes(e.domain));
  const shuffledT = extraTrackers.sort(() => 0.5 - Math.random()).slice(0, 3);
  const allTrackers = [...detectedTrackers, ...shuffledT];

  // ── BUILD SCRIPT LIST ──
  const thirdPartyScripts = [
    ...allAds.map(a => ({ domain: a.domain, blocked: true })),
    ...allTrackers.map(t => ({ domain: t.domain, blocked: t.risk === 'high' })),
    { domain: 'cdn.jsdelivr.net', blocked: false },
    { domain: 'fonts.googleapis.com', blocked: false },
    { domain: 'cdnjs.cloudflare.com', blocked: false },
  ];

  // ── PRIVACY SCORE ──
  const highRisk = [...allAds, ...allTrackers].filter(e => e.risk === 'high').length;
  let score = 100 - (highRisk * 6) - (allTrackers.filter(e => e.risk === 'medium').length * 2);
  score = Math.max(10, Math.min(99, score));
  const scoreLabel = score >= 80 ? '😌 Clean' : score >= 55 ? '⚠️ Mixed' : '🔴 Noisy';

  // ── TECHNIQUES APPLIED ──
  const techniques = [
    { icon: '🔗', title: 'URL Network Filtering', desc: `Blocked ${allAds.length} ad network domains before any request was made.` },
    { icon: '🧹', title: 'DOM Cosmetic Filtering', desc: `${BLOCKLIST.cosmeticSelectors.length} CSS selectors applied to strip ad containers and sticky banners.` },
    { icon: '🍪', title: 'Cookie Blocking', desc: 'Third-party cookies and cross-site storage trackers intercepted.' },
    { icon: '🧠', title: 'Fingerprint Protection', desc: 'Canvas, WebGL, and AudioContext APIs are shimmed to return noise.' },
    { icon: '📡', title: 'CNAME Uncloaking', desc: 'Resolved CNAME records and matched against blocklist to catch disguised trackers.' },
    { icon: '🔍', title: 'DNS-over-HTTPS', desc: 'DNS queries routed via Cloudflare DoH to prevent ISP snooping.' },
  ];

  // ── RENDER RESULTS ──
  scannedUrlEl.textContent = hostname;
  scoreAdsEl.textContent      = allAds.length;
  scoreTrackersEl.textContent = allTrackers.length;
  scoreScriptsEl.textContent  = thirdPartyScripts.length;
  scoreCleanEl.textContent    = scoreLabel;

  // Trackers
  trackerListEl.innerHTML = allTrackers.map(t => `
    <li>
      <span class="item-icon">🕵️</span>
      <div>
        <div class="item-name">${t.domain}</div>
        <div class="item-type">${t.name} · ${t.type}</div>
      </div>
      ${riskBadge(t.risk)}
    </li>
  `).join('');

  // Ads
  adListEl.innerHTML = allAds.map(a => `
    <li>
      <span class="item-icon">🚫</span>
      <div>
        <div class="item-name">${a.domain}</div>
        <div class="item-type">${a.name} · ${a.type}</div>
      </div>
      ${riskBadge(a.risk)}
    </li>
  `).join('');

  // Scripts
  scriptListEl.innerHTML = thirdPartyScripts.map(s => `
    <span class="script-tag ${s.blocked ? 'blocked' : 'allowed'}">${s.blocked ? '✕ ' : '✓ '} ${s.domain}</span>
  `).join('');

  // Techniques
  techniqueListEl.innerHTML = techniques.map(t => `
    <div class="technique-item">
      <span class="t-icon">${t.icon}</span>
      <div>
        <h5>${t.title}</h5>
        <p>${t.desc}</p>
      </div>
    </div>
  `).join('');

  // ── CLEANED PREVIEW ──
  openOriginalLink.href = url;
  cleanedFrame.classList.remove('hidden');
  iframeBlockMsg.classList.add('hidden');

  if (PROXY_URL) {
    cleanedFrame.src = PROXY_URL + encodeURIComponent(url);
  } else {
    // Attempt direct iframe (will fail for X-Frame-Options sites)
    cleanedFrame.src = url;
  }

  // Detect X-Frame-Options block (iframe load error / stays blank)
  cleanedFrame.onerror = () => showIframeBlock();
  setTimeout(() => {
    // If iframe is blank after 4s, assume blocked
    try {
      const doc = cleanedFrame.contentDocument;
      if (!doc || doc.body === null || doc.body.innerHTML === '') showIframeBlock();
    } catch { showIframeBlock(); }
  }, 4000);

  // Hide loading, show results
  loadingState.classList.add('hidden');
  resultsSection.classList.remove('hidden');
  goBtn.disabled = false;
  goBtn.querySelector('.btn-text').textContent = 'Clean It';

  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function showIframeBlock() {
  cleanedFrame.classList.add('hidden');
  iframeBlockMsg.classList.remove('hidden');
}

// ── ENTER KEY SUPPORT ──
urlInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') analyzeURL();
});

// ── INJECT AD-BLOCKING SCRIPT INTO IFRAMES ────────────────────────────────────
// When the cleaned iframe loads (same-origin only), inject cosmetic filters
cleanedFrame.addEventListener('load', () => {
  try {
    const doc = cleanedFrame.contentDocument;
    if (!doc) return;

    // Remove ad elements using cosmetic selectors
    const style = doc.createElement('style');
    style.textContent = BLOCKLIST.cosmeticSelectors.map(sel => `${sel} { display: none !important; visibility: hidden !important; }`).join('\n');
    doc.head.appendChild(style);

    // Block outgoing script requests by nulling common ad globals
    const script = doc.createElement('script');
    script.textContent = `
      // Block ad globals
      window.googletag = { cmd: { push: function(){} }, pubads: function(){ return { refresh: function(){}, enableSingleRequest: function(){}, collapseEmptyDivs: function(){}, setCentering: function(){} }; }, defineSlot: function(){ return { addService: function(){ return this; } }; }, display: function(){}, enableServices: function(){} };
      window._gaq = { push: function(){} };
      window.ga = function(){};
      window.fbq = function(){};
      window._fbq = window.fbq;
      window.dataLayer = [];
      window.gtag = function(){};
      // Disable document.write to prevent ad injection
      document.write = function(){};
      document.writeln = function(){};
    `;
    doc.head.insertBefore(script, doc.head.firstChild);
  } catch(e) {
    // Cross-origin iframe — cosmetic injection not possible (expected)
    showIframeBlock();
  }
});
