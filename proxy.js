/**
 * QUIT THE DISTRACTS — SERVER-SIDE PROXY
 * ========================================
 * Deploy to Cloudflare Workers or Vercel Edge Functions.
 * This proxy fetches any URL server-side, strips ad/tracker scripts,
 * removes ad DOM elements via injected CSS, and returns cleaned HTML.
 *
 * ── DEPLOY TO CLOUDFLARE WORKERS ──────────────────────────────────────────
 * 1. Install Wrangler: npm install -g wrangler
 * 2. wrangler login
 * 3. wrangler init quit-distracts-proxy
 * 4. Replace the generated worker with this file
 * 5. wrangler deploy
 * 6. Set PROXY_URL in app.js to: "https://quit-distracts-proxy.YOUR-NAME.workers.dev/proxy?url="
 *
 * ── DEPLOY TO VERCEL EDGE ─────────────────────────────────────────────────
 * 1. Save as /api/proxy.js in your Next.js or Vercel project
 * 2. vercel deploy
 * 3. Set PROXY_URL in app.js to: "https://your-project.vercel.app/api/proxy?url="
 */

// ─── AD/TRACKER DOMAINS TO STRIP FROM FETCHED HTML ───────────────────────────
const BLOCKED_DOMAINS = [
  "doubleclick.net", "googlesyndication.com", "googleadservices.com",
  "adnxs.com", "moatads.com", "taboola.com", "outbrain.com",
  "criteo.com", "criteo.net", "rubiconproject.com", "pubmatic.com",
  "openx.net", "advertising.com", "media.net", "adroll.com",
  "amazon-adsystem.com", "smartadserver.com", "triplelift.com",
  "indexexchange.com", "sharethrough.com", "bidswitch.net",
  "google-analytics.com", "googletagmanager.com", "facebook.net",
  "connect.facebook.net", "hotjar.com", "mouseflow.com",
  "fullstory.com", "segment.io", "mixpanel.com", "amplitude.com",
  "quantserve.com", "scorecardresearch.com", "chartbeat.com",
  "omtrdc.net", "demdex.net", "bluekai.com", "addthis.com",
  "sharethis.com", "fingerprintjs.com",
];

// ─── COSMETIC SELECTORS TO HIDE ───────────────────────────────────────────────
const COSMETIC_CSS = `
  [id*='ad-'],[class*='ad-'],[id*='-ad'],[class*='-ad'],
  [id*='ads-'],[class*='ads-'],[id*='advert'],[class*='advert'],
  [id*='banner'],[class*='banner'],[id*='sponsor'],[class*='sponsor'],
  [class*='promo'],[id*='promo'],[class*='outbrain'],[class*='taboola'],
  iframe[src*='doubleclick'],iframe[src*='adnxs'],div[data-google-query-id],
  .adsbygoogle,[class*='popup'],[id*='popup'] {
    display: none !important;
    visibility: hidden !important;
  }
`;

// ─── SCRIPT OVERRIDE TO NULL AD GLOBALS ──────────────────────────────────────
const BLOCKER_SCRIPT = `
<script>
  window.googletag = { cmd:{push:function(){}}, pubads:function(){return{refresh:function(){},enableSingleRequest:function(){},collapseEmptyDivs:function(){}};}, defineSlot:function(){return{addService:function(){return this;}};}, display:function(){}, enableServices:function(){} };
  window.ga = function(){};
  window.fbq = function(){};
  window._fbq = window.fbq;
  window.dataLayer = [];
  window.gtag = function(){};
  window._gaq = {push:function(){}};
  document.write = function(){};
  document.writeln = function(){};
<\/script>
<style>${COSMETIC_CSS}</style>
`;

/**
 * Strip blocked domains from HTML
 * Removes <script src="blocked-domain">, <img src="blocked-domain">, etc.
 */
function stripBlockedContent(html, baseUrl) {
  let cleaned = html;

  for (const domain of BLOCKED_DOMAINS) {
    // Remove script tags loading from blocked domains
    const scriptRegex = new RegExp(`<script[^>]*src=["'][^"']*${domain.replace('.', '\\.')}[^"']*["'][^>]*>.*?<\\/script>`, 'gis');
    cleaned = cleaned.replace(scriptRegex, '<!-- [BLOCKED: ' + domain + '] -->');

    // Remove iframes from blocked domains
    const iframeRegex = new RegExp(`<iframe[^>]*src=["'][^"']*${domain.replace('.', '\\.')}[^"']*["'][^>]*>.*?<\\/iframe>`, 'gis');
    cleaned = cleaned.replace(iframeRegex, '');

    // Remove img tags from blocked domains
    const imgRegex = new RegExp(`<img[^>]*src=["'][^"']*${domain.replace('.', '\\.')}[^"']*["'][^>]*>`, 'gi');
    cleaned = cleaned.replace(imgRegex, '');
  }

  // Inject blocker script right after <head>
  cleaned = cleaned.replace(/<head>/i, '<head>' + BLOCKER_SCRIPT);
  // Also inject base tag so relative URLs resolve
  cleaned = cleaned.replace(/<head>/i, `<head><base href="${baseUrl}">`);

  return cleaned;
}

// ─── CLOUDFLARE WORKERS HANDLER ───────────────────────────────────────────────
export default {
  async fetch(request) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET',
          'Access-Control-Allow-Headers': 'Content-Type',
        }
      });
    }

    if (url.pathname !== '/proxy') {
      return new Response('Quit the Distracts Proxy. Use /proxy?url=https://example.com', { status: 200 });
    }

    const targetUrl = url.searchParams.get('url');
    if (!targetUrl) {
      return new Response(JSON.stringify({ error: 'Missing url parameter' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      const parsed = new URL(targetUrl);
      const baseUrl = parsed.origin;

      const response = await fetch(targetUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
        },
        redirect: 'follow',
      });

      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('text/html')) {
        return Response.redirect(targetUrl, 302);
      }

      const originalHtml = await response.text();
      const cleanedHtml  = stripBlockedContent(originalHtml, baseUrl);

      return new Response(cleanedHtml, {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
          // Remove X-Frame-Options so our iframe can load it
          'X-Frame-Options': 'ALLOWALL',
          'Content-Security-Policy': '',
          'Cache-Control': 'no-store',
        }
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }
  }
};

/*
 * ─── VERCEL EDGE FUNCTION ALTERNATIVE ────────────────────────────────────────
 * Save as /api/proxy.js and export the following:
 *
 * export const config = { runtime: 'edge' };
 *
 * export default async function handler(req) {
 *   // ... same logic as the fetch() handler above ...
 * }
 */
