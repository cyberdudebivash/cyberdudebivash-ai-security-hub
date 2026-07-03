// Visual-regression harness for the global UX upgrade.
// Serves frontend/ statically and screenshots a representative page sample at
// desktop + mobile widths. Run with a label arg: `node ux-screenshot.mjs before|after`.
import { chromium } from 'playwright-core';
import http from 'node:http';
import { readFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';

const ROOT  = path.resolve(process.cwd(), 'frontend');
const LABEL = process.argv[2] || 'shot';
const OUT   = path.resolve('/tmp/claude-0/-home-user-cyberdudebivash-ai-security-hub/eadfba02-402a-5bc7-8563-02d9330dd8b5/scratchpad/uxshots');
const CHROME = '/opt/pw-browsers/chromium-1194/chrome-linux/chrome';

// Representative sample: homepage, a heavy dashboard, marketing, a page that
// currently has NEITHER shared sheet (biggest delta), pricing/scan, compliance.
const PAGES = [
  'index.html', 'user-dashboard.html', 'about.html', 'services.html',
  'ai-security.html', 'ciso-hub.html', 'pricing' in {} ? '' : 'contact.html',
].filter(Boolean);

const MIME = { '.html':'text/html', '.css':'text/css', '.js':'text/javascript',
  '.png':'image/png', '.jpg':'image/jpeg', '.svg':'image/svg+xml', '.json':'application/json',
  '.woff2':'font/woff2', '.ico':'image/x-icon' };

const server = http.createServer(async (req, res) => {
  try {
    let p = decodeURIComponent(req.url.split('?')[0]);
    if (p === '/') p = '/index.html';
    const fp = path.join(ROOT, p);
    if (!fp.startsWith(ROOT) || !existsSync(fp)) { res.writeHead(404); return res.end('nf'); }
    const buf = await readFile(fp);
    res.writeHead(200, { 'Content-Type': MIME[path.extname(fp)] || 'application/octet-stream' });
    res.end(buf);
  } catch { res.writeHead(500); res.end('err'); }
});

await new Promise(r => server.listen(0, r));
const port = server.address().port;
await mkdir(OUT, { recursive: true });

const browser = await chromium.launch({ executablePath: CHROME, args: ['--no-sandbox'] });
const viewports = [{ name: 'desktop', width: 1440, height: 900 }, { name: 'mobile', width: 390, height: 844 }];
let n = 0;
for (const page of PAGES) {
  for (const vp of viewports) {
    const ctx = await browser.newContext({ viewport: { width: vp.width, height: vp.height }, deviceScaleFactor: 1 });
    const pg = await ctx.newPage();
    // Silence blocked API calls quickly; we only care about the static shell.
    pg.on('pageerror', () => {});
    try {
      await pg.goto(`http://localhost:${port}/${page}`, { waitUntil: 'domcontentloaded', timeout: 15000 });
      await pg.waitForTimeout(1200); // let CSS + fonts settle
      const file = path.join(OUT, `${page.replace('.html','')}__${vp.name}__${LABEL}.png`);
      await pg.screenshot({ path: file, fullPage: false }); // above-the-fold is enough for layout regressions
      n++;
    } catch (e) { console.log(`  ! ${page} ${vp.name}: ${e.message}`); }
    await ctx.close();
  }
}
await browser.close();
server.close();
console.log(`[${LABEL}] captured ${n} screenshots → ${OUT}`);
