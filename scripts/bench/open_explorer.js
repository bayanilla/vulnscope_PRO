const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch(); const p = await b.newPage();
  const errs = []; p.on('pageerror', e => errs.push(String(e).slice(0,200))); p.on('crash', () => errs.push('PAGE CRASHED'));
  const t = Date.now();
  try { await p.goto('file://' + process.argv[2], { timeout: 240000, waitUntil: 'load' });
        console.log('loaded in', (Date.now()-t)/1000, 's'); }
  catch (e) { console.log('failed after', (Date.now()-t)/1000, 's:', String(e).slice(0,200)); }
  console.log('errors', errs); await b.close();
})();
