// GPL receipt lookups. GPL has no JSON API: the receipt page is HTML, so we read the fields out of it.
const cheerio = require('cheerio');
const { httpErr } = require('./queries');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const txt = (s) => String(s || '').replace(/\s+/g, ' ').trim();
const money = (s) => { const n = Number(String(s || '').replace(/[^0-9.\-]/g, '')); return String(s || '').trim() && !isNaN(n) ? n : null; };

// Turns the receipt page into fields. Returns null when the page has no receipt on it.
function parseReceipt(html) {
  const $ = cheerio.load(html), r = $('#receipt');
  if (!r.length) return null;
  const head = {};
  $('.print\\:hidden h2').each((_, e) => { const t = txt($(e).text()), i = t.indexOf(':'); if (i > 0) head[t.slice(0, i).trim()] = t.slice(i + 1).trim(); });
  const rows = {};
  r.find('div.grid.grid-cols-2').each((_, e) => { const sp = $(e).children('span'); if (sp.length >= 2) rows[txt($(sp[0]).text()).replace(/:$/, '')] = txt($(sp[1]).text()); });
  const when = (r.text().match(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/) || [''])[0];
  let reference = '';
  r.find('span').each((_, e) => { if (/^Reference\s*#/i.test(txt($(e).text()))) reference = txt($(e).parent().find('span').eq(1).text()); });
  return {
    account: head.Account || rows.Account || '', name: head.Name || '', address1: head.Address_1 || '', address2: head.Address_2 || '', city: head.City || '', state: head.State || '',
    time: when, cashier: rows.Cashier || '', paymentMethod: rows['Payment Method'] || '', tariff: rows.Tariff || '', meter: rows.Meter || '',
    totalKwh: rows['Total kWh'] || '', energy: rows.Energy || '', fuel: rows.Fuel || '', taxRate: rows['Tax Rate'] || '', tax: rows.Tax || '',
    arrears: rows.Arrears || '', wallet: rows.Wallet || '', total: rows.Total || '', totalNumber: money(rows.Total), reference,
  };
}

class Gpl {
  // getAuth(env) -> { headers } saved from a pasted curl; saveAuth(env, headers) keeps a renewed cookie
  constructor(getAuth, saveAuth = async () => {}) { this.getAuth = getAuth; this.saveAuth = saveAuth; }

  async receipt(cfg, env, uuid, timeoutSec) {
    if (!UUID.test(uuid)) throw httpErr(400, 'That is not a valid UUID.');
    const e = cfg.envs[env];
    if (!e || !e.base) throw httpErr(503, `The GPL ${env.toUpperCase()} address is not set. Add it under Data Sources.`, 'no_gpl');
    const saved = await this.getAuth(env);
    if (!saved || !saved.headers || !Object.keys(saved.headers).length) throw httpErr(503, `No GPL login saved for ${env.toUpperCase()}. An admin needs to paste the GPL curl under Data Sources.`, 'no_credentials');
    const url = e.base.replace(/\/+$/, '') + (e.path || '/transactions/{uuid}/receipt').replace('{uuid}', encodeURIComponent(uuid.toLowerCase()));
    const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), Math.max(1, Number(timeoutSec) || 30) * 1000);
    try {
      const r = await fetch(url, { method: 'GET', redirect: 'manual', signal: ctl.signal, headers: { Accept: 'text/html,application/xhtml+xml', 'Accept-Language': 'en-US,en;q=0.9', 'User-Agent': 'Mozilla/5.0 (compatible; SupportHub)', ...saved.headers } });
      if ([301, 302, 303, 307, 308].includes(r.status) || r.status === 401 || r.status === 403) { await r.arrayBuffer().catch(() => {}); throw httpErr(502, `GPL rejected the saved login (${r.status}). An admin should paste a fresh GPL curl under Data Sources.`, 'auth_expired'); }
      if (r.status === 404) { await r.arrayBuffer().catch(() => {}); return null; }
      if (!r.ok) { await r.arrayBuffer().catch(() => {}); throw httpErr(502, `GPL answered ${r.status}.`, 'gpl_http'); }
      const buf = Buffer.from(await r.arrayBuffer()); if (buf.length > 3e6) throw httpErr(502, 'GPL sent back an unexpectedly large page.', 'gpl_http');
      await this._refresh(env, saved, r);
      return parseReceipt(buf.toString('utf8'));
    } catch (x) {
      if (x.name === 'AbortError') throw httpErr(504, `GPL did not answer within ${timeoutSec} seconds.`, 'timeout');
      if (x.status) throw x;
      throw httpErr(502, 'Could not reach GPL: ' + (x.cause && x.cause.code ? x.cause.code : x.message), 'unreachable');
    } finally { clearTimeout(timer); }
  }

  async _refresh(env, saved, r) {
    const ck = saved.headers.Cookie; if (!ck || !r.headers.getSetCookie) return;
    const fresh = {}; for (const x of r.headers.getSetCookie()) { const [kv] = x.split(';'), i = kv.indexOf('='); if (i > 0) fresh[kv.slice(0, i).trim()] = kv.slice(i + 1); }
    let changed = false;
    const next = ck.split(';').map((p) => { const i = p.indexOf('='), k = p.slice(0, i).trim(); if (k in fresh && fresh[k] !== p.slice(i + 1).trim()) { changed = true; return k + '=' + fresh[k]; } return p.trim(); }).join('; ');
    if (changed) await this.saveAuth(env, { ...saved.headers, Cookie: next }).catch(() => {});
  }
}

// Reads a pasted GPL curl: address, path (the UUID in it becomes {uuid}) and the login headers.
function parseGplCurl(text) {
  const um = String(text).match(/https?:\/\/[^\s'"\\]+/); if (!um) return { error: 'No URL found in that curl.' };
  let u; try { u = new URL(um[0]); } catch { return { error: 'The URL in that curl is not valid.' }; }
  const m = u.pathname.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
  if (!m) return { error: 'No UUID found in the curl address. Use a curl for one receipt, such as /transactions/<uuid>/receipt.' };
  return { base: u.origin, path: u.pathname.replace(m[0], '{uuid}'), sampleUuid: m[0].toLowerCase() };
}
module.exports = { Gpl, parseReceipt, parseGplCurl, UUID };
