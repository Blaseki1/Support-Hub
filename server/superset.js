// Talks to Superset. Signs in with a service account (best), or uses a token / cookie from the environment.
const { httpErr } = require('./queries');

class Superset {
  // getAuth(env) returns the headers saved from a pasted curl (or null). creds is an optional service account fallback.
  constructor(creds = {}, getAuth = async () => null, saveAuth = async () => {}) { this.creds = creds; this.getAuth = getAuth; this.saveAuth = saveAuth; this.sessions = {}; }

  async _login(base, env) {
    const saved = await this.getAuth(env);
    if (saved && Object.keys(saved.headers || {}).length) return { headers: { ...saved.headers }, static: true, curl: true, env };
    const c = this.creds[env] || {};
    if (c.token || c.cookie) return { headers: { ...(c.token ? { Authorization: 'Bearer ' + c.token } : {}), ...(c.cookie ? { Cookie: c.cookie } : {}) }, static: true };
    if (!c.user || !c.pass) throw httpErr(503, `No Superset login saved for ${env.toUpperCase()}. An admin needs to paste a curl under Data Sources.`, 'no_credentials');
    const jar = new Map();
    const eat = (res) => { for (const x of (res.headers.getSetCookie ? res.headers.getSetCookie() : [])) { const [kv] = x.split(';'); const i = kv.indexOf('='); jar.set(kv.slice(0, i), kv.slice(i + 1)); } };
    const cookie = () => [...jar].map(([k, v]) => k + '=' + v).join('; ');
    const r = await fetch(base + '/api/v1/security/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: c.user, password: c.pass, provider: 'db', refresh: true }) });
    if (!r.ok) throw httpErr(502, `Superset refused the service account login (${r.status}).`, 'superset_login');
    eat(r);
    const { access_token: token } = await r.json();
    const cr = await fetch(base + '/api/v1/security/csrf_token/', { headers: { Authorization: 'Bearer ' + token, Cookie: cookie() } });
    eat(cr);
    const csrf = cr.ok ? (await cr.json()).result : null;
    return { headers: { Authorization: 'Bearer ' + token, ...(csrf ? { 'X-CSRFToken': csrf } : {}), Cookie: cookie() } };
  }

  async _session(base, env, fresh) {
    const k = base + '|' + env;
    if (fresh || !this.sessions[k]) this.sessions[k] = await this._login(base, env);
    return this.sessions[k];
  }
  reset() { this.sessions = {}; }

  // Superset hands out a renewed session cookie as you use it. Keep the newest one so the saved login lasts longer.
  async _refresh(s, r) {
    if (!s.curl || !s.headers.Cookie || !r.headers.getSetCookie) return;
    const fresh = {}; for (const x of r.headers.getSetCookie()) { const [kv] = x.split(';'); const i = kv.indexOf('='); if (i > 0) fresh[kv.slice(0, i).trim()] = kv.slice(i + 1); }
    let changed = false;
    const next = s.headers.Cookie.split(';').map((p) => { const i = p.indexOf('='), k = p.slice(0, i).trim(); if (k in fresh && fresh[k] !== p.slice(i + 1).trim()) { changed = true; return k + '=' + fresh[k]; } return p.trim(); }).join('; ');
    if (changed) { s.headers.Cookie = next; await this.saveAuth(s.env, { ...s.headers }).catch(() => {}); }
  }

  // Runs one chart/data request. Throws code 'timeout' if Superset does not answer within timeoutSec.
  async query(base, endpoint, env, body, timeoutSec, ctx = {}) {
    const url = base.replace(/\/+$/, '') + endpoint + (ctx.qs || '');
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), Math.max(1, Number(timeoutSec) || 60) * 1000);
    try {
      for (let attempt = 0; attempt < 2; attempt++) {
        const s = await this._session(base.replace(/\/+$/, ''), env, attempt > 0 && !(this.sessions[base.replace(/\/+$/, '') + '|' + env] || {}).static);
        const root = base.replace(/\/+$/, '');
        const headers = { Accept: 'application/json', 'Accept-Language': 'en-US,en;q=0.9', 'Content-Type': 'application/json', Origin: root,
          Referer: ctx.dashboard ? `${root}/superset/dashboard/${ctx.dashboard}/` : root + '/', 'User-Agent': 'Mozilla/5.0 (compatible; SupportHub)', ...s.headers };
        const r = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body), signal: ctl.signal });
        if ([400, 401, 403].includes(r.status) && !s.static && attempt === 0) { await r.arrayBuffer().catch(() => {}); continue; }
        if (r.status === 401 || (r.status === 403 && s.curl) || (r.status === 400 && s.curl)) {
          await r.arrayBuffer().catch(() => {});
          throw httpErr(502, s.curl ? `Superset rejected the saved login (${r.status}). It has probably expired. An admin should paste a fresh curl under Data Sources.` : `Superset rejected the login (${r.status}).`, 'auth_expired');
        }
        if (!r.ok) { const t = (await r.text().catch(() => '')).slice(0, 200); throw httpErr(502, `Superset answered ${r.status}.${t ? ' ' + t : ''}`, 'superset_http'); }
        await this._refresh(s, r);
        const ct = r.headers.get('content-type') || '';
        if (!ct.includes('json')) { await r.arrayBuffer().catch(() => {}); throw httpErr(502, s.curl ? 'Superset sent back a page instead of data. The saved login has probably expired. An admin should paste a fresh curl under Data Sources.' : 'Superset did not return data.', s.curl ? 'auth_expired' : 'superset_http'); }
        return await r.json();
      }
    } catch (e) {
      if (e.name === 'AbortError') throw httpErr(504, `Superset did not answer within ${timeoutSec} seconds.`, 'timeout');
      if (e.status) throw e;
      throw httpErr(502, 'Could not reach Superset: ' + (e.cause && e.cause.code ? e.cause.code : e.message), 'unreachable');
    } finally { clearTimeout(timer); }
  }
}
module.exports = { Superset };
