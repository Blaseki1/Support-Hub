const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { httpErr } = require('./queries');

const COOKIE = 'hub_sid';
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
let pepper = (s) => s;
const setPepper = (fn) => { pepper = fn; };
const hash = (pw) => bcrypt.hash(pepper(pw), 11);
const check = (pw, h) => bcrypt.compare(pepper(pw), h);
const tempPassword = () => { const a = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let s = ''; for (const b of crypto.randomBytes(12)) s += a[b % a.length]; return s; };
const validPassword = (p) => { if (typeof p !== 'string' || p.length < 10) throw httpErr(400, 'Use at least 10 characters.'); if (p.length > 200) throw httpErr(400, 'That password is too long.'); };

function readCookie(req, name) {
  const h = req.headers.cookie || '';
  for (const part of h.split(';')) { const i = part.indexOf('='); if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim()); }
  return '';
}
function setCookie(res, token, cfg, maxAgeSec) {
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${cfg.secureCookie ? '; Secure' : ''}`);
}
const device = (ua) => {
  ua = ua || ''; const b = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const o = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : '';
  return o ? `${b} on ${o}` : b;
};

// Failed logins per email+ip: 5 misses lock that pair for 15 minutes.
function limiter() {
  const m = new Map();
  return {
    blocked(k) { const e = m.get(k); if (!e) return 0; if (e.until && e.until > Date.now()) return Math.ceil((e.until - Date.now()) / 60000); if (e.until) m.delete(k); return 0; },
    fail(k) { const e = m.get(k) || { n: 0 }; e.n++; if (e.n >= 5) { e.until = Date.now() + 15 * 60000; e.n = 0; } m.set(k, e); },
    ok(k) { m.delete(k); },
  };
}
module.exports = { setPepper, COOKIE, sha, hash, check, tempPassword, validPassword, readCookie, setCookie, device, limiter };
