const express = require('express');
const crypto = require('crypto');
const path = require('path');
const A = require('./auth');
const D = require('./defaults');
const Q = require('./queries');
const { buildWorkbook } = require('./xlsx');
const { parseGplCurl, UUID } = require('./gpl');
const S3 = require('./s3');
const { httpErr } = Q;

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const MON = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const stamp = (d) => { d = new Date(d); return `${d.getDate()} ${MON[d.getMonth()]} ${d.toTimeString().slice(0, 5)}`; };
const maskId = (v) => { v = String(v); return v.length <= 3 ? '***' : '•'.repeat(v.length - 3) + v.slice(-3); };
const clip = (s, n = 300) => String(s == null ? '' : s).replace(/[\r\n\t]+/g, ' ').slice(0, n);

function createApp({ store, superset, config, gpl, s3 }) {
  const app = express();
  if (config.trustProxy) app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(express.json({ limit: '256kb' }));
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'no-referrer');
    if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
    next();
  });
  // CSRF guard: every change must carry a header a cross-site form cannot send. The cookie is also SameSite=Strict.
  app.use('/api', (req, res, next) => {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.get('X-Requested-With') !== 'hub') return res.status(403).json({ error: 'Blocked request.' });
    next();
  });

  const limit = A.limiter();
  const pulls = new Map(); // pullId -> { uid, cols, rows, info, expires }
  const log = (req, act, mod, detail, user) => store.addAudit({ uid: (user || req.user || {}).id || null, uname: (user || req.user || {}).name || clip(req.body && req.body.email, 80) || '', act, mod, detail: clip(detail), ip: req.ip }).catch(() => {});

  // ---- connections & options (settings) ----
  const getConnections = async () => {
    const saved = (await store.getSetting('connections')) || {}, def = D.defaultConnections(), out = {};
    for (const k of Object.keys(def)) out[k] = { ...def[k], ...(saved[k] || {}), searchCols: def[k].searchCols, columns: def[k].columns, dateCol: def[k].dateCol, orderBy: def[k].orderBy, fixedFilters: def[k].fixedFilters, envs: { uat: { ...def[k].envs.uat, ...((saved[k] || {}).envs || {}).uat }, prod: { ...def[k].envs.prod, ...((saved[k] || {}).envs || {}).prod } } };
    return out;
  };
  const customIds = async () => (await store.listOptions()).map((o) => o.id);
  const allPerms = async () => { const c = await customIds(); const ids = [...D.MODULES.map((m) => m.id), ...c]; return new Set([...ids, ...ids.map(D.exp), ...D.SPECIAL, 'admin']); };
  const safePerms = async (list) => { const ok = await allPerms(); return [...new Set((Array.isArray(list) ? list : []).filter((p) => ok.has(p)))]; };
  const roleDefaultsFor = async (role) => {
    const opts = await store.listOptions();
    const ids = opts.filter((o) => role === 'Admin' || (o.roles || []).includes(role)).map((o) => o.id);
    return D.roleDefaults(role, ids);
  };

  const ctxOf = (q) => ({ qs: Q.queryString(q), dashboard: Q.num(Q.active(q).dashboard) });

  // ---- sessions ----
  async function loadSession(req) {
    const token = A.readCookie(req, A.COOKIE); if (!token) return null;
    const s = await store.getSessionByHash(A.sha(token)); if (!s) return null;
    const now = Date.now();
    if (new Date(s.expiresAt) < now || now - new Date(s.lastSeen) > config.idleMinutes * 60000) { await store.deleteSession(s.id); return null; }
    const user = await store.getUser(s.uid);
    if (!user || user.status !== 'active') { await store.deleteSession(s.id); return null; }
    if (now - new Date(s.lastSeen) > 60000) store.touchSession(s.id).catch(() => {});
    return { session: s, user };
  }
  const auth = wrap(async (req, res, next) => {
    const x = await loadSession(req); if (!x) return res.status(401).json({ error: 'Please sign in.' });
    req.user = x.user; req.session = x.session;
    if (x.user.mustChange && !req.path.startsWith('/api/auth/') && req.path !== '/api/bootstrap') return res.status(403).json({ error: 'Change your password first.', code: 'must_change' });
    next();
  });
  const need = (...perms) => (req, res, next) => { if (!perms.every((p) => req.user.perms.includes(p))) return res.status(403).json({ error: 'You do not have access to this.' }); next(); };
  const pubUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role, perms: u.perms, status: u.status, mustChange: !!u.mustChange });

  async function openSession(req, res, user) {
    const token = crypto.randomBytes(32).toString('base64url');
    const exp = new Date(Date.now() + config.sessionHours * 3600000);
    await store.createSession({ tokenHash: A.sha(token), uid: user.id, uname: user.name, device: A.device(req.get('user-agent')), ip: req.ip, expiresAt: exp });
    A.setCookie(res, token, config, config.sessionHours * 3600);
  }

  // ---- auth routes ----
  app.post('/api/auth/login', wrap(async (req, res) => {
    const email = clip(req.body && req.body.email, 200).toLowerCase(), pw = req.body && req.body.password;
    const key = email + '|' + req.ip, wait = limit.blocked(key);
    if (wait) return res.status(429).json({ error: `Too many attempts. Try again in ${wait} minute${wait === 1 ? '' : 's'}.` });
    const u = email && typeof pw === 'string' ? await store.findUserByEmail(email) : null;
    // compare against a dummy hash for unknown users so timing does not reveal which emails exist
    const okPw = await A.check(typeof pw === 'string' ? pw : '', u ? u.passwordHash : '$2a$10$7EqJtq98hPqEX7fNZaFWoOa5xSyYkZ1eYk9W1Qv0Jm9g1vNn2o0sK');
    if (!u || !okPw || u.status !== 'active') { limit.fail(key); log(req, 'login_failed', 'auth', 'Failed sign-in for ' + email, { id: u ? u.id : null, name: email }); return res.status(401).json({ error: u && okPw && u.status !== 'active' ? 'This account is disabled. Ask an admin.' : 'Wrong email or password.' }); }
    limit.ok(key);
    await openSession(req, res, u);
    await store.updateUser(u.id, { lastLogin: new Date() });
    log(req, 'login', 'auth', 'Signed in', u);
    res.json({ user: pubUser(u) });
  }));
  app.post('/api/auth/logout', wrap(async (req, res) => {
    const x = await loadSession(req);
    if (x) { await store.deleteSession(x.session.id); log(req, 'logout', 'auth', 'Signed out', x.user); }
    A.setCookie(res, '', config, 0); res.json({ ok: true });
  }));
  app.post('/api/auth/change-password', auth, wrap(async (req, res) => {
    const { current, next } = req.body || {};
    if (!(await A.check(String(current || ''), req.user.passwordHash))) return res.status(400).json({ error: 'Your current password is not right.' });
    A.validPassword(next);
    if (next === current) return res.status(400).json({ error: 'Choose a different password.' });
    await store.updateUser(req.user.id, { passwordHash: await A.hash(next), mustChange: false });
    await store.deleteSessionsForUser(req.user.id, req.session.id); // other devices must sign in again
    log(req, 'account', 'auth', 'Changed own password'); res.json({ ok: true });
  }));

  // ---- bootstrap ----
  app.get('/api/bootstrap', auth, wrap(async (req, res) => {
    const u = req.user, conns = await getConnections();
    const options = (await store.listOptions()).filter((o) => u.perms.includes(o.id)).map((o) => ({ id: o.id, name: o.name, ico: o.ico, desc: o.desc, fields: o.fields, url: o.url || '' }));
    const recent = (await store.recentForUser(u.id, 6)).filter((a) => a.act === 'search').map((a) => ({ detail: a.detail, t: stamp(a.ts) }));
    res.json({ user: pubUser(u), options, recent, searchCount: await store.countForUser(u.id, 'search'),
      settings: { connections: Object.fromEntries(Object.entries(conns).map(([k, c]) => [k, { env: c.env, timeoutSec: c.timeoutSec, minChars: c.minChars, searchCols: c.searchCols }])) } });
  }));
  app.post('/api/audit/event', auth, wrap(async (req, res) => {
    const { act, mod, detail } = req.body || {};
    if (!['open', 'download', 'export'].includes(act)) return res.status(400).json({ error: 'Unknown event.' });
    const m = clip(mod, 40);
    if (act === 'export' && !req.user.perms.includes('export:' + m)) return res.status(403).json({ error: 'You do not have access to this.' });
    log(req, act, m, detail); res.json({ ok: true });
  }));

  // ---- Search Hub ----
  const FIELD_LABEL = { ID_NUMBER: 'ID number', USER_NAME: 'Username', MOBILE_NUMBER: 'MSISDN', FIRST_NAME: 'First name', Middle_name: 'Middle name', LAST_NAME: 'Last name', EMAIL_ID: 'Email' };
  const outRows = (rows, user) => rows.map((r) => (r.ID_NUMBER && !user.perms.includes('unmask') ? { ...r, ID_NUMBER: maskId(r.ID_NUMBER) } : r));
  // Superset sometimes returns a column in a different letter case (id_number vs ID_NUMBER). Map it back so the page always finds it.
  const fixKeys = (r, cols) => { const low = new Map(Object.keys(r).map((k) => [k.toLowerCase(), k])); const o = { ...r }; for (const c of cols) if (!(c in o) && low.has(c.toLowerCase())) o[c] = r[low.get(c.toLowerCase())]; return o; };
  const hasAny = (row, col, vs) => { const cell = String(row[col] == null ? '' : row[col]).toLowerCase(); return vs.some((v) => cell.includes(String(v).toLowerCase())); };

  app.post('/api/search', auth, need('search'), wrap(async (req, res) => {
    const conns = await getConnections(), q = conns['search.lookup'];
    const filters = (req.body && req.body.filters) || {}, match = req.body && req.body.match === 'any' ? 'any' : 'all';
    const per = {}, used = {};
    for (const c of q.searchCols) {
      const v = Q.cleanValue(filters[c], q.minChars);
      if (v) { used[c] = v; per[c] = ['MOBILE_NUMBER', 'USER_NAME'].includes(c) ? Q.variants(v) : [v]; }
    }
    if (!Object.keys(used).length) throw httpErr(400, `Fill in at least one field (${q.minChars}+ characters).`);
    const body = Q.buildBody(q, per, 'No filter');
    const e = Q.active(q); if (!e.base) throw httpErr(503, `The ${q.env.toUpperCase()} Superset address is not set. Add it under Data Sources.`);
    const t0 = Date.now();
    const resp = await superset.query(e.base, q.endpoint, q.env, body, q.timeoutSec, ctxOf(q));
    let { rows, rowcount } = Q.rowsFrom(resp);
    rows = rows.map((r) => fixKeys(r, q.columns));
    const lim = Number(e.rowLimit) || 1000, truncated = rowcount >= lim;
    // The dataset matches ANY filled field. "Match all" keeps only rows that fit every filled field.
    if (match === 'all' && Object.keys(used).length > 1) rows = rows.filter((r) => Object.keys(per).every((c) => hasAny(r, c, per[c])));
    log(req, 'search', 'search', 'Search Hub: ' + Object.entries(used).map(([c, v]) => `${FIELD_LABEL[c] || c} "${v}"`).join(match === 'all' ? ' and ' : ' or ') + ` → ${rows.length} found (${Date.now() - t0} ms)`);
    res.json({ rows: outRows(rows, req.user), total: rows.length, truncated, limit: lim, env: q.env, at: new Date().toTimeString().slice(0, 8), match, vals: used });
  }));


  // ---- Deleted Docs: file paths come from Superset (by Partner ID), the files themselves from S3 ----
  const S3CFG = (config.s3 || {}), PREFIX = S3CFG.prefix || 'public_images/';
  const docKeys = new Map(); // user id -> Map(key -> { partner, docId, ct, exp }): only paths we just looked up can be downloaded
  const rememberDocs = (uid, files, partner) => { const m = docKeys.get(uid) || new Map(), n = Date.now(); for (const [k, v] of m) if (v.exp < n) m.delete(k); for (const f of files) if (f.key) m.set(f.key, { partner, docId: f.docId, ct: f.contentType, exp: n + 30 * 60000 }); docKeys.set(uid, m); };
  const s3Info = () => (s3 && s3.configured() ? { ok: true, bucket: S3CFG.bucket } : { ok: false, message: 'AWS is not set up on the server yet, so files cannot be listed or downloaded. An admin can follow the "Deleted Docs" step in the README.' });
  const docOut = (p, d, i) => { const key = S3.safeKey(d.path, PREFIX); return { n: i + 1, docId: String(d.document_id == null ? '' : d.document_id), key, bad: key ? '' : 'Path is not under ' + PREFIX, label: S3.labelOf(d.path || ''), contentType: d.content_type || '', ext: S3.EXT[String(d.content_type || '').toLowerCase().split(';')[0]] || '' }; };

  app.post('/api/docs/accounts', auth, need('docs'), wrap(async (req, res) => {
    const q = (await getConnections())['txns.lookup'], e = Q.active(q);
    const val = Q.cleanValue(req.body && req.body.value, q.minChars);
    if (!val) throw httpErr(400, `Enter at least ${q.minChars} characters.`);
    if (!e.base) throw httpErr(503, `The ${q.env.toUpperCase()} Superset address is not set for Account lookup. Add it under Data Sources.`);
    const { rows } = Q.rowsFrom(await superset.query(e.base, q.endpoint, q.env, Q.buildBody(q, Q.variants(val), 'No filter'), q.timeoutSec, ctxOf(q)));
    log(req, 'search', 'docs', `Deleted Docs account lookup: "${val}" → ${rows.length} found`);
    res.json({ rows: rows.map((r) => ({ USER_ID: r.USER_ID, PARTNER_ID: r.PARTNER_ID, USER_NAME: r.USER_NAME, MOBILE_NUMBER: r.MOBILE_NUMBER, FIRST_NAME: r.FIRST_NAME, Name: r.Name, STATUS: r.STATUS })) });
  }));

  app.post('/api/docs/lookup', auth, need('docs'), wrap(async (req, res) => {
    const q = (await getConnections())['docs.lookup'], e = Q.active(q);
    const partner = String((req.body && req.body.partner) || '').trim();
    if (!/^[A-Za-z0-9_-]{1,40}$/.test(partner)) throw httpErr(400, 'Enter a Partner ID (letters and numbers only).');
    if (!e.base) throw httpErr(503, `The ${q.env.toUpperCase()} Superset address is not set. Add it under Data Sources.`);
    const t0 = Date.now(), resp = await superset.query(e.base, q.endpoint, q.env, Q.buildBody(q, { partner_id: [partner] }, 'No filter'), q.timeoutSec, ctxOf(q));
    const { rows, rowcount } = Q.rowsFrom(resp), files = rows.map((r) => docOut(partner, fixKeys(r, q.columns), 0)).map((f, i) => ({ ...f, n: i + 1 }));
    const info = s3Info();
    if (info.ok) await Promise.all(files.map(async (f) => { if (!f.key) { f.state = 'bad'; return; } try { const h = await s3.head(f.key); f.size = h.length; f.state = 'ok'; if (!f.ext) f.ext = S3.sniff(null, h.contentType); } catch (x) { f.state = x.code === 'missing' ? 'missing' : 'unknown'; f.note = x.message; } }));
    else files.forEach((f) => { f.state = f.key ? 'unknown' : 'bad'; });
    files.forEach((f) => { f.ext = f.ext || 'jpg'; f.name = S3.fileName(partner, f.docId, f.key || f.label, f.ext); });
    if (req.user.perms.includes('dl_images')) rememberDocs(req.user.id, files, partner);
    log(req, 'search', 'docs', `Deleted Docs: Partner ID ${partner} → ${files.length} file(s) (${Date.now() - t0} ms)`);
    res.json({ partner, files, s3: info, canDownload: req.user.perms.includes('dl_images'), env: q.env, at: new Date().toTimeString().slice(0, 8), truncated: rowcount >= (Number(e.rowLimit) || 1000) });
  }));

  const hits = new Map(); // simple brake: one person can start at most 120 file or zip downloads in 10 minutes
  const dlBrake = (req, res, next) => { const n = Date.now(), l = (hits.get(req.user.id) || []).filter((x) => n - x < 600000); if (l.length >= 120) return res.status(429).json({ error: 'Too many downloads in a short time. Wait a few minutes and try again.' }); l.push(n); hits.set(req.user.id, l); next(); };
  const sendFile = (res, name, ext, buf) => { res.setHeader('Content-Type', S3.MIME[ext] || 'application/octet-stream'); res.setHeader('Content-Disposition', `attachment; filename="${name.replace(/[^\w.\-]/g, '_')}"`); res.setHeader('Content-Length', buf.length); res.end(buf); };
  app.get('/api/docs/file', auth, need('docs', 'dl_images'), dlBrake, wrap(async (req, res) => {
    const key = S3.safeKey(req.query.key, PREFIX), ok = key && (docKeys.get(req.user.id) || new Map()).get(key);
    if (!key) throw httpErr(400, 'That is not a valid file path.');
    if (!ok || ok.exp < Date.now()) throw httpErr(403, 'Look up this Partner ID again, then download the file.');
    if (!s3 || !s3.configured()) throw httpErr(503, s3Info().message, 's3_config');
    const { buf, contentType } = await s3.fetch(key), ext = S3.sniff(buf, ok.ct || contentType);
    log(req, 'download', 'docs', `Downloaded document ${ok.docId} for Partner ID ${ok.partner} (.${ext}, ${buf.length} bytes)`);
    sendFile(res, S3.fileName(ok.partner, ok.docId, key, ext), ext, buf);
  }));
  app.get('/api/docs/zip', auth, need('docs', 'dl_images'), dlBrake, wrap(async (req, res) => {
    const partner = String(req.query.partner || '').trim(), mine = [...(docKeys.get(req.user.id) || new Map())].filter(([, v]) => v.partner === partner && v.exp > Date.now());
    if (!mine.length) throw httpErr(403, 'Look up this Partner ID again, then download.');
    if (!s3 || !s3.configured()) throw httpErr(503, s3Info().message, 's3_config');
    const got = [], failed = []; let total = 0;
    for (const [key, v] of mine) { try { const r = await s3.fetch(key); total += r.buf.length; if (total > 250 * 1048576) throw httpErr(413, 'Too much to zip at once. Download the files one by one.'); const ext = S3.sniff(r.buf, v.ct || r.contentType); got.push({ name: S3.fileName(partner, v.docId, key, ext), buf: r.buf }); } catch (x) { if (x.status === 413) throw x; failed.push(`${v.docId}: ${x.message}`); } }
    if (!got.length) throw httpErr(404, failed[0] || 'No files could be read from S3.');
    const seen = new Set(); got.forEach((g) => { let n = g.name, i = 1; while (seen.has(n)) n = g.name.replace(/(\.\w+)$/, `_${++i}$1`); seen.add(n); g.name = n; });
    res.setHeader('Content-Type', 'application/zip'); res.setHeader('Content-Disposition', `attachment; filename="partner_${partner.replace(/[^\w-]/g, '')}_documents.zip"`);
    const z = require('archiver')('zip', { zlib: { level: 0 } }); z.on('error', () => res.destroy()); z.pipe(res);
    for (const g of got) z.append(g.buf, { name: g.name });
    if (failed.length) z.append('Some files could not be downloaded:\n' + failed.join('\n') + '\n', { name: '_not_downloaded.txt' });
    log(req, 'download', 'docs', `Downloaded ${got.length} document(s) as a zip for Partner ID ${partner}${failed.length ? ` (${failed.length} failed)` : ''}`);
    await z.finalize();
  }));

  // ---- Fees & Commissions, Thresholds & Limits: reference tables with dropdown filters ----
  const REF = { fees: { key: 'fees.rules', cols: ['service_name', 'SENDER_PROFILE', 'RECEIVER_PROFILE'], label: 'Fees & Commissions' }, limits: { key: 'limits.rules', cols: ['PROFILE_NAME', 'service_display_name'], label: 'Thresholds & Limits' } };
  const refCache = new Map(); // one full copy per connection, kept 10 minutes
  async function refAll(q) {
    const e = Q.active(q), k = [q.env, e.base, e.datasource, e.slice, e.rowLimit].join('|'), hit = refCache.get(k);
    if (hit && Date.now() - hit.at < 600000) return hit;
    if (!e.base) throw httpErr(503, `The ${q.env.toUpperCase()} Superset address is not set. Add it under Data Sources.`);
    const { rows, rowcount } = Q.rowsFrom(await superset.query(e.base, q.endpoint, q.env, Q.buildBody(q, {}, 'No filter'), q.timeoutSec, ctxOf(q)));
    const limit = Number(e.rowLimit) || 1000, opts = {};
    for (const c of q.searchCols) opts[c] = [...new Set(rows.map((r) => r[c]).filter((v) => v !== null && v !== undefined && v !== '').map(String))].sort((x, y) => x.localeCompare(y, undefined, { numeric: true }));
    const v = { at: Date.now(), rows, opts, truncated: rowcount >= limit, limit };
    refCache.set(k, v); return v;
  }
  const refMod = (req) => { const m = REF[req.params.mod]; if (!m) throw httpErr(404, 'Unknown module.'); return m; };
  const refNeed = (req, res, next) => { const m = REF[req.params.mod]; if (!m) return res.status(404).json({ error: 'Unknown module.' }); return need(req.params.mod)(req, res, next); };
  app.get('/api/ref/:mod/options', auth, refNeed, wrap(async (req, res) => {
    const m = refMod(req), q = (await getConnections())[m.key], all = await refAll(q);
    res.json({ options: all.opts, total: all.rows.length, truncated: all.truncated, limit: all.limit, env: q.env });
  }));
  app.post('/api/ref/:mod/query', auth, refNeed, wrap(async (req, res) => {
    const m = refMod(req), q = (await getConnections())[m.key], all = await refAll(q), want = {};
    for (const c of q.searchCols) {
      let v = (req.body && req.body.filters || {})[c]; if (v === undefined || v === '' || v === null) continue;
      v = (Array.isArray(v) ? v : [v]).map(String).slice(0, 50);
      if (v.some((x) => !all.opts[c].includes(x))) throw httpErr(400, `Unknown value for ${c}. Reload the page and pick from the list.`);
      want[c] = v;
    }
    let rows;
    if (!Object.keys(want).length) rows = all.rows;
    else if (!all.truncated) rows = all.rows.filter((r) => Object.entries(want).every(([c, v]) => v.includes(String(r[c]))));
    else { const e = Q.active(q); rows = Q.rowsFrom(await superset.query(e.base, q.endpoint, q.env, Q.buildBody(q, want, 'No filter'), q.timeoutSec, ctxOf(q))).rows; }
    log(req, 'search', req.params.mod, `${m.label}: ${Object.entries(want).map(([c, v]) => `${c} = ${v.join(' / ')}`).join(', ') || 'all rows'} → ${rows.length} row(s)`);
    res.json({ rows, total: rows.length, truncated: !Object.keys(want).length && all.truncated, limit: all.limit, env: q.env, at: new Date().toTimeString().slice(0, 8) });
  }));

  // ---- GPL token checker ----
  const getGpl = async () => { const s = (await store.getSetting('gpl')) || {}, d = D.defaultGpl(); return { ...d, ...s, envs: { uat: { ...d.envs.uat, ...((s.envs || {}).uat || {}) }, prod: { ...d.envs.prod, ...((s.envs || {}).prod || {}) } } }; };
  const norm = (x) => String(x == null ? '' : x).trim().toLowerCase();
  function compareGpl(uuid, rows, g) {
    if (!g) return { uuid: 'not_found', serial: 'unknown', amount: 'unknown' };
    const serials = rows.map((r) => norm(r.Serial_number)).filter(Boolean);
    const amts = rows.map((r) => Number(r.amount)).filter((n) => !isNaN(n));
    return {
      uuid: norm(g.reference) === norm(uuid) ? 'match' : 'differ',
      serial: !serials.length || !g.meter ? 'unknown' : serials.includes(norm(g.meter)) ? 'match' : 'differ',
      amount: !amts.length || g.totalNumber == null ? 'unknown' : amts.includes(g.totalNumber) ? 'match' : amts.some((n) => Math.abs(n - g.totalNumber * 100) < 0.5) ? 'match_cents' : 'differ',
    };
  }
  app.post('/api/gpl/lookup', auth, need('gpl'), wrap(async (req, res) => {
    const q = (await getConnections())['gpl.lookup'], cfg = await getGpl(), e = Q.active(q);
    const val = Q.cleanValue(req.body && req.body.value, q.minChars);
    if (!val) throw httpErr(400, `Enter at least ${q.minChars} characters.`);
    if (!e.base) throw httpErr(503, `The ${q.env.toUpperCase()} Superset address is not set. Add it under Data Sources.`);
    const byUuid = UUID.test(val), col = byUuid ? 'UUID' : 'TRANSACTION_ID', lim = Number(e.rowLimit) || 1000;
    const run = (c, v) => superset.query(e.base, q.endpoint, q.env, Q.buildBody(q, { [c]: [v] }, 'No filter'), q.timeoutSec, ctxOf(q)).then(Q.rowsFrom);
    const first = await run(col, val), rows = first.rows;
    const uuids = [...new Set(rows.map((r) => norm(r.UUID)).filter((u) => UUID.test(u)))].slice(0, 5);
    const checks = await Promise.all(uuids.map(async (u) => {
      const mine = rows.filter((r) => norm(r.UUID) === u);
      let dupRows = mine, dupError = null;
      if (!byUuid) { try { dupRows = (await run('UUID', u)).rows; } catch (x) { dupError = x.message; } }
      let g = null, gplError = null, gplCode = null;
      try { g = await gpl.receipt(cfg, cfg.env, u, cfg.timeoutSec); } catch (x) { gplError = x.message; gplCode = x.code || 'error'; }
      const ids = [...new Set(dupRows.map((r) => String(r.TRANSACTION_ID)))];
      return { uuid: u, rows: mine, dupCount: dupRows.length, isDuplicate: dupRows.length > 1, dupRows: dupRows.length > 1 ? dupRows : [], dupTransactionIds: ids, dupError,
        gpl: g, gplError, gplCode, compare: gplError ? { uuid: 'unknown', serial: 'unknown', amount: 'unknown' } : compareGpl(u, mine, g) };
    }));
    const dup = checks.filter((c) => c.isDuplicate).length, found = checks.filter((c) => c.gpl).length;
    log(req, 'search', 'gpl', `GPL check: ${byUuid ? 'UUID' : 'Transaction ID'} "${val}" → ${rows.length} row(s), ${dup ? dup + ' duplicate UUID' : 'no duplicate UUID'}, GPL receipt ${found ? 'found' : 'not found'}`);
    res.json({ kind: byUuid ? 'uuid' : 'transaction', value: val, rows, truncated: first.rowcount >= lim, limit: lim, checks, env: q.env, gplEnv: cfg.env, at: new Date().toTimeString().slice(0, 8) });
  }));

  // ---- Transaction History ----
  app.post('/api/txns/lookup', auth, need('txns'), wrap(async (req, res) => {
    const q = (await getConnections())['txns.lookup'];
    const val = Q.cleanValue(req.body && req.body.value, q.minChars);
    if (!val) throw httpErr(400, `Enter at least ${q.minChars} characters.`);
    const vals = Q.variants(val), e = Q.active(q);
    if (!e.base) throw httpErr(503, `The ${q.env.toUpperCase()} Superset address is not set. Add it under Data Sources.`);
    const resp = await superset.query(e.base, q.endpoint, q.env, Q.buildBody(q, vals, 'No filter'), q.timeoutSec, ctxOf(q));
    const { rows, rowcount } = Q.rowsFrom(resp), lim = Number(e.rowLimit) || 1000;
    log(req, 'search', 'txns', `Account lookup: "${val}" → ${rows.length} found`);
    res.json({ rows, vals, env: q.env, at: new Date().toTimeString().slice(0, 8), truncated: rowcount >= lim, limit: lim });
  }));

  const sweep = () => { const n = Date.now(); for (const [k, v] of pulls) if (v.expires < n) pulls.delete(k); };
  app.post('/api/txns/history', auth, need('txns'), wrap(async (req, res) => {
    const q = (await getConnections())['txns.history'];
    const pid = String((req.body && req.body.partnerId) || '').trim();
    if (!/^[A-Za-z0-9_-]{1,40}$/.test(pid)) throw httpErr(400, 'That Partner ID does not look right.');
    const pr = Q.periodRange(String(req.body.period || ''));
    const e = Q.active(q); if (!e.base) throw httpErr(503, `The ${q.env.toUpperCase()} Superset address is not set. Add it under Data Sources.`);
    const t0 = Date.now();
    let resp;
    try { resp = await superset.query(e.base, q.endpoint, q.env, Q.buildBody(q, { WALLET_PARTNER_ID: [pid] }, pr.range), q.timeoutSec, ctxOf(q)); }
    catch (x) { if (x.code === 'timeout') log(req, 'error', 'txns', `Transaction history timed out after ${q.timeoutSec}s: Partner ID ${pid}, ${pr.label}`); throw x; }
    const { rows, rowcount } = Q.rowsFrom(resp), lim = Number(e.rowLimit) || 0;
    sweep();
    for (const [k, v] of pulls) if (v.uid === req.user.id && pulls.size > 3) pulls.delete(k); // keep memory bounded
    if (pulls.size >= 30) pulls.delete(pulls.keys().next().value);
    const pullId = crypto.randomBytes(12).toString('base64url');
    const at = new Date();
    pulls.set(pullId, { uid: req.user.id, cols: q.columns, rows, pid, label: pr.label, range: pr.range, env: q.env, at, expires: Date.now() + config.historyKeepMinutes * 60000 });
    const ok = rows.filter((r) => r.STATUS_TYPE === 'Success').length;
    log(req, 'search', 'txns', `Transaction history: Partner ID ${pid}, ${pr.label} → ${rows.length} rows (${Date.now() - t0} ms)`);
    res.json({ pullId, total: rows.length, ok, bad: rows.length - ok, preview: rows.slice(0, 15), at: at.toTimeString().slice(0, 8), range: pr.range, env: q.env, rowLimit: lim, truncated: !!lim && rowcount >= lim });
  }));
  app.get('/api/txns/history/:id/xlsx', auth, need('txns', 'export:txns'), wrap(async (req, res) => {
    sweep();
    const p = pulls.get(req.params.id);
    if (!p || p.uid !== req.user.id) throw httpErr(404, 'That pull has expired. Pull the transactions again.');
    const info = [['Partner ID', p.pid], ['Period', p.label], ['Date filter', p.range], ['Rows', p.rows.length], ['Pulled', p.at.toISOString()], ['Pulled by', req.user.name], ['Environment', p.env.toUpperCase()],
      ['Note', 'Amounts are exactly as returned by Superset. Dates are UTC.']];
    const buf = await buildWorkbook(p.cols, p.rows, info);
    log(req, 'download', 'txns', `Downloaded Excel: Partner ID ${p.pid}, ${p.label}, ${p.rows.length} rows`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename="transactions.xlsx"');
    res.send(Buffer.from(buf));
  }));

  // ---- admin ----
  const admin = [auth, need('admin')];
  const lastSeenStr = (u) => (u.lastLogin ? stamp(u.lastLogin) : 'Never');
  const adminUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role, perms: u.perms, status: u.status, mfa: false, last: lastSeenStr(u) });
  const adminsLeft = (exceptId) => store.countUsersWithPerm('admin', exceptId);

  app.get('/api/admin/users', admin, wrap(async (req, res) => res.json({ users: (await store.listUsers()).map(adminUser) })));
  app.post('/api/admin/users', admin, wrap(async (req, res) => {
    const name = clip(req.body.name, 80).trim(), email = clip(req.body.email, 200).trim().toLowerCase(), role = req.body.role;
    if (!name) throw httpErr(400, 'Enter a name.');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw httpErr(400, 'Enter a valid email address.');
    if (!D.ROLES.includes(role)) throw httpErr(400, 'Pick a role.');
    if (await store.findUserByEmail(email)) throw httpErr(409, 'Someone with that email already exists.');
    const tmp = A.tempPassword();
    const u = await store.createUser({ name, email, role, perms: await roleDefaultsFor(role), status: 'active', passwordHash: await A.hash(tmp), mustChange: true });
    log(req, 'account', 'admin', `Created user ${name} (${role})`);
    res.json({ user: adminUser(u), tempPassword: tmp });
  }));
  app.put('/api/admin/users/:id', admin, wrap(async (req, res) => {
    const u = await store.getUser(req.params.id); if (!u) throw httpErr(404, 'User not found.');
    const b = req.body || {}, patch = {}, self = u.id === req.user.id, notes = [];
    if (b.role !== undefined) { if (!D.ROLES.includes(b.role)) throw httpErr(400, 'Unknown role.'); if (b.role !== u.role) notes.push(`role ${u.role} → ${b.role}`); patch.role = b.role; if (b.applyRoleDefaults) patch.perms = await roleDefaultsFor(b.role); }
    if (b.perms !== undefined && !b.applyRoleDefaults) patch.perms = await safePerms(b.perms);
    if (b.status !== undefined) { if (!['active', 'disabled'].includes(b.status)) throw httpErr(400, 'Unknown status.'); patch.status = b.status; }
    const newPerms = patch.perms || u.perms, newStatus = patch.status || u.status;
    if (self && (!newPerms.includes('admin') || newStatus !== 'active')) throw httpErr(400, 'You cannot remove your own admin access or disable yourself.');
    if (u.perms.includes('admin') && (!newPerms.includes('admin') || newStatus !== 'active') && (await adminsLeft(u.id)) < 1) throw httpErr(400, 'There must be at least one active admin.');
    if (patch.perms) { const add = patch.perms.filter((p) => !u.perms.includes(p)), rem = u.perms.filter((p) => !patch.perms.includes(p)); if (add.length) notes.push('added ' + add.join(', ')); if (rem.length) notes.push('removed ' + rem.join(', ')); }
    if (patch.status && patch.status !== u.status) notes.push('status ' + patch.status);
    const saved = await store.updateUser(u.id, patch);
    if (newStatus === 'disabled') await store.deleteSessionsForUser(u.id);
    if (notes.length) log(req, 'permission', 'admin', `${u.name}: ${notes.join('; ')}`);
    res.json({ user: adminUser(saved) });
  }));
  app.delete('/api/admin/users/:id', admin, wrap(async (req, res) => {
    const u = await store.getUser(req.params.id); if (!u) throw httpErr(404, 'User not found.');
    if (u.id === req.user.id) throw httpErr(400, 'You cannot remove yourself.');
    if (u.perms.includes('admin') && (await adminsLeft(u.id)) < 1) throw httpErr(400, 'There must be at least one active admin.');
    await store.deleteSessionsForUser(u.id); await store.deleteUser(u.id);
    log(req, 'account', 'admin', 'Removed ' + u.name); res.json({ ok: true });
  }));
  app.post('/api/admin/users/:id/reset-password', admin, wrap(async (req, res) => {
    const u = await store.getUser(req.params.id); if (!u) throw httpErr(404, 'User not found.');
    const tmp = A.tempPassword();
    await store.updateUser(u.id, { passwordHash: await A.hash(tmp), mustChange: true });
    await store.deleteSessionsForUser(u.id, u.id === req.user.id ? req.session.id : undefined);
    log(req, 'account', 'admin', 'Reset password for ' + u.name); res.json({ tempPassword: tmp });
  }));

  app.get('/api/admin/sessions', admin, wrap(async (req, res) => {
    const ss = await store.listSessions();
    res.json({ sessions: ss.map((s) => ({ id: s.id, uid: s.uid, uname: s.uname, device: s.device, ip: s.ip, createdAt: s.createdAt, lastSeen: s.lastSeen, current: s.id === req.session.id })) });
  }));
  app.delete('/api/admin/sessions/:id', admin, wrap(async (req, res) => {
    const ok = await store.deleteSession(req.params.id); if (!ok) throw httpErr(404, 'Session not found.');
    log(req, 'account', 'admin', 'Ended a session'); res.json({ ok: true });
  }));
  app.get('/api/admin/audit', admin, wrap(async (req, res) => {
    const n = Math.min(2000, Math.max(1, Number(req.query.limit) || 500));
    res.json({ events: (await store.listAudit(n)).map((e) => ({ ts: e.ts, uid: e.uid, uname: e.uname, act: e.act, mod: e.mod, detail: e.detail, ip: e.ip })) });
  }));

  app.get('/api/admin/connections', admin, wrap(async (req, res) => res.json({ connections: await getConnections(), auth: await authStatus() })));
  // Sends a tiny real request (1 row) so an admin can see straight away whether the address, IDs and saved login work.
  app.post('/api/admin/connections/:key/test', admin, wrap(async (req, res) => {
    const q = (await getConnections())[req.params.key]; if (!q) throw httpErr(404, 'Unknown connection.');
    const e = Q.active(q); if (!e.base) return res.json({ ok: false, error: `The ${q.env.toUpperCase()} address is not set.` });
    const probe = { ...q, envs: { ...q.envs, [q.env]: { ...e, rowLimit: 1 } } };
    const t0 = Date.now();
    try {
      const resp = await superset.query(e.base, q.endpoint, q.env, Q.buildBody(probe, { [q.searchCols[0]]: ['0'] }, 'No filter'), Math.min(q.timeoutSec, 30), ctxOf(probe));
      const { rows } = Q.rowsFrom(resp);
      log(req, 'setting', 'admin', `Tested "${q.label}" on ${q.env.toUpperCase()}: OK`);
      res.json({ ok: true, ms: Date.now() - t0, env: q.env, message: `Working. ${q.env.toUpperCase()} answered in ${Date.now() - t0} ms.` });
    } catch (x) {
      log(req, 'error', 'admin', `Tested "${q.label}" on ${q.env.toUpperCase()}: ${x.message}`);
      res.json({ ok: false, code: x.code || 'error', error: x.message, ms: Date.now() - t0 });
    }
  }));
  app.post('/api/admin/s3/test', admin, wrap(async (req, res) => {
    if (!s3 || !s3.configured()) return res.json({ ok: false, code: 's3_config', error: 'AWS_REGION is not set on the server, so S3 is switched off.', bucket: S3CFG.bucket, prefix: PREFIX });
    const r = await s3.test(); log(req, 'setting', 'admin', `Tested S3 access: ${r.ok ? 'OK' : r.error}`); res.json({ ...r, bucket: S3CFG.bucket, region: S3CFG.region, prefix: PREFIX });
  }));
  app.delete('/api/admin/connections/:key', admin, wrap(async (req, res) => {
    if (!D.defaultConnections()[req.params.key]) throw httpErr(404, 'Unknown connection.');
    const saved = (await store.getSetting('connections')) || {}; delete saved[req.params.key]; await store.setSetting('connections', saved);
    superset.reset(); refCache.clear();
    log(req, 'setting', 'admin', `Reset Superset connection "${req.params.key}" to the built-in defaults`);
    res.json((await getConnections())[req.params.key]);
  }));
  app.put('/api/admin/connections/:key', admin, wrap(async (req, res) => {
    const all = await getConnections(), cur = all[req.params.key]; if (!cur) throw httpErr(404, 'Unknown connection.');
    const b = req.body || {}, next = { ...cur };
    if (b.env !== undefined) { if (!['uat', 'prod'].includes(b.env)) throw httpErr(400, 'Environment must be uat or prod.'); next.env = b.env; }
    if (b.timeoutSec !== undefined) { const t = Number(b.timeoutSec); if (!(t >= 5 && t <= 600)) throw httpErr(400, 'Timeout must be between 5 and 600 seconds.'); next.timeoutSec = Math.round(t); }
    if (b.minChars !== undefined) { const m = Number(b.minChars); if (!(m >= 1 && m <= 20)) throw httpErr(400, 'Minimum characters must be between 1 and 20.'); next.minChars = Math.round(m); }
    if (b.endpoint !== undefined) { if (!/^\/[\w\-./]+$/.test(b.endpoint)) throw httpErr(400, 'The endpoint must be a path such as /api/v1/chart/data.'); next.endpoint = b.endpoint; }
    const colList = (x, what) => { if (!Array.isArray(x) || x.some((c) => typeof c !== 'string' || !/^[\w .\-]{1,80}$/.test(c))) throw httpErr(400, `${what} contains an invalid column name.`); return x; };
    // searchCols, columns, dateCol, orderBy and fixedFilters are fixed by the app (each page and the Excel file are built on them), so values sent here are ignored
    if (b.envs !== undefined) for (const t of ['uat', 'prod']) {
      const e = (b.envs || {})[t]; if (!e) continue;
      const base = String(e.base || '').trim().replace(/\/+$/, '');
      if (base && !/^https?:\/\/[^\s/]+$/i.test(base)) throw httpErr(400, `${t.toUpperCase()} base URL must look like http://host:port`);
      const n = (x, d) => (x === '' || x == null ? d : Number(x));
      const lim = n(e.rowLimit, 1000); if (!(lim >= 1 && lim <= 500000)) throw httpErr(400, 'Row limit must be between 1 and 500000.');
      for (const k of ['datasource', 'slice', 'dashboard']) if (e[k] !== '' && e[k] != null && isNaN(Number(e[k]))) throw httpErr(400, `${k} must be a number.`);
      next.envs = { ...next.envs, [t]: { base, datasource: e.datasource === '' ? '' : n(e.datasource, ''), slice: e.slice === '' ? '' : n(e.slice, ''), dashboard: e.dashboard === '' ? '' : n(e.dashboard, ''), rowLimit: lim } };
    }
    if (!next.envs[next.env].base) throw httpErr(400, `Add the ${next.env.toUpperCase()} base URL before making it the live one.`);
    const saved = (await store.getSetting('connections')) || {}; saved[req.params.key] = next; await store.setSetting('connections', saved);
    superset.reset(); refCache.clear(); // pick up any change of address
    log(req, 'setting', 'admin', `Updated Superset connection "${next.label}" (hub uses ${next.env.toUpperCase()}, timeout ${next.timeoutSec}s)`);
    res.json((await getConnections())[req.params.key]);
  }));
  // The login for Superset comes from a pasted curl. Only Cookie / X-CSRFToken / Authorization are kept, encrypted, and never sent back to the browser.
  const authStatus = async () => { const o = {}; for (const env of ['uat', 'prod']) { const s = await store.getSecret('superset:' + env); o[env] = s ? { saved: true, at: s.at, headers: Object.keys(s.headers), by: s.by } : { saved: false }; } return o; };
  app.get('/api/admin/superset-auth', admin, wrap(async (req, res) => res.json({ auth: await authStatus() })));
  app.put('/api/admin/superset-auth/:env', admin, wrap(async (req, res) => {
    const env = req.params.env; if (!['uat', 'prod'].includes(env)) throw httpErr(400, 'Environment must be uat or prod.');
    const c = String((req.body || {}).curl || ''); if (!/^\s*curl\s/i.test(c)) throw httpErr(400, 'That does not look like a curl command.');
    const headers = Q.parseCurlAuth(c);
    if (!headers.Cookie && !headers.Authorization) throw httpErr(400, 'No login found in that curl. Copy it from the browser as "Copy as cURL" so it includes the Cookie header.');
    await store.setSecret('superset:' + env, { headers, at: new Date().toISOString(), by: req.user.name });
    superset.reset();
    log(req, 'setting', 'admin', `Saved a new Superset login for ${env.toUpperCase()} (${Object.keys(headers).join(', ')})`);
    res.json({ auth: await authStatus() });
  }));
  app.delete('/api/admin/superset-auth/:env', admin, wrap(async (req, res) => {
    if (!['uat', 'prod'].includes(req.params.env)) throw httpErr(400, 'Environment must be uat or prod.');
    await store.setSecret('superset:' + req.params.env, null); superset.reset(); res.json({ auth: await authStatus() });
  }));
  // GPL: address, path and timeout, plus the login (Basic auth / cookie) taken from a pasted curl and stored encrypted.
  const gplAuthStatus = async () => { const o = {}; for (const env of ['uat', 'prod']) { const s = await store.getSecret('gpl:' + env); o[env] = s ? { saved: true, at: s.at, headers: Object.keys(s.headers) } : { saved: false }; } return o; };
  app.get('/api/admin/gpl', admin, wrap(async (req, res) => res.json({ gpl: await getGpl(), auth: await gplAuthStatus() })));
  app.put('/api/admin/gpl', admin, wrap(async (req, res) => {
    const b = req.body || {}, cur = await getGpl(), next = { ...cur, envs: { uat: { ...cur.envs.uat }, prod: { ...cur.envs.prod } } };
    if (b.env !== undefined) { if (!['uat', 'prod'].includes(b.env)) throw httpErr(400, 'Environment must be uat or prod.'); next.env = b.env; }
    if (b.timeoutSec !== undefined) { const t = Number(b.timeoutSec); if (!(t >= 5 && t <= 300)) throw httpErr(400, 'GPL timeout must be between 5 and 300 seconds.'); next.timeoutSec = Math.round(t); }
    for (const t of ['uat', 'prod']) { const e = (b.envs || {})[t]; if (!e) continue;
      const base = String(e.base || '').trim().replace(/\/+$/, ''), p = String(e.path || '/transactions/{uuid}/receipt').trim();
      if (base && !/^https?:\/\/[^\s/]+$/i.test(base)) throw httpErr(400, `${t.toUpperCase()} GPL address must look like https://host`);
      if (!/^\/[\w\-./{}]*\{uuid\}[\w\-./{}]*$/.test(p)) throw httpErr(400, 'The path must start with / and contain {uuid}, for example /transactions/{uuid}/receipt');
      next.envs[t] = { base, path: p }; }
    if (!next.envs[next.env].base) throw httpErr(400, `Add the ${next.env.toUpperCase()} GPL address before making it the live one.`);
    await store.setSetting('gpl', next); gpl.reset && gpl.reset();
    log(req, 'setting', 'admin', `Updated GPL connection (hub uses ${next.env.toUpperCase()}, timeout ${next.timeoutSec}s)`);
    res.json({ gpl: await getGpl(), auth: await gplAuthStatus() });
  }));
  app.put('/api/admin/gpl-auth/:env', admin, wrap(async (req, res) => {
    const env = req.params.env; if (!['uat', 'prod'].includes(env)) throw httpErr(400, 'Environment must be uat or prod.');
    const c = String((req.body || {}).curl || ''); if (!/^\s*curl\s/i.test(c)) throw httpErr(400, 'That does not look like a curl command.');
    const p = parseGplCurl(c); if (p.error) throw httpErr(400, p.error);
    const headers = Q.parseCurlAuth(c);
    if (!headers.Authorization && !headers.Cookie) throw httpErr(400, 'No login found in that curl. Copy it from the browser as "Copy as cURL" so it includes the authorization header or cookie.');
    const cur = await getGpl(); cur.envs[env] = { base: p.base, path: p.path }; cur.sampleUuid = p.sampleUuid;
    await store.setSetting('gpl', cur);
    await store.setSecret('gpl:' + env, { headers, at: new Date().toISOString(), by: req.user.name });
    log(req, 'setting', 'admin', `Saved the GPL address and login for ${env.toUpperCase()} (${Object.keys(headers).join(', ')})`);
    res.json({ gpl: await getGpl(), auth: await gplAuthStatus() });
  }));
  app.post('/api/admin/gpl/test', admin, wrap(async (req, res) => {
    const cfg = await getGpl(), t0 = Date.now();
    if (!cfg.sampleUuid) return res.json({ ok: false, error: 'Paste a GPL curl first. Its receipt is used for the test.' });
    try {
      const g = await gpl.receipt(cfg, cfg.env, cfg.sampleUuid, Math.min(cfg.timeoutSec, 30));
      log(req, 'setting', 'admin', `Tested GPL on ${cfg.env.toUpperCase()}: ${g ? 'OK' : 'receipt not found'}`);
      res.json(g ? { ok: true, ms: Date.now() - t0, message: `Working. GPL ${cfg.env.toUpperCase()} answered in ${Date.now() - t0} ms.` } : { ok: false, error: 'GPL answered, but has no receipt for the saved UUID. The address and login work; try a curl for a current receipt.' });
    } catch (x) { res.json({ ok: false, code: x.code || 'error', error: x.message }); }
  }));
  app.get('/api/admin/health', admin, wrap(async (req, res) => {
    const conns = await getConnections(), out = {};
    const au = await authStatus(), gau = await gplAuthStatus(); for (const env of ['uat', 'prod']) { const c = config.superset[env]; out[env] = { login: au[env].saved || !!(c.user && c.pass) || !!c.token || !!c.cookie, mode: au[env].saved ? 'saved curl' : c.user ? 'service account' : 'none', savedAt: au[env].at || null }; }
    await store.ping(); res.json({ store: store.kind, gpl: gau, superset: out, live: Object.fromEntries(Object.entries(conns).map(([k, c]) => [k, c.env])) });
  }));

  // custom options built from a Superset dashboard curl
  const optView = (o) => ({ id: o.id, name: o.name, ico: o.ico, desc: o.desc, fields: o.fields, url: o.url || '', roles: o.roles });
  app.get('/api/admin/options', admin, wrap(async (req, res) => res.json({ options: (await store.listOptions()).map(optView) })));
  app.post('/api/admin/options', admin, wrap(async (req, res) => {
    const b = req.body || {}, name = clip(b.name, 60).trim();
    if (!name) throw httpErr(400, 'Give the option a name.');
    const existing = await store.listOptions();
    if ([...D.MODULES, ...existing].some((m) => m.name.toLowerCase() === name.toLowerCase())) throw httpErr(409, 'An option with that name already exists.');
    let url = '', body = null;
    if (b.curl) { if (!/^\s*curl\s/i.test(b.curl)) throw httpErr(400, 'That does not look like a curl command.'); const p = Q.parseCurl(b.curl); if (p.error) throw httpErr(400, p.error); url = p.url; body = p.body; }
    const roles = (Array.isArray(b.roles) ? b.roles : []).filter((r) => D.ROLES.includes(r));
    const o = await store.createOption({ name, ico: /^[a-z_]{2,40}$/.test(b.ico || '') ? b.ico : 'dashboard', desc: clip(b.desc, 200) || 'Custom Superset dashboard.', fields: (Array.isArray(b.fields) ? b.fields : ['Search']).map((f) => clip(f, 40)).filter(Boolean).slice(0, 5), url, body, roles: ['Admin', ...roles.filter((r) => r !== 'Admin')] });
    for (const u of await store.listUsers()) if (o.roles.includes(u.role)) await store.updateUser(u.id, { perms: [...new Set([...u.perms, o.id, ...(u.role === 'Agent' ? [] : [D.exp(o.id)])])] });
    log(req, 'create', 'admin', `Created option "${name}" for ${o.roles.join(', ')}`);
    res.json({ option: optView(o) });
  }));
  app.put('/api/admin/options/:id', admin, wrap(async (req, res) => {
    const c = String((req.body || {}).curl || ''); if (!/^\s*curl\s/i.test(c)) throw httpErr(400, 'That does not look like a curl command.');
    const p = Q.parseCurl(c); if (p.error) throw httpErr(400, p.error);
    const o = await store.updateOption(req.params.id, { url: p.url, body: p.body }); if (!o) throw httpErr(404, 'Option not found.');
    log(req, 'setting', 'admin', `Updated curl for "${o.name}"`); res.json({ option: optView(o) });
  }));
  app.delete('/api/admin/options/:id', admin, wrap(async (req, res) => {
    const o = (await store.listOptions()).find((x) => x.id === req.params.id); if (!o) throw httpErr(404, 'Option not found.');
    await store.deleteOption(o.id);
    for (const u of await store.listUsers()) if (u.perms.includes(o.id)) await store.updateUser(u.id, { perms: u.perms.filter((p) => p !== o.id && p !== D.exp(o.id)) });
    log(req, 'create', 'admin', `Removed option "${o.name}"`); res.json({ ok: true });
  }));

  // ---- static page ----
  const pub = path.join(__dirname, '..', 'public');
  app.use(express.static(pub, { index: 'index.html', maxAge: 0 }));
  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
  app.use((err, req, res, next) => { // eslint-disable-line
    if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Bad request.' });
    const status = err.status || 500;
    if (status >= 500 && !err.code) console.error(err);
    res.status(status).json({ error: status === 500 ? 'Something went wrong on the server.' : err.message, code: err.code });
  });
  return app;
}
module.exports = { createApp };
