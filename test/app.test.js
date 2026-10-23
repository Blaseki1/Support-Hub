const test = require('node:test');
const assert = require('node:assert/strict');
const ExcelJS = require('exceljs');
const { createApp } = require('../server/app');
const { memoryStore } = require('../server/store');
const { Superset } = require('../server/superset');
const { ensureAdmin } = require('../server/bootstrap');
const { makeBox, secureStore } = require('../server/crypto-box');
const A = require('../server/auth');
const fake = require('./fake-superset');
const fakeGpl = require('./fake-gpl');
const { Gpl } = require('../server/gpl');

let F, G, store, raw, srv, base, superset;
const config = { sessionHours: 12, idleMinutes: 120, secureCookie: false, trustProxy: false, adminEmail: 'boss@example.com', adminName: 'Boss', adminPassword: 'Correct-Horse-1', historyKeepMinutes: 30,
  superset: { uat: {}, prod: {} } };
const CURL = "curl 'http://127.0.0.1/api/v1/chart/data' -H 'Content-Type: application/json' -H 'Cookie: session=abc; other=1' -H 'X-CSRFToken: csrf1' -H 'Authorization: Bearer tok1' --data '{}'";

class Client {
  constructor() { this.cookie = ''; }
  async req(method, url, body) {
    const r = await fetch(base + url, { method, headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'hub', Cookie: this.cookie }, body: body === undefined ? undefined : JSON.stringify(body) });
    const sc = r.headers.get('set-cookie'); if (sc) this.cookie = sc.split(';')[0].endsWith('=') ? '' : sc.split(';')[0];
    const ct = r.headers.get('content-type') || ''; const data = ct.includes('json') ? await r.json() : Buffer.from(await r.arrayBuffer());
    return { status: r.status, data, headers: r.headers };
  }
  get(u) { return this.req('GET', u); } post(u, b) { return this.req('POST', u, b || {}); } put(u, b) { return this.req('PUT', u, b); } del(u) { return this.req('DELETE', u); }
}
async function signedIn(email = 'boss@example.com', pw = 'Correct-Horse-1') { const c = new Client(); const r = await c.post('/api/auth/login', { email, password: pw }); assert.equal(r.status, 200); return c; }

test.before(async () => {
  F = await fake.start(0, { slowMs: 4000 }); G = await fakeGpl.start();
  raw = memoryStore(); const box = makeBox('test-key-123'); A.setPepper(box.pepper); store = secureStore(raw, box); await store.init(); await ensureAdmin(store, config);
  // point the connections at the fake
  const conns = {};
  for (const [k, ds] of Object.entries({ 'search.lookup': 76, 'txns.lookup': 74, 'txns.history': 73, 'gpl.lookup': 70, 'fees.rules': 71, 'limits.rules': 77 })) conns[k] = { envs: { uat: { base: 'http://127.0.0.1:' + F.port, datasource: ds } } };
  await store.setSetting('connections', conns);
  await store.setSetting('gpl', { envs: { uat: { base: 'http://127.0.0.1:' + G.port } } });
  await store.setSecret('gpl:uat', { headers: { Authorization: 'Basic dGVzdDp0ZXN0', Cookie: '_juice_ex_key=good' }, at: 'x' });
  await store.setSecret('superset:uat', { headers: { Cookie: 'session=abc', 'X-CSRFToken': 'csrf1', Authorization: 'Bearer tok1' }, at: 'x', by: 'test' });
  superset = new Superset(config.superset, (env) => store.getSecret('superset:' + env), async (env, headers) => { const cur = (await store.getSecret('superset:' + env)) || {}; await store.setSecret('superset:' + env, { ...cur, headers }); });
  const gplc = new Gpl((env) => store.getSecret('gpl:' + env));
  const app = createApp({ store, superset, config, gpl: gplc });
  await new Promise((r) => { srv = app.listen(0, '127.0.0.1', r); }); base = 'http://127.0.0.1:' + srv.address().port;
});
test.after(async () => { srv.close(); await F.close(); await G.close(); });

test('login: wrong password, missing CSRF header, forced password change', async () => {
  const c = new Client();
  assert.equal((await c.post('/api/auth/login', { email: 'boss@example.com', password: 'nope' })).status, 401);
  const raw = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(raw.status, 403);
  assert.equal((await c.get('/api/bootstrap')).status, 401);
  assert.equal((await c.post('/api/auth/login', { email: 'boss@example.com', password: 'Correct-Horse-1' })).status, 200);
  const b = await c.get('/api/bootstrap'); assert.equal(b.data.user.mustChange, true);
  assert.equal((await c.post('/api/search', { filters: { USER_NAME: '6010256' } })).status, 403); // must change first
  assert.equal((await c.post('/api/auth/change-password', { current: 'Correct-Horse-1', next: 'short' })).status, 400);
  assert.equal((await c.post('/api/auth/change-password', { current: 'Correct-Horse-1', next: 'Another-Long-Pass-2' })).status, 200);
  config.adminPassword = 'Another-Long-Pass-2';
  assert.equal((await c.get('/api/bootstrap')).data.user.mustChange, false);
});

test('lockout after five wrong passwords', async () => {
  const c = new Client(); let last;
  for (let i = 0; i < 6; i++) last = await c.post('/api/auth/login', { email: 'ghost@example.com', password: 'x' });
  assert.equal(last.status, 429);
});

test('many people can be signed in at once, and logging out only ends your own session', async () => {
  const admin = await signedIn('boss@example.com', 'Another-Long-Pass-2');
  const mk = await admin.post('/api/admin/users', { name: 'Carleane', email: 'c@example.com', role: 'Agent' });
  assert.equal(mk.status, 200);
  const tmp = mk.data.tempPassword;
  const a1 = await signedIn('c@example.com', tmp), a2 = new Client();
  await a2.post('/api/auth/login', { email: 'c@example.com', password: tmp });
  assert.equal((await a1.post('/api/auth/change-password', { current: tmp, next: 'Carleane-Pass-123' })).status, 200);
  assert.equal((await a2.get('/api/bootstrap')).status, 401); // other devices end after a password change
  const b1 = await signedIn('c@example.com', 'Carleane-Pass-123'), b2 = await signedIn('c@example.com', 'Carleane-Pass-123');
  await b1.post('/api/auth/logout');
  assert.equal((await b1.get('/api/bootstrap')).status, 401);
  assert.equal((await b2.get('/api/bootstrap')).status, 200);
  const ss = await admin.get('/api/admin/sessions'); assert.ok(ss.data.sessions.filter((s) => s.uname === 'Carleane').length >= 1);
});

test('search: any number works, match all vs any, ID masked without unmask', async () => {
  const admin = await signedIn('boss@example.com', 'Another-Long-Pass-2');
  let r = await admin.post('/api/search', { filters: { MOBILE_NUMBER: '6010256' }, match: 'all' });
  assert.equal(r.status, 200); assert.equal(r.data.rows.length, 1); assert.equal(r.data.rows[0].USER_NAME, '6010256');
  assert.equal(r.data.rows[0].ID_NUMBER, 'R1234567'); // admin has unmask
  r = await admin.post('/api/search', { filters: { FIRST_NAME: 'Anna', LAST_NAME: 'Persaud' }, match: 'all' });
  assert.deepEqual(r.data.rows.map((x) => x.USER_ID), ['101']);
  r = await admin.post('/api/search', { filters: { FIRST_NAME: 'Anna', LAST_NAME: 'Persaud' }, match: 'any' });
  assert.deepEqual(r.data.rows.map((x) => x.USER_ID).sort(), ['101', '102', '103']);
  r = await admin.post('/api/search', { filters: { MOBILE_NUMBER: '5926010256' }, match: 'all' }); // with country code
  assert.equal(r.data.rows.length, 1);
  assert.equal((await admin.post('/api/search', { filters: {} })).status, 400);
  assert.equal((await admin.post('/api/search', { filters: { FIRST_NAME: "a' OR 1=1" } })).status, 400);
  assert.equal((await admin.post('/api/search', { filters: { FIRST_NAME: 'ab' } })).status, 400); // under 3 chars
  const c = await signedIn('c@example.com', 'Carleane-Pass-123');
  r = await c.post('/api/search', { filters: { USER_NAME: '6010256' } });
  assert.equal(r.data.rows[0].ID_NUMBER, '•••••••'.slice(0, 5) + '567'.padStart(3)); // masked except last 3
});

test('permissions are enforced on the server', async () => {
  const c = await signedIn('c@example.com', 'Carleane-Pass-123');
  assert.equal((await c.post('/api/txns/lookup', { value: '6010256' })).status, 200);
  assert.equal((await c.get('/api/admin/users')).status, 403);
  const hist = await c.post('/api/txns/history', { partnerId: 's100', period: 'all' });
  assert.equal(hist.status, 200);
  assert.equal((await c.get('/api/txns/history/' + hist.data.pullId + '/xlsx')).status, 403); // Agent has no export
  const admin = await signedIn('boss@example.com', 'Another-Long-Pass-2');
  const users = (await admin.get('/api/admin/users')).data.users, cu = users.find((u) => u.email === 'c@example.com');
  assert.equal((await admin.put('/api/admin/users/' + cu.id, { perms: [...cu.perms, 'export:txns'] })).status, 200);
  assert.equal((await c.get('/api/txns/history/' + hist.data.pullId + '/xlsx')).status, 200); // applies immediately
  assert.equal((await admin.get('/api/txns/history/' + hist.data.pullId + '/xlsx')).status, 404); // someone else's pull
  assert.equal((await admin.put('/api/admin/users/' + cu.id, { perms: cu.perms.filter((p) => p !== 'search') })).status, 200);
  assert.equal((await c.post('/api/search', { filters: { USER_NAME: '6010256' } })).status, 403);
  const me = users.find((u) => u.email === 'boss@example.com');
  assert.equal((await admin.put('/api/admin/users/' + me.id, { status: 'disabled' })).status, 400);
  assert.equal((await admin.del('/api/admin/users/' + me.id)).status, 400);
});

test('transaction history: pulls by Partner ID, Excel has 42 columns and real dates', async () => {
  const admin = await signedIn('boss@example.com', 'Another-Long-Pass-2');
  const h = await admin.post('/api/txns/history', { partnerId: 's100', period: 'all' });
  assert.equal(h.data.total, 20); assert.equal(h.data.preview.length, 15);
  assert.equal(F.calls.filter((c) => c.id === 73).pop().filters.find((f) => f.col === 'WALLET_PARTNER_ID').val[0], 's100');
  const x = await admin.get('/api/txns/history/' + h.data.pullId + '/xlsx'); assert.equal(x.status, 200);
  const wb = new ExcelJS.Workbook(); await wb.xlsx.load(x.data);
  const ws = wb.getWorksheet('Transactions'); assert.equal(ws.columnCount, 42); assert.equal(ws.rowCount, 21);
  assert.ok(ws.getRow(2).getCell(4).value instanceof Date); assert.equal(typeof ws.getRow(2).getCell(1).value, 'string');
  assert.ok(wb.getWorksheet('About this file'));
  assert.equal((await admin.post('/api/txns/history', { partnerId: "s1'; drop", period: 'all' })).status, 400);
  assert.equal((await admin.post('/api/txns/history', { partnerId: 's100', period: 'zz' })).status, 400);
});

test('timeout is configurable and reported', async () => {
  const admin = await signedIn('boss@example.com', 'Another-Long-Pass-2');
  const cur = (await admin.get('/api/admin/connections')).data.connections['txns.history'];
  assert.equal((await admin.put('/api/admin/connections/txns.history', { timeoutSec: 2 })).status, 400); // below the 5 s floor
  assert.equal((await admin.put('/api/admin/connections/txns.history', { timeoutSec: 5 })).status, 200);
  const t0 = Date.now(); const r = await admin.post('/api/txns/history', { partnerId: 'slow', period: 'all' }); // fake sleeps 4s: succeeds
  assert.equal(r.status, 200);
  assert.ok(cur.timeoutSec >= 5 && Date.now() - t0 >= 3900);
});

test('admin can edit connection (UAT to PROD) and options; audit records activity', async () => {
  const admin = await signedIn('boss@example.com', 'Another-Long-Pass-2');
  const bad = await admin.put('/api/admin/connections/search.lookup', { env: 'prod' });
  assert.equal(bad.status, 400); // prod has no URL yet
  const ok = await admin.put('/api/admin/connections/search.lookup', { envs: { prod: { base: 'https://superset.example.com', datasource: 1, slice: 2, dashboard: 3, rowLimit: 500 } } });
  assert.equal(ok.status, 200); assert.equal(ok.data.envs.prod.base, 'https://superset.example.com');
  const o = await admin.post('/api/admin/options', { name: 'Agent float', ico: 'dashboard', desc: 'x', fields: ['MSISDN'], curl: "curl 'http://s.example.com/api/v1/chart/data' -H 'Cookie: session=SECRET' --data '{\"a\":1}'", roles: ['Supervisor'] });
  assert.equal(o.status, 200); assert.ok(!JSON.stringify(await store.listOptions()).includes('SECRET'));
  const users = (await admin.get('/api/admin/users')).data.users;
  assert.ok(users.find((u) => u.role === 'Admin').perms.includes(o.data.option.id));
  const a = await admin.get('/api/admin/audit?limit=100');
  const acts = a.data.events.map((e) => e.act); for (const k of ['login', 'search', 'download', 'permission', 'setting', 'login_failed']) assert.ok(acts.includes(k), k);
  assert.ok(a.data.events.some((e) => e.act === 'search' && /MSISDN "6010256"/.test(e.detail)));
});

test('Superset errors come back as readable messages', async () => {
  const bad = new Superset({ uat: { user: 'svc', pass: 'WRONG' }, prod: {} });
  await assert.rejects(() => bad.query('http://127.0.0.1:' + F.port, '/api/v1/chart/data', 'uat', {}, 5), (e) => e.code === 'superset_login');
  const none = new Superset({ uat: {}, prod: {} });
  await assert.rejects(() => none.query('http://127.0.0.1:' + F.port, '/api/v1/chart/data', 'uat', {}, 5), (e) => e.code === 'no_credentials');
  const down = new Superset({ uat: { token: 't' }, prod: {} });
  await assert.rejects(() => down.query('http://127.0.0.1:9', '/api/v1/chart/data', 'uat', {}, 5), (e) => e.code === 'unreachable');
});

test('a hung Superset times out', async () => {
  const hang = require('http').createServer(() => {}); await new Promise((r) => hang.listen(0, '127.0.0.1', r));
  const s = new Superset({ uat: { token: 't' }, prod: {} });
  const t0 = Date.now();
  await assert.rejects(() => s.query('http://127.0.0.1:' + hang.address().port, '/x', 'uat', {}, 1), (e) => e.code === 'timeout');
  assert.ok(Date.now() - t0 < 3000); hang.closeAllConnections(); hang.close();
});

test('no Superset username/password needed: the login comes from a pasted curl, stored encrypted', async () => {
  const admin = await signedIn('boss@example.com', 'Another-Long-Pass-2');
  await admin.del('/api/admin/superset-auth/uat'); // before any curl is saved, a search explains what to do
  const before = await admin.post('/api/search', { filters: { USER_NAME: '6010256' } });
  assert.equal(before.status, 503); assert.match(before.data.error, /paste a curl/i);
  assert.equal((await admin.put('/api/admin/superset-auth/uat', { curl: "curl 'http://x' --data '{}'" })).status, 400); // no login in it
  const ok = await admin.put('/api/admin/superset-auth/uat', { curl: CURL });
  assert.equal(ok.status, 200); assert.deepEqual(ok.data.auth.uat.headers.sort(), ['Authorization', 'Cookie', 'X-CSRFToken']);
  assert.ok(!JSON.stringify(ok.data).includes('tok1') && !JSON.stringify(ok.data).includes('abc'));
  const r = await admin.post('/api/search', { filters: { USER_NAME: '6010256' } }); assert.equal(r.status, 200);
  const stored = JSON.stringify(await raw.getSetting('secret:superset:uat')); assert.ok(!/tok1|session=abc|csrf1/.test(stored));
  // an expired login gives a clear message
  assert.equal((await admin.put('/api/admin/superset-auth/uat', { curl: CURL.replace('tok1', 'old') })).status, 200);
  const bad = await admin.post('/api/search', { filters: { USER_NAME: '6010256' } });
  assert.equal(bad.status, 502); assert.match(bad.data.error, /expired/);
  await admin.put('/api/admin/superset-auth/uat', { curl: CURL });
});

test('names, emails, passwords, audit text and sessions are encrypted in the database', async () => {
  const rows = await raw.listUsers();
  assert.ok(rows.length >= 2);
  const dump = JSON.stringify(rows) + JSON.stringify(await raw.listAudit(500)) + JSON.stringify(await raw.listSessions());
  for (const plain of ['boss@example.com', 'c@example.com', 'Carleane', 'Boss', 'Another-Long-Pass-2', 'Carleane-Pass-123', '6010256']) assert.ok(!dump.includes(plain), 'plaintext found: ' + plain);
  assert.ok(rows.every((u) => u.passwordHash.startsWith('$2')) && rows.every((u) => u.email.startsWith('v1:')));
  // the app still reads them
  const admin = await signedIn('BOSS@example.com', 'Another-Long-Pass-2'); // email lookup is case-insensitive
  assert.equal((await admin.get('/api/bootstrap')).data.user.name, 'Boss');
  assert.ok((await admin.get('/api/admin/audit')).data.events.some((e) => /6010256/.test(e.detail)));
});

test('a renewed session cookie from Superset is kept, and the test button reports clearly', async () => {
  const F2 = await fake.start(0, { rotate: true });
  const saved = { headers: { Cookie: 'session=abc', 'X-CSRFToken': 'csrf1', Authorization: 'Bearer tok1' } };
  const s = new Superset({}, async () => JSON.parse(JSON.stringify(saved)), async (env, h) => { saved.headers = h; });
  await s.query('http://127.0.0.1:' + F2.port, '/api/v1/chart/data', 'uat', { datasource: { id: 76 }, queries: [{ filters: [], row_limit: 1 }] }, 5, { qs: '?form_data=%7B%22slice_id%22%3A83%7D&dashboard_id=103', dashboard: 103 });
  assert.match(saved.headers.Cookie, /session=abc2/);
  await F2.close();
  const admin = await signedIn('boss@example.com', 'Another-Long-Pass-2');
  const t = await admin.post('/api/admin/connections/search.lookup/test'); assert.equal(t.data.ok, true);
  await admin.put('/api/admin/superset-auth/uat', { curl: CURL.replace('tok1', 'old') });
  const bad = await admin.post('/api/admin/connections/search.lookup/test'); assert.equal(bad.data.ok, false); assert.equal(bad.data.code, 'auth_expired');
  await admin.put('/api/admin/superset-auth/uat', { curl: CURL });
});

const U1 = '7bcea5b1-9ab3-49fc-8e73-e39b5887b3c4', U2 = '14702560-cc3c-11f0-9bb5-b02628171946';
test('GPL: transaction ID -> Superset row -> GPL receipt, serial / UUID / amount checks, duplicate UUIDs', async () => {
  const admin = await signedIn('boss@example.com', 'Another-Long-Pass-2');
  let r = await admin.post('/api/gpl/lookup', { value: '20376942462079' });
  assert.equal(r.status, 200); assert.equal(r.data.rows.length, 1);
  let c = r.data.checks[0];
  assert.equal(c.uuid, U1); assert.equal(c.gpl.reference, U1); assert.equal(c.gpl.meter, 'temp_6523'); assert.equal(c.gpl.name, 'TEST CUSTOMER');
  assert.deepEqual(c.compare, { uuid: 'match', serial: 'match', amount: 'match_cents' }); assert.equal(c.isDuplicate, false);
  r = await admin.post('/api/gpl/lookup', { value: '20376942462080' }); c = r.data.checks[0];
  assert.equal(c.isDuplicate, true); assert.equal(c.dupCount, 2); assert.deepEqual(c.dupTransactionIds.sort(), ['20376942462080', '20376942462081']);
  assert.equal(c.compare.serial, 'differ'); // meter-777 in Superset, meter-999 at GPL
  r = await admin.post('/api/gpl/lookup', { value: U2 }); assert.equal(r.data.kind, 'uuid'); assert.equal(r.data.rows.length, 2); assert.equal(r.data.checks[0].isDuplicate, true);
  r = await admin.post('/api/gpl/lookup', { value: '20376942462082' }); c = r.data.checks[0];
  assert.equal(c.gpl, null); assert.equal(c.compare.uuid, 'not_found');
  r = await admin.post('/api/gpl/lookup', { value: '99999999999' }); assert.equal(r.data.rows.length, 0); assert.equal(r.data.checks.length, 0);
  assert.equal((await admin.post('/api/gpl/lookup', { value: "1' or '1'='1" })).status, 400);
  assert.ok(G.calls.at(-1).headers.authorization.startsWith('Basic '));
});

test('GPL: an expired GPL login still shows the Superset result, with a clear message', async () => {
  const admin = await signedIn('boss@example.com', 'Another-Long-Pass-2');
  await store.setSecret('gpl:uat', { headers: { Authorization: 'Basic dGVzdDp0ZXN0', Cookie: '_juice_ex_key=stale' }, at: 'x' });
  const r = await admin.post('/api/gpl/lookup', { value: '20376942462079' });
  assert.equal(r.status, 200); assert.equal(r.data.rows.length, 1); assert.equal(r.data.checks[0].gplCode, 'auth_expired'); assert.match(r.data.checks[0].gplError, /fresh GPL curl/);
  await store.setSecret('gpl:uat', { headers: { Authorization: 'Basic dGVzdDp0ZXN0', Cookie: '_juice_ex_key=good' }, at: 'x' });
});

test('GPL: admin pastes the GPL curl; address, path and login are saved, login stays encrypted', async () => {
  const admin = await signedIn('boss@example.com', 'Another-Long-Pass-2');
  const curl = `curl --url 'http://127.0.0.1:${G.port}/transactions/${U1}/receipt' -H 'accept: text/html' -H 'authorization: Basic dGVzdDp0ZXN0' -b '_juice_ex_key=good' -H 'user-agent: Mozilla/5.0'`;
  assert.equal((await admin.put('/api/admin/gpl-auth/uat', { curl: "curl 'http://x/y'" })).status, 400);
  const ok = await admin.put('/api/admin/gpl-auth/uat', { curl }); assert.equal(ok.status, 200);
  assert.equal(ok.data.gpl.envs.uat.path, '/transactions/{uuid}/receipt'); assert.equal(ok.data.gpl.sampleUuid, U1);
  assert.deepEqual(ok.data.auth.uat.headers.sort(), ['Authorization', 'Cookie', 'User-Agent']);
  assert.ok(!JSON.stringify(ok.data).includes('dGVzdDp0ZXN0'));
  assert.ok(!JSON.stringify(await raw.getSetting('secret:gpl:uat')).includes('dGVzdDp0ZXN0'));
  assert.equal((await admin.post('/api/admin/gpl/test')).data.ok, true);
  assert.equal((await admin.put('/api/admin/gpl', { timeoutSec: 2 })).status, 400);
  assert.equal((await admin.put('/api/admin/gpl', { timeoutSec: 45 })).status, 200);
  assert.equal((await admin.put('/api/admin/gpl', { envs: { prod: { base: 'https://x.example.com', path: '/no-uuid' } } })).status, 400);
});

test('GPL: needs the gpl permission', async () => {
  const c = await signedIn('c@example.com', 'Carleane-Pass-123');
  assert.equal((await c.post('/api/gpl/lookup', { value: '20376942462079' })).status, 403);
});

test('Fees & Commissions and Thresholds & Limits: options from Superset, exact-match filters, permissions', async () => {
  const admin = await signedIn('boss@example.com', 'Another-Long-Pass-2');
  let r = await admin.get('/api/ref/fees/options'); assert.equal(r.status, 200);
  assert.deepEqual(r.data.options.service_name, ['AGENT_TOPUP', 'COLLECT_PAY']);
  r = await admin.post('/api/ref/fees/query', { filters: { service_name: 'COLLECT_PAY' } }); assert.equal(r.data.rows.length, 2);
  r = await admin.post('/api/ref/fees/query', { filters: { service_name: 'COLLECT_PAY', SENDER_PROFILE: 'MMGAgent' } }); assert.equal(r.data.rows.length, 0);
  r = await admin.post('/api/ref/fees/query', { filters: {} }); assert.equal(r.data.rows.length, 3);
  assert.equal((await admin.post('/api/ref/fees/query', { filters: { service_name: "x' OR 1=1 --" } })).status, 400); // only values Superset listed are accepted
  r = await admin.post('/api/ref/limits/query', { filters: { PROFILE_NAME: 'Biller', service_display_name: 'Bill Payment' } });
  assert.equal(r.data.rows.length, 1); assert.equal(r.data.rows[0].max_send_amt, '$1,000,000');
  assert.equal((await admin.get('/api/ref/nope/options')).status, 404);
  const c = await signedIn('c@example.com', 'Carleane-Pass-123');
  assert.equal((await c.get('/api/ref/fees/options')).status, 403); // Agent has no fees access
  const a = await admin.get('/api/admin/audit?limit=50'); assert.ok(a.data.events.some((e) => /Fees & Commissions: service_name = COLLECT_PAY/.test(e.detail)));
});

test('a wrong curl pasted into a connection cannot break its search fields; reset restores the defaults', async () => {
  const admin = await signedIn('boss@example.com', 'Another-Long-Pass-2');
  const saved = await store.getSetting('connections');
  const before = JSON.parse(JSON.stringify(saved));
  saved['search.lookup'] = { ...saved['search.lookup'], searchCols: ['MOBILE_NUMBER', 'USER_NAME'], columns: ['USER_ID'], dateCol: 'CREATED_DATE' };
  await store.setSetting('connections', saved);
  let c = (await admin.get('/api/admin/connections')).data.connections['search.lookup'];
  assert.equal(c.searchCols.length, 7); assert.equal(c.columns.length, 18); assert.ok(c.columns.includes('LAST_NAME')); assert.equal(c.dateCol, ''); // fixed by the app
  assert.equal((await admin.put('/api/admin/connections/search.lookup', { searchCols: ['EMAIL_ID'], columns: ['x'], dateCol: 'CREATED_DATE', timeoutSec: 60 })).status, 200);
  c = (await admin.get('/api/admin/connections')).data.connections['search.lookup']; assert.equal(c.searchCols.length, 7); assert.equal(c.columns.length, 18);
  const hit = await admin.post('/api/search', { filters: { USER_NAME: '6010256' } }); assert.equal(hit.status, 200); assert.equal(hit.data.rows[0].LAST_NAME, 'Persaud'); // last name still comes back
  const r = await admin.del('/api/admin/connections/search.lookup'); assert.equal(r.status, 200);
  assert.equal(r.data.columns.length, 18); assert.equal(r.data.dateCol, ''); assert.equal(r.data.envs.uat.datasource, 76);
  assert.equal((await admin.del('/api/admin/connections/nope')).status, 404);
  await store.setSetting('connections', before); // put the test servers back
});
