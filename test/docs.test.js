const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
const { createApp } = require('../server/app');
const { memoryStore } = require('../server/store');
const { Superset } = require('../server/superset');
const { ensureAdmin } = require('../server/bootstrap');
const { makeBox, secureStore } = require('../server/crypto-box');
const A = require('../server/auth');
const D = require('../server/defaults');
const S3 = require('../server/s3');
const fake = require('./fake-superset');

const JPG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.from('jfif-data')]);
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from('png-data')]);
const FILES = { 'public_images/20372034818943/1760869793603_IDType.nationalId': JPG, 'public_images/20372034831153/1760869805814__selfie': PNG /* labelled jpeg in Superset but really a png */ };
const fakeS3 = { gets: [], async get(key) { this.gets.push(key); if (!FILES[key]) { const e = new Error('nope'); e.name = 'NoSuchKey'; throw e; } return { body: FILES[key], contentType: 'binary/octet-stream' }; }, async head(key) { if (!FILES[key]) { const e = new Error('nope'); e.name = 'NotFound'; throw e; } return { length: FILES[key].length, contentType: 'binary/octet-stream' }; }, async list() { return { count: 1 }; } };

let F, srv, base, store;
const config = { sessionHours: 12, idleMinutes: 120, secureCookie: false, trustProxy: false, adminEmail: 'boss@example.com', adminName: 'Boss', adminPassword: 'Correct-Horse-1', historyKeepMinutes: 30, superset: { uat: {}, prod: {} }, s3: { bucket: 'b', region: 'us-east-1', prefix: 'public_images/' } };
class Client {
  constructor() { this.cookie = ''; }
  async req(method, url, body) {
    const r = await fetch(base + url, { method, headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'hub', Cookie: this.cookie }, body: body === undefined ? undefined : JSON.stringify(body) });
    const sc = r.headers.get('set-cookie'); if (sc) this.cookie = sc.split(';')[0];
    const ct = r.headers.get('content-type') || ''; const data = ct.includes('json') ? await r.json() : Buffer.from(await r.arrayBuffer());
    return { status: r.status, data, headers: r.headers };
  }
  get(u) { return this.req('GET', u); } post(u, b) { return this.req('POST', u, b || {}); }
}
async function login(email, pw) { const c = new Client(); const r = await c.post('/api/auth/login', { email, password: pw }); assert.equal(r.status, 200); return c; }

test.before(async () => {
  F = await fake.start(0, {});
  const box = makeBox('k'); A.setPepper(box.pepper); store = secureStore(memoryStore(), box); await store.init(); await ensureAdmin(store, config);
  await store.setSetting('connections', { 'docs.lookup': { envs: { uat: { base: 'http://127.0.0.1:' + F.port } } }, 'txns.lookup': { envs: { uat: { base: 'http://127.0.0.1:' + F.port } } } });
  await store.setSecret('superset:uat', { headers: { Cookie: 'session=abc', 'X-CSRFToken': 'csrf1', Authorization: 'Bearer tok1' }, at: 'x', by: 't' });
  // a second person who may look up documents but not download them
  await store.createUser({ name: 'Viewer', email: 'v@example.com', role: 'Agent', perms: ['docs'], status: 'active', passwordHash: await A.hash('Viewer-Pass-12345') });
  await store.createUser({ name: 'Nodocs', email: 'n@example.com', role: 'Agent', perms: ['search'], status: 'active', passwordHash: await A.hash('Nodocs-Pass-12345') });
  const superset = new Superset(config.superset, (env) => store.getSecret('superset:' + env), async () => {});
  const app = createApp({ store, superset, config, gpl: null, s3: S3.makeS3(config.s3, fakeS3) });
  await new Promise((r) => { srv = app.listen(0, '127.0.0.1', r); }); base = 'http://127.0.0.1:' + srv.address().port;
});
test.after(async () => { srv.close(); await F.close(); });
let adminC; const admin = async () => adminC || (adminC = await (async () => { const c = await login('boss@example.com', 'Correct-Horse-1'); await c.post('/api/auth/change-password', { current: 'Correct-Horse-1', next: 'Another-Long-Pass-2' }); return c; })());

test('Deleted Docs is a module that Admins get by default and Agents do not', () => {
  assert.ok(D.MODULES.some((m) => m.id === 'docs')); assert.ok(D.roleDefaults('Admin').includes('docs')); assert.ok(!D.roleDefaults('Agent').includes('docs'));
});
test('safeKey blocks traversal and anything outside public_images/', () => {
  const p = 'public_images/';
  assert.ok(S3.safeKey('public_images/1/a_b', p));
  for (const bad of ['../etc/passwd', 'public_images/../x', '/public_images/1/a', 'other/1/a', 'public_images//a', 'public_images/1/a\\b', 'public_images/', 'public_images/1/a?x=1', null, 123]) assert.equal(S3.safeKey(bad, p), null, String(bad));
});
test('extension follows the real file contents, then the content type', () => {
  assert.equal(S3.sniff(JPG, 'image/png'), 'jpg'); assert.equal(S3.sniff(PNG, 'image/jpeg'), 'png');
  assert.equal(S3.sniff(Buffer.from('zzzz'), 'image/jpeg'), 'jpg'); assert.equal(S3.sniff(Buffer.from('zzzz'), ''), 'bin');
  assert.equal(S3.fileName('32248', '20372034831153', 'public_images/x/1760869805814__selfie', 'jpg'), '32248_20372034831153_selfie.jpg');
  assert.equal(S3.labelOf('public_images/x/1760869793603_IDType.nationalId'), 'IDType_nationalId');
});
test('lookup lists every file for the partner, flags bad paths and missing files', async () => {
  const c = await admin(), r = await c.post('/api/docs/lookup', { partner: '32248' });
  assert.equal(r.status, 200); assert.equal(r.data.files.length, 4); assert.equal(r.data.s3.ok, true);
  const by = Object.fromEntries(r.data.files.map((f) => [f.docId, f]));
  assert.equal(by['20372034818943'].state, 'ok'); assert.equal(by['20372034818943'].name, '32248_20372034818943_IDType_nationalId.jpg');
  assert.equal(by['20372034831154'].state, 'missing'); assert.equal(by['1'].state, 'bad'); assert.equal(by['1'].key, null);
  assert.equal((await c.post('/api/docs/lookup', { partner: "1' OR 1=1" })).status, 400);
  assert.equal((await c.post('/api/docs/lookup', { partner: '555' })).data.files.length, 1);
});
test('download sets the extension from the real file and only allows looked-up paths', async () => {
  const c = await admin();
  await c.post('/api/docs/lookup', { partner: '32248' });
  const a = await c.get('/api/docs/file?key=' + encodeURIComponent('public_images/20372034818943/1760869793603_IDType.nationalId'));
  assert.equal(a.status, 200); assert.match(a.headers.get('content-disposition'), /32248_20372034818943_IDType_nationalId\.jpg/); assert.equal(a.headers.get('content-type'), 'image/jpeg'); assert.deepEqual(a.data, JPG);
  const b = await c.get('/api/docs/file?key=' + encodeURIComponent('public_images/20372034831153/1760869805814__selfie'));
  assert.match(b.headers.get('content-disposition'), /selfie\.png/); // Superset said jpeg, the bytes are png
  assert.equal((await c.get('/api/docs/file?key=' + encodeURIComponent('../../etc/passwd'))).status, 400);
  assert.equal((await c.get('/api/docs/file?key=' + encodeURIComponent('public_images/999/never-listed'))).status, 403);
});
test('zip holds every file that exists, with correct names, and notes the ones that failed', async () => {
  const c = await admin(); await c.post('/api/docs/lookup', { partner: '32248' });
  const z = await c.get('/api/docs/zip?partner=32248'); assert.equal(z.status, 200); assert.equal(z.headers.get('content-type'), 'application/zip');
  const names = [...z.data.toString('latin1').matchAll(/(32248_[\w]+\.\w+|_not_downloaded\.txt)/g)].map((m) => m[1]);
  assert.ok(names.includes('32248_20372034818943_IDType_nationalId.jpg')); assert.ok(names.includes('32248_20372034831153_selfie.png')); assert.ok(names.includes('_not_downloaded.txt'));
  assert.equal((await c.get('/api/docs/zip?partner=777')).status, 403);
});
test('permissions: lookup needs docs, download also needs the images permission', async () => {
  const v = await login('v@example.com', 'Viewer-Pass-12345');
  const r = await v.post('/api/docs/lookup', { partner: '32248' }); assert.equal(r.status, 200); assert.equal(r.data.canDownload, false);
  assert.equal((await v.get('/api/docs/file?key=' + encodeURIComponent('public_images/20372034818943/1760869793603_IDType.nationalId'))).status, 403);
  assert.equal((await v.get('/api/docs/zip?partner=32248')).status, 403);
  const n = await login('n@example.com', 'Nodocs-Pass-12345');
  assert.equal((await n.post('/api/docs/lookup', { partner: '32248' })).status, 403);
});
test('account lookup finds a Partner ID from a username; admin can test S3', async () => {
  const c = await admin(), r = await c.post('/api/docs/accounts', { value: '6010256' });
  assert.equal(r.status, 200); assert.equal(r.data.rows[0].PARTNER_ID, 's100');
  const t = await c.post('/api/admin/s3/test'); assert.equal(t.data.ok, true);
});
test('downloads are written to the audit log', async () => {
  const c = await admin(); const a = await c.get('/api/admin/audit?limit=50');
  const txt = JSON.stringify(a.data); assert.match(txt, /Downloaded document 20372034818943 for Partner ID 32248/);
});
