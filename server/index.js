const config = require('./config');
const { createApp } = require('./app');
const { memoryStore, mongoStore } = require('./store');
const { Superset } = require('./superset');
const { Gpl } = require('./gpl');
const { ensureAdmin } = require('./bootstrap');
const { makeBox, secureStore } = require('./crypto-box');
const crypto = require('crypto');
const A = require('./auth');

(async () => {
  const store = config.store === 'mongo' ? mongoStore(config.mongoUri, config.mongoDb) : memoryStore();
  if (config.store === 'mongo' && !config.mongoUri) { console.error('STORE=mongo needs MONGODB_URI.'); process.exit(1); }
  let key = config.encryptionKey;
  if (!key) {
    if (config.store === 'mongo') { console.error('APP_ENCRYPTION_KEY is required. Generate one with: openssl rand -hex 32'); process.exit(1); }
    key = crypto.randomBytes(32).toString('hex'); console.warn('No APP_ENCRYPTION_KEY set: using a temporary key (memory store only).');
  }
  const box = makeBox(key); A.setPepper(box.pepper);
  const raw = store; const sec = secureStore(raw, box);
  await sec.init();
  await ensureAdmin(sec, config);
  const superset = new Superset(config.superset, (env) => sec.getSecret('superset:' + env), async (env, headers) => { const cur = (await sec.getSecret('superset:' + env)) || {}; await sec.setSecret('superset:' + env, { ...cur, headers, refreshed: new Date().toISOString() }); });
  const gpl = new Gpl((env) => sec.getSecret('gpl:' + env), async (env, headers) => { const cur = (await sec.getSecret('gpl:' + env)) || {}; await sec.setSecret('gpl:' + env, { ...cur, headers }); });
  const app = createApp({ store: sec, superset, config, gpl });
  const srv = app.listen(config.port, () => console.log(`Support Hub on http://localhost:${config.port}  (store: ${store.kind})`));
  if (store.kind === 'memory') console.warn('Using the in-memory store: users, sessions and the audit log are lost on restart. Set MONGODB_URI for real use.');
  const stop = () => srv.close(() => store.close().then(() => process.exit(0))); process.on('SIGTERM', stop); process.on('SIGINT', stop);
})().catch((e) => { console.error('Could not start:', e.message); process.exit(1); });
