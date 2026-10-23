// Seeds MongoDB (or the memory store, as a dry run). Safe to run again: it only adds what is missing.
//   npm run seed                 indexes + first admin + default Superset connections
//   npm run seed -- --demo       also adds three example people (Supervisor, Agent, Agent) with temporary passwords
const config = require('../server/config');
const { memoryStore, mongoStore } = require('../server/store');
const { makeBox, secureStore } = require('../server/crypto-box');
const A = require('../server/auth');
const D = require('../server/defaults');
const { ensureAdmin } = require('../server/bootstrap');

(async () => {
  if (config.store === 'mongo' && (!config.mongoUri || !config.encryptionKey)) { console.error('Set MONGODB_URI and APP_ENCRYPTION_KEY in .env first.'); process.exit(1); }
  const box = makeBox(config.encryptionKey || require('crypto').randomBytes(32).toString('hex')); A.setPepper(box.pepper);
  const store = secureStore(config.store === 'mongo' ? mongoStore(config.mongoUri, config.mongoDb) : memoryStore(), box);
  console.log(config.envFile ? 'Read settings from ' + config.envFile : 'No .env file found here. Using environment variables only.');
  if (config.store !== 'mongo') { console.error('\nSTOPPED: this would use the in-memory store, so nothing would reach MongoDB.\nMONGODB_URI is empty. Run this from the project folder that holds your .env file.'); process.exit(1); }
  console.log('Connecting to MongoDB, database "' + config.mongoDb + '"...');
  await store.init(); // creates the database, collections and indexes
  console.log('Connected. Collections and indexes ready (users, sessions, audit, options, settings).');

  const made = await ensureAdmin(store, config);
  console.log(made ? 'Admin created.' : 'Admin already exists, left unchanged.');

  if (!(await store.getSetting('connections'))) { await store.setSetting('connections', D.defaultConnections()); console.log('Default Superset connections saved (UAT filled in from your curls, PROD blank).'); }
  else console.log('Superset connections already set, left unchanged.');

  if (process.argv.includes('--demo')) {
    const people = [['Marcus Hinds', 'marcus@example.com', 'Supervisor'], ['Carleane Dos Santos', 'carleane@example.com', 'Agent'], ['Priya Singh', 'priya@example.com', 'Agent']];
    for (const [name, email, role] of people) {
      if (await store.findUserByEmail(email)) { console.log('Exists:', email); continue; }
      const tmp = A.tempPassword();
      await store.createUser({ name, email, role, perms: D.roleDefaults(role), status: 'active', passwordHash: await A.hash(tmp), mustChange: true });
      console.log(`Added ${role} ${email}  temporary password: ${tmp}`);
    }
    console.log('Delete these example people in Users & Permissions before real use.');
  }
  const users = await store.listUsers();
  console.log('\nCheck: ' + users.length + ' user(s) now in ' + config.mongoDb + '.users: ' + users.map((u) => u.email + ' (' + u.role + ')').join(', '));
  console.log('Refresh Data Explorer to see them.');
  await store.close();
})().catch((e) => {
  const m = String(e.message || e);
  console.error('\nSeed failed:', m);
  if (/Server selection|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|timed out/i.test(m)) console.error('Cannot reach the cluster. In Atlas > Network Access, add the IP address of THIS computer (or "Add current IP address"), then try again. Also check the address in MONGODB_URI.');
  if (/auth|bad auth|Authentication/i.test(m)) console.error('Atlas rejected the username or password. Check them in Database Access, and URL-encode special characters in the password.');
  process.exit(1);
});
