// One interface, two implementations: MongoDB (real) and memory (tests / quick trial; data is lost on restart).
const crypto = require('crypto');
const id = () => crypto.randomBytes(8).toString('hex');

function memoryStore() {
  const users = [], sessions = [], audit = [], options = []; const settings = {};
  return {
    kind: 'memory', async init() {}, async close() {}, async ping() { return true; },
    async findUserByEmail(e) { return users.find((u) => u.emailIdx === e) || null; },
    async getUser(i) { return users.find((u) => u.id === i) || null; },
    async listUsers() { return users.map((u) => ({ ...u })); },
    async createUser(u) { const x = { id: 'u_' + id(), createdAt: new Date(), ...u }; users.push(x); return x; },
    async updateUser(i, patch) { const u = users.find((x) => x.id === i); if (!u) return null; Object.assign(u, patch); return u; },
    async deleteUser(i) { const k = users.findIndex((x) => x.id === i); if (k >= 0) users.splice(k, 1); },
    async countUsersWithPerm(p, exceptId) { return users.filter((u) => u.status === 'active' && u.perms.includes(p) && u.id !== exceptId).length; },
    async createSession(s) { const x = { id: 's_' + id(), createdAt: new Date(), lastSeen: new Date(), ...s }; sessions.push(x); return x; },
    async getSessionByHash(h) { return sessions.find((s) => s.tokenHash === h) || null; },
    async touchSession(i) { const s = sessions.find((x) => x.id === i); if (s) s.lastSeen = new Date(); },
    async listSessions() { return sessions.map((s) => ({ ...s })); },
    async deleteSession(i) { const k = sessions.findIndex((x) => x.id === i); if (k >= 0) sessions.splice(k, 1); return k >= 0; },
    async deleteSessionsForUser(uid, exceptId) { for (let k = sessions.length - 1; k >= 0; k--) if (sessions[k].uid === uid && sessions[k].id !== exceptId) sessions.splice(k, 1); },
    async deleteExpired(before) { for (let k = sessions.length - 1; k >= 0; k--) if (sessions[k].expiresAt < before || sessions[k].lastSeen < new Date(before - 0)) { if (sessions[k].expiresAt < before) sessions.splice(k, 1); } },
    async addAudit(e) { audit.push({ id: 'a_' + id(), ts: new Date(), ...e }); },
    async listAudit(limit) { return audit.slice(-limit).reverse(); },
    async recentForUser(uid, n) { return audit.filter((a) => a.uid === uid && ['search', 'open'].includes(a.act)).slice(-n).reverse(); },
    async countForUser(uid, act) { return audit.filter((a) => a.uid === uid && a.act === act).length; },
    async getSetting(k) { return settings[k] === undefined ? null : JSON.parse(JSON.stringify(settings[k])); },
    async setSetting(k, v) { settings[k] = JSON.parse(JSON.stringify(v)); },
    async listOptions() { return options.map((o) => ({ ...o })); },
    async createOption(o) { const x = { id: 'c_' + id(), createdAt: new Date(), ...o }; options.push(x); return x; },
    async updateOption(i, patch) { const o = options.find((x) => x.id === i); if (!o) return null; Object.assign(o, patch); return o; },
    async deleteOption(i) { const k = options.findIndex((x) => x.id === i); if (k >= 0) options.splice(k, 1); return k >= 0; },
  };
}

function mongoStore(uri, dbName) {
  const { MongoClient } = require('mongodb');
  let client, db, C;
  const strip = (d) => (d ? (({ _id, ...r }) => r)(d) : null);
  const many = async (cur) => (await cur.toArray()).map(strip);
  return {
    kind: 'mongo',
    async init() {
      client = new MongoClient(uri, { serverSelectionTimeoutMS: 8000 }); await client.connect(); db = client.db(dbName);
      C = { users: db.collection('users'), sessions: db.collection('sessions'), audit: db.collection('audit'), options: db.collection('options'), settings: db.collection('settings') };
      await C.users.createIndex({ id: 1 }, { unique: true }); await C.users.createIndex({ emailIdx: 1 }, { unique: true });
      await C.sessions.createIndex({ tokenHash: 1 }, { unique: true }); await C.sessions.createIndex({ id: 1 }, { unique: true });
      await C.sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // Mongo removes expired sessions itself
      await C.audit.createIndex({ ts: -1 }); await C.audit.createIndex({ uid: 1, act: 1, ts: -1 });
      await C.options.createIndex({ id: 1 }, { unique: true }); await C.settings.createIndex({ key: 1 }, { unique: true });
    },
    async close() { if (client) await client.close(); },
    async ping() { await db.command({ ping: 1 }); return true; },
    async findUserByEmail(e) { return strip(await C.users.findOne({ emailIdx: e })); },
    async getUser(i) { return strip(await C.users.findOne({ id: i })); },
    async listUsers() { return many(C.users.find({}).sort({ createdAt: 1 })); },
    async createUser(u) { const x = { id: 'u_' + id(), createdAt: new Date(), ...u }; await C.users.insertOne({ ...x }); return x; },
    async updateUser(i, patch) { await C.users.updateOne({ id: i }, { $set: patch }); return strip(await C.users.findOne({ id: i })); },
    async deleteUser(i) { await C.users.deleteOne({ id: i }); },
    async countUsersWithPerm(p, exceptId) { return C.users.countDocuments({ status: 'active', perms: p, id: { $ne: exceptId || '' } }); },
    async createSession(s) { const x = { id: 's_' + id(), createdAt: new Date(), lastSeen: new Date(), ...s }; await C.sessions.insertOne({ ...x }); return x; },
    async getSessionByHash(h) { return strip(await C.sessions.findOne({ tokenHash: h })); },
    async touchSession(i) { await C.sessions.updateOne({ id: i }, { $set: { lastSeen: new Date() } }); },
    async listSessions() { return many(C.sessions.find({}).sort({ lastSeen: -1 })); },
    async deleteSession(i) { return (await C.sessions.deleteOne({ id: i })).deletedCount > 0; },
    async deleteSessionsForUser(uid, exceptId) { await C.sessions.deleteMany({ uid, id: { $ne: exceptId || '' } }); },
    async deleteExpired(before) { await C.sessions.deleteMany({ expiresAt: { $lt: before } }); },
    async addAudit(e) { await C.audit.insertOne({ id: 'a_' + id(), ts: new Date(), ...e }); },
    async listAudit(limit) { return many(C.audit.find({}).sort({ ts: -1 }).limit(limit)); },
    async recentForUser(uid, n) { return many(C.audit.find({ uid, act: { $in: ['search', 'open'] } }).sort({ ts: -1 }).limit(n)); },
    async countForUser(uid, act) { return C.audit.countDocuments({ uid, act }); },
    async getSetting(k) { const d = await C.settings.findOne({ key: k }); return d ? d.value : null; },
    async setSetting(k, v) { await C.settings.updateOne({ key: k }, { $set: { value: v } }, { upsert: true }); },
    async listOptions() { return many(C.options.find({}).sort({ createdAt: 1 })); },
    async createOption(o) { const x = { id: 'c_' + id(), createdAt: new Date(), ...o }; await C.options.insertOne({ ...x }); return x; },
    async updateOption(i, patch) { await C.options.updateOne({ id: i }, { $set: patch }); return strip(await C.options.findOne({ id: i })); },
    async deleteOption(i) { return (await C.options.deleteOne({ id: i })).deletedCount > 0; },
  };
}
module.exports = { memoryStore, mongoStore };
