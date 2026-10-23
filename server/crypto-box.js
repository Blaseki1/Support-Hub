// Field encryption (AES-256-GCM) and a blind index (HMAC) so encrypted emails can still be looked up.
// The key comes from APP_ENCRYPTION_KEY. Lose the key and encrypted data cannot be read, so back it up.
const crypto = require('crypto');

function makeBox(secret) {
  if (!secret) throw new Error('APP_ENCRYPTION_KEY is not set.');
  const key = /^[0-9a-f]{64}$/i.test(secret) ? Buffer.from(secret, 'hex') : crypto.scryptSync(secret, 'support-hub-v1', 32);
  const idxKey = crypto.createHmac('sha256', key).update('index').digest();
  return {
    enc(text) {
      if (text == null) return null;
      const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv);
      const ct = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
      return 'v1:' + [iv, c.getAuthTag(), ct].map((b) => b.toString('base64')).join(':');
    },
    dec(blob) {
      if (blob == null) return null;
      const [v, iv, tag, ct] = String(blob).split(':');
      if (v !== 'v1') return String(blob); // not encrypted (older rows)
      const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64')); d.setAuthTag(Buffer.from(tag, 'base64'));
      return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8');
    },
    blind: (s) => crypto.createHmac('sha256', idxKey).update(String(s).toLowerCase()).digest('hex'),
    // passwords: peppered so a stolen database alone cannot be cracked offline
    pepper: (pw) => crypto.createHmac('sha256', key).update('pw:' + pw).digest('base64'),
  };
}

// Wraps a store so names, emails, audit text, session names and Superset logins are encrypted at rest.
function secureStore(raw, box) {
  const { enc, dec } = box;
  const outUser = (u) => (u ? { ...u, name: dec(u.name), email: dec(u.email) } : null);
  const inUser = (p) => { const o = { ...p }; if ('name' in o) o.name = enc(o.name); if ('email' in o) { o.emailIdx = box.blind(o.email); o.email = enc(o.email); } return o; };
  const outAudit = (e) => ({ ...e, uname: dec(e.uname), detail: dec(e.detail) });
  return {
    ...raw, kind: raw.kind,
    init: () => raw.init(), close: () => raw.close(), ping: () => raw.ping(),
    async findUserByEmail(e) { return outUser(await raw.findUserByEmail(box.blind(e))); },
    async getUser(i) { return outUser(await raw.getUser(i)); },
    async listUsers() { return (await raw.listUsers()).map(outUser); },
    async createUser(u) { return outUser(await raw.createUser(inUser(u))); },
    async updateUser(i, p) { return outUser(await raw.updateUser(i, inUser(p))); },
    async createSession(s) { return raw.createSession({ ...s, uname: enc(s.uname) }); },
    async getSessionByHash(h) { const s = await raw.getSessionByHash(h); return s && { ...s, uname: dec(s.uname) }; },
    async listSessions() { return (await raw.listSessions()).map((s) => ({ ...s, uname: dec(s.uname) })); },
    async addAudit(e) { return raw.addAudit({ ...e, uname: enc(e.uname), detail: enc(e.detail) }); },
    async listAudit(n) { return (await raw.listAudit(n)).map(outAudit); },
    async recentForUser(u, n) { return (await raw.recentForUser(u, n)).map(outAudit); },
    // Superset logins pasted from a curl: only ever stored encrypted
    async getSecret(k) { const v = await raw.getSetting('secret:' + k); return v ? JSON.parse(dec(v)) : null; },
    async setSecret(k, obj) { await raw.setSetting('secret:' + k, enc(JSON.stringify(obj))); },
  };
}
module.exports = { makeBox, secureStore };
