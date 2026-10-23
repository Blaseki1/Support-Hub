// All settings come from environment variables (see .env.example).
// Reads .env from the project folder (or where you start the app) so you do not have to export anything.
// Real environment variables win over the file. Quotes and "# comments" after a value are handled.
(function loadEnv() {
  const fs = require('fs'), path = require('path');
  for (const dir of [process.cwd(), path.join(__dirname, '..')]) {
    const f = path.join(dir, '.env'); if (!fs.existsSync(f)) continue;
    for (let line of fs.readFileSync(f, 'utf8').replace(/^\uFEFF/, '').split(/\r?\n/)) {
      line = line.trim(); if (!line || line[0] === '#') continue;
      const m = line.replace(/^export\s+/, '').match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/); if (!m) continue;
      let v = m[2];
      if (/^["']/.test(v)) { const q = v[0], end = v.indexOf(q, 1); v = end > 0 ? v.slice(1, end) : v.slice(1); } else v = v.replace(/\s+#.*$/, '').trim();
      if (process.env[m[1]] === undefined) process.env[m[1]] = v;
    }
    module.exports.envFile = f; break;
  }
})();
const num = (v, d) => (v === undefined || v === '' || isNaN(Number(v)) ? d : Number(v));
Object.assign(module.exports, {
  port: num(process.env.PORT, 3000),
  store: process.env.STORE || (process.env.MONGODB_URI ? 'mongo' : 'memory'),
  mongoUri: process.env.MONGODB_URI || '',
  mongoDb: process.env.MONGODB_DB || 'support_hub',
  sessionHours: num(process.env.SESSION_HOURS, 12),
  idleMinutes: num(process.env.IDLE_MINUTES, 120),
  secureCookie: process.env.COOKIE_SECURE === 'true',
  trustProxy: process.env.TRUST_PROXY === 'true',
  adminEmail: (process.env.ADMIN_EMAIL || 'admin@example.com').toLowerCase(),
  adminName: process.env.ADMIN_NAME || 'Admin',
  adminPassword: process.env.ADMIN_PASSWORD || '', // blank = a random one is printed on first start
  encryptionKey: process.env.APP_ENCRYPTION_KEY || '',
  // Optional service-account fallback. Normally leave these blank: paste a curl under Data Sources instead.
  // Superset credentials per environment. A service account is best: browser cookies expire.
  superset: {
    uat: { user: process.env.SUPERSET_UAT_USER || '', pass: process.env.SUPERSET_UAT_PASSWORD || '', token: process.env.SUPERSET_UAT_TOKEN || '', cookie: process.env.SUPERSET_UAT_COOKIE || '' },
    prod: { user: process.env.SUPERSET_PROD_USER || '', pass: process.env.SUPERSET_PROD_PASSWORD || '', token: process.env.SUPERSET_PROD_TOKEN || '', cookie: process.env.SUPERSET_PROD_COOKIE || '' },
  },
  s3: { bucket: process.env.S3_BUCKET || 'mmg-s3-apps-prod', region: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || '', prefix: process.env.S3_PREFIX || 'public_images/', maxMb: num(process.env.S3_MAX_MB, 30), localDir: process.env.S3_LOCAL_DIR || '' },
  historyKeepMinutes: num(process.env.HISTORY_KEEP_MINUTES, 30),
});
