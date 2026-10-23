// Reads files from the S3 bucket. All AWS calls happen here, on the server. Credentials never reach the browser.
// Credentials come from the normal AWS chain: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in .env, or the folder
// made by "aws configure" (~/.aws), or an IAM role on the server. Nothing is stored in the database.
const { httpErr } = require('./queries');

const EXT = { 'image/jpeg': 'jpg', 'image/jpg': 'jpg', 'image/pjpeg': 'jpg', 'image/png': 'png', 'image/gif': 'gif', 'image/webp': 'webp', 'image/bmp': 'bmp', 'image/tiff': 'tif', 'image/heic': 'heic', 'application/pdf': 'pdf' };
const MIME = { jpg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp', tif: 'image/tiff', heic: 'image/heic', pdf: 'application/pdf' };

// What the file really is, from its first bytes. Falls back to the content type Superset gave, then to "bin".
function sniff(buf, contentType) {
  const b = buf || Buffer.alloc(0), has = (...a) => a.every((x, i) => b[i] === x);
  if (has(0xff, 0xd8, 0xff)) return 'jpg';
  if (has(0x89, 0x50, 0x4e, 0x47)) return 'png';
  if (has(0x47, 0x49, 0x46, 0x38)) return 'gif';
  if (has(0x25, 0x50, 0x44, 0x46)) return 'pdf';
  if (has(0x42, 0x4d)) return 'bmp';
  if (b.length > 12 && b.toString('latin1', 0, 4) === 'RIFF' && b.toString('latin1', 8, 12) === 'WEBP') return 'webp';
  if (b.length > 12 && b.toString('latin1', 4, 8) === 'ftyp' && /hei|mif1/.test(b.toString('latin1', 8, 12))) return 'heic';
  if (has(0x49, 0x49, 0x2a, 0x00) || has(0x4d, 0x4d, 0x00, 0x2a)) return 'tif';
  return EXT[String(contentType || '').toLowerCase().split(';')[0].trim()] || 'bin';
}

// Only keys under the allowed folder, with no "..", no leading slash and only plain characters.
function safeKey(key, prefix) {
  const k = String(key == null ? '' : key);
  if (!k.startsWith(prefix) || k.length > 400 || k.includes('..') || k.includes('\\') || k.includes('//') || !/^[\w\-./ ]+$/.test(k) || k.endsWith('/')) return null;
  return k;
}

// "1760869793603_IDType.nationalId" -> "IDType_nationalId",  "1760869805814__selfie" -> "selfie"
function labelOf(key) {
  const base = String(key).split('/').pop().replace(/^\d+_+/, '').replace(/[^A-Za-z0-9-]+/g, '_').replace(/^_+|_+$/g, '');
  return base || 'file';
}
const fileName = (partner, docId, key, ext) => `${String(partner).replace(/[^\w-]/g, '')}_${String(docId).replace(/[^\w-]/g, '')}_${labelOf(key)}.${ext}`;

// For trying the app without AWS: S3_LOCAL_DIR=/some/folder makes that folder act as the bucket. Not for production.
function localClient(dir) {
  const fs = require('fs'), path = require('path'), root = path.resolve(dir);
  const file = (key) => { const f = path.resolve(root, key); if (!f.startsWith(root + path.sep)) throw Object.assign(new Error('bad'), { name: 'NotFound' }); return f; };
  const nf = () => Object.assign(new Error('nope'), { name: 'NoSuchKey' });
  return { async get(k) { try { return { body: fs.readFileSync(file(k)) }; } catch (e) { throw nf(); } }, async head(k) { try { return { length: fs.statSync(file(k)).size }; } catch (e) { throw nf(); } }, async list() { return { count: 1 }; } };
}
function makeS3(cfg, injected) {
  if (!injected && cfg.localDir) { injected = localClient(cfg.localDir); cfg = { ...cfg, region: cfg.region || 'local' }; }
  const MAX = (cfg.maxMb || 30) * 1048576;
  let client = injected || null;
  const sdk = () => {
    if (client) return client;
    if (!cfg.region) throw httpErr(503, 'AWS is not set up yet. Set AWS_REGION (and the AWS login) on the server. See the README, step "Deleted Docs".', 's3_config');
    const { S3Client, GetObjectCommand, HeadObjectCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');
    const c = new S3Client({ region: cfg.region, maxAttempts: 3 });
    client = {
      async get(key) { const r = await c.send(new GetObjectCommand({ Bucket: cfg.bucket, Key: key })); return { body: r.Body, contentType: r.ContentType, length: r.ContentLength }; },
      async head(key) { const r = await c.send(new HeadObjectCommand({ Bucket: cfg.bucket, Key: key })); return { length: r.ContentLength, contentType: r.ContentType }; },
      async list(prefix) { const r = await c.send(new ListObjectsV2Command({ Bucket: cfg.bucket, Prefix: prefix, MaxKeys: 1 })); return { count: r.KeyCount || 0 }; },
    };
    return client;
  };
  const friendly = (e, key) => {
    const n = (e && (e.name || e.Code)) || '';
    if (e && e.status && e.code) return e;
    if (n === 'NoSuchKey' || n === 'NotFound') return httpErr(404, 'That file is not in S3 (it may have been removed).', 'missing');
    if (n === 'AccessDenied' || n === 'Forbidden') return httpErr(502, 'AWS refused access. Check that the server login has s3:GetObject on ' + cfg.prefix + '* and s3:ListBucket on the bucket.', 's3_denied');
    if (/Credential|credentials|CredentialsProviderError/i.test(n + ' ' + (e && e.message))) return httpErr(503, 'The server has no AWS login. Run "aws configure" as the user that runs the hub, or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.', 's3_creds');
    if (n === 'NoSuchBucket') return httpErr(502, 'The bucket "' + cfg.bucket + '" was not found. Check S3_BUCKET and AWS_REGION.', 's3_bucket');
    return httpErr(502, 'S3 error: ' + String((e && e.message) || e).slice(0, 200), 's3_error');
  };
  const read = async (body) => { const parts = []; let n = 0; for await (const c of body) { n += c.length; if (n > MAX) throw httpErr(413, 'That file is larger than ' + (cfg.maxMb || 30) + ' MB.'); parts.push(c); } return Buffer.concat(parts); };
  return {
    cfg,
    configured: () => !!(injected || cfg.region),
    async fetch(key) { try { const r = await sdk().get(key); const buf = Buffer.isBuffer(r.body) ? r.body : await read(r.body); return { buf, contentType: r.contentType }; } catch (e) { throw friendly(e, key); } },
    async head(key) { try { return await sdk().head(key); } catch (e) { throw friendly(e, key); } },
    async test() { try { const r = await sdk().list(cfg.prefix); return { ok: true, message: 'Connected to "' + cfg.bucket + '" in ' + cfg.region + '.' + (r.count ? '' : ' (The folder looks empty.)') }; } catch (e) { const f = friendly(e); return { ok: false, code: f.code, error: f.message }; } },
  };
}
module.exports = { makeS3, safeKey, sniff, labelOf, fileName, MIME, EXT };
