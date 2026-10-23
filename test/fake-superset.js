// A stand-in for Superset so the app can be tried and tested without the real one.
// It behaves like the real datasets: filled filters are OR-ed with LIKE on the search datasets.
const http = require('http');
const acct = (o) => ({ USER_ID: 'x', PARTNER_ID: 'p', STATUS: 'Active', Account_type: 'Customer', USER_NAME: '', MOBILE_NUMBER: '', FIRST_NAME: '', Middle_name: null, LAST_NAME: '', Name: '', DOB: 0, EMAIL_ID: '', CREATED_DATE: Date.UTC(2023, 0, 5), CREATED_BY: 'initial_load', LAST_MODIFIED_DATE: null, LAST_MODIFIED_BY: null, IDENTIFICATION_TYPE: 'Nationalid', ID_NUMBER: null, PLACE_OF_ISSUE: null, ...o });
const ACCOUNTS = [
  acct({ USER_ID: '101', PARTNER_ID: 's100', USER_NAME: '6010256', MOBILE_NUMBER: '5926010256', FIRST_NAME: 'Anna', LAST_NAME: 'Persaud', Name: 'Persaud', EMAIL_ID: 'anna@example.com', ID_NUMBER: 'R1234567' }),
  acct({ USER_ID: '102', PARTNER_ID: 's200', USER_NAME: '6010999', MOBILE_NUMBER: '5926010999', FIRST_NAME: 'Anna', LAST_NAME: 'Singh', Name: 'Singh', EMAIL_ID: 'asingh@example.com', ID_NUMBER: 'D7654321', Account_type: 'Agent' }),
  acct({ USER_ID: '103', PARTNER_ID: 's300', USER_NAME: '6800922', MOBILE_NUMBER: '5926800922', FIRST_NAME: 'Marcus', LAST_NAME: 'Persaud', Name: 'Persaud', EMAIL_ID: 'marcus@example.com', ID_NUMBER: 'P1111111', STATUS: 'Terminated' }),
];
const day = (n) => Date.UTC(2026, 9, n);
const TXNS = [];
for (let i = 1; i <= 40; i++) TXNS.push({ TRANSACTION_ID: String(2040000000000 + i), TRANS_DATE: day(i % 28 + 1), TRANS_TIME: '10:00:00', TRANSACTION_DATE: day(i % 28 + 1) + 36000000, STATUS_TYPE: i % 7 ? 'Success' : 'Failure', SERVICE_NAME: 'CASH_IN', WALLET_ID: '300001', WALLET_PARTNER_ID: i % 2 ? 's100' : 's200', WALLET_TYPE_ID: 1, WALLET_SIDE: 'DP', WALLET_NET_AMOUNT: 1000 * i, TRANSACTION_AMOUNT: 1000 * i, WALLET_BAL_BEFORE: 0, WALLET_BAL_AFTER: 1000 * i, OP_FEE: 0, DP_FEE: 0 });

function start(port = 0, opts = {}) {
  const calls = [];
  const srv = http.createServer((req, res) => {
    let raw = ''; req.on('data', (c) => (raw += c));
    req.on('end', async () => {
      const send = (code, o, h = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', ...h }); res.end(JSON.stringify(o)); };
      const u = new URL(req.url, 'http://x'); req.path0 = u.pathname;
      if (req.url === '/api/v1/security/login') { const b = JSON.parse(raw); calls.push({ url: req.url, user: b.username }); return b.username === 'svc' && b.password === 'pw' ? send(200, { access_token: 'tok1' }, { 'Set-Cookie': 'session=abc; Path=/; HttpOnly' }) : send(401, { message: 'bad' }); }
      if (req.url === '/api/v1/security/csrf_token/') return send(200, { result: 'csrf1' });
      if (req.path0 === '/api/v1/chart/data') {
        if (!u.searchParams.get('dashboard_id') || !JSON.parse(u.searchParams.get('form_data') || '{}').slice_id || !req.headers.origin || !req.headers.referer) return send(400, { message: 'missing dashboard context' });
        if (req.headers.authorization !== 'Bearer tok1' || req.headers['x-csrftoken'] !== 'csrf1' || !/session=abc/.test(req.headers.cookie || '')) return send(401, { message: 'no' });
        const b = JSON.parse(raw), qy = b.queries[0], id = b.datasource.id; calls.push({ url: req.url, id, filters: qy.filters, headers: req.headers });
        const f = qy.filters.filter((x) => x.op === 'IN');
        if (f.some((x) => x.val.includes('slow')) && opts.slowMs) await new Promise((r) => setTimeout(r, opts.slowMs));
        let data;
        if (id === 73) { const pid = f.find((x) => x.col === 'WALLET_PARTNER_ID').val[0]; data = TXNS.filter((t) => t.WALLET_PARTNER_ID === pid); const tr = qy.filters.find((x) => x.op === 'TEMPORAL_RANGE'); if (tr && tr.val !== 'No filter') { const [a, z] = tr.val.split(' : ').map((s) => Date.parse(s + 'Z')); data = data.filter((t) => t.TRANS_DATE >= a && t.TRANS_DATE < z); } data = data.slice(0, qy.row_limit); }
        else data = ACCOUNTS.filter((a) => f.some((x) => x.val.some((v) => String(a[x.col] == null ? '' : a[x.col]).toLowerCase().includes(String(v).toLowerCase())))).slice(0, qy.row_limit);
        return send(200, { result: [{ data, rowcount: data.length }] }, opts.rotate ? { 'Set-Cookie': 'session=abc2; Path=/; HttpOnly' } : {});
      }
      send(404, {});
    });
  });
  return new Promise((r) => srv.listen(port, '127.0.0.1', () => r({ srv, calls, port: srv.address().port, close: () => new Promise((x) => { srv.closeAllConnections(); srv.close(x); }) })));
}
module.exports = { start };
if (require.main === module) start(Number(process.env.PORT) || 8091, {}).then((s) => console.log('Fake Superset on port ' + s.port + ' (login svc / pw)'));
