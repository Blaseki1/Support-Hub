// Stand-in for the GPL receipt site: basic auth + a cookie, HTML page per UUID, login redirect when the cookie is wrong.
const http = require('http'), fs = require('fs'), path = require('path');
const PAGE = fs.readFileSync(path.join(__dirname, 'fixtures', 'receipt.html'), 'utf8');
const KNOWN = { '7bcea5b1-9ab3-49fc-8e73-e39b5887b3c4': { meter: 'temp_6523', total: '$3,000.00' }, '14702560-cc3c-11f0-9bb5-b02628171946': { meter: 'meter-999', total: '$50.00' } };
function start(opts = {}) {
  const calls = [];
  const srv = http.createServer((req, res) => {
    calls.push({ url: req.url, headers: req.headers });
    if (req.headers.authorization !== 'Basic dGVzdDp0ZXN0') { res.writeHead(401, { 'WWW-Authenticate': 'Basic' }); return res.end('no'); }
    if (!/_juice_ex_key=good/.test(req.headers.cookie || '')) { res.writeHead(302, { Location: '/login' }); return res.end(); }
    const m = req.url.match(/^\/transactions\/([0-9a-f-]{36})\/receipt$/); const k = m && KNOWN[m[1]];
    if (!k) { res.writeHead(404, { 'Content-Type': 'text/html' }); return res.end('<html>Not found</html>'); }
    let html = PAGE.replace('{{UUID}}', m[1]).replace('temp_6523', k.meter).replace('$3,000.00', k.total);
    res.writeHead(200, { 'Content-Type': 'text/html', ...(opts.rotate ? { 'Set-Cookie': '_juice_ex_key=good2; Path=/' } : {}) }); res.end(html);
  });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r({ srv, calls, port: srv.address().port, close: () => new Promise((x) => { srv.closeAllConnections(); srv.close(x); }) })));
}
module.exports = { start };
