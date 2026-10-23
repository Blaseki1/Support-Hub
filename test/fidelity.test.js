// Checks that the requests we build match the curls from the real Superset page.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), path = require('path');
const Q = require('../server/queries');
const D = require('../server/defaults');
const read = (n) => fs.readFileSync(path.join(__dirname, 'fixtures', n), 'utf8');
const real = (n) => Q.parseCurl(read(n)).body;
const conn = (k) => D.defaultConnections()[k];

test('login headers are read from "Copy as cURL" (-b cookie, X-CSRFToken), nothing else is kept', () => {
  const h = Q.parseCurlAuth(read('history.curl'));
  assert.deepEqual(Object.keys(h).sort(), ['Cookie', 'User-Agent', 'X-CSRFToken']);
  assert.equal(h.Cookie, 'session=REDACTED');
});

test('history request equals the real one (same partner, no date filter)', () => {
  const mine = Q.buildBody(conn('txns.history'), { WALLET_PARTNER_ID: ['32223'] }, 'No filter'), r = real('history.curl');
  assert.deepEqual(mine.queries[0], r.queries[0]);
  for (const k of Object.keys(r.form_data).filter((x) => x !== 'all_columns')) assert.deepEqual(mine.form_data[k], r.form_data[k], 'form_data.' + k);
  assert.deepEqual(mine.form_data.all_columns, r.queries[0].columns);
  assert.equal(Q.queryString(conn('txns.history')), '?form_data=%7B%22slice_id%22%3A79%7D&dashboard_id=101');
});

test('lookup request equals the real one (mobile and username)', () => {
  const mine = Q.buildBody(conn('txns.lookup'), ['6010256'], 'No filter'), r = real('lookup.curl');
  assert.deepEqual(mine.queries[0], r.queries[0]);
  assert.equal(Q.queryString(conn('txns.lookup')), '?form_data=%7B%22slice_id%22%3A76%7D&dashboard_id=99');
  for (const k of ['datasource', 'slice_id', 'temporal_columns_lookup', 'adhoc_filters', 'extra_form_data', 'row_limit']) assert.deepEqual(mine.form_data[k], r.form_data[k], k);
});

test('search request filters and query string', () => {
  const c = conn('search.lookup'), b = Q.buildBody(c, { USER_NAME: ['6010256'], EMAIL_ID: ['a@b.com'] }, 'No filter');
  assert.deepEqual(b.queries[0].filters, [{ col: 'USER_NAME', op: 'IN', val: ['6010256'] }, { col: 'EMAIL_ID', op: 'IN', val: ['a@b.com'] }, { col: 'Account_type', op: 'IS NOT NULL' }]);
  assert.equal(Q.queryString(c), '?form_data=%7B%22slice_id%22%3A83%7D&dashboard_id=103');
  assert.equal(b.datasource.id, 76);
});
