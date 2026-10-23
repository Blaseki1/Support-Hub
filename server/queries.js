// Builds Superset requests. Mirrors the curls you shared; values are only ever placed in filter "val" lists.
function num(x) { return x === '' || x == null ? undefined : isNaN(x) ? x : Number(x); }
const active = (q) => q.envs[q.env];
const urlFor = (q) => { const e = active(q); return e && e.base ? e.base.replace(/\/+$/, '') + q.endpoint : ''; };
// Superset's own page adds ?form_data={"slice_id":N}&dashboard_id=N to the call. We do the same.
function queryString(q) {
  const e = active(q), s = num(e.slice), d = num(e.dashboard), p = [];
  if (s !== undefined && s !== '') p.push('form_data=' + encodeURIComponent(JSON.stringify({ slice_id: s })));
  if (d !== undefined && d !== '') p.push('dashboard_id=' + d);
  return p.length ? '?' + p.join('&') : '';
}
const DATE_COLS = ['CREATED_DATE', 'LAST_MODIFIED_DATE', 'DOB', 'TRANS_DATE', 'TRANSACTION_DATE', 'profile_last_modified'];

// Search values go into Superset filters, and some datasets put them into SQL through Jinja.
// So only letters, digits, space and @ . _ + - are allowed. Apostrophes, quotes, %, ; etc. are refused.
const SAFE = /^[\p{L}\p{N} @._+\-]+$/u;
function cleanValue(v, min) {
  const s = String(v == null ? '' : v).trim();
  if (!s) return '';
  if (s.length > 100) throw httpErr(400, 'That value is too long.');
  if (!SAFE.test(s)) throw httpErr(400, 'Only letters, numbers, spaces and @ . _ + - are allowed in a search.');
  if (s.length < min) throw httpErr(400, `Enter at least ${min} characters.`);
  return s;
}
function httpErr(status, message, code) { const e = new Error(message); e.status = status; if (code) e.code = code; return e; }

// One box for username or mobile. A number with 592 in front is also tried without it.
function variants(raw) {
  const v = String(raw || '').trim(), d = v.replace(/[\s()+-]/g, '');
  if (/^[\d\s()+-]+$/.test(v) && /^\d+$/.test(d)) { const out = [d]; if (d.startsWith('592') && d.length >= 9) out.push(d.slice(3)); return out; }
  return v ? [v] : [];
}

// vals: array (used for every search column) or { column: [values] } (only those columns are filtered)
function buildBody(q, vals, range) {
  const e = active(q), ds = num(e.datasource), dash = num(e.dashboard), lim = Number(e.rowLimit) || 1000, rg = range || 'No filter', ob = q.orderBy || [];
  const per = Array.isArray(vals) ? Object.fromEntries(q.searchCols.map((c) => [c, vals])) : vals;
  const mk = () => q.searchCols.filter((c) => per[c] && per[c].length).map((c) => ({ col: c, op: 'IN', val: [...per[c]] }));
  const fixed = (q.fixedFilters || []).map((f) => ({ col: f.col, op: f.op }));
  const flt = [...mk(), ...fixed];
  if (q.dateCol) flt.push({ col: q.dateCol, op: 'TEMPORAL_RANGE', val: rg });
  const adhoc = [
    ...(q.dateCol ? [{ clause: 'WHERE', comparator: rg, expressionType: 'SIMPLE', operator: 'TEMPORAL_RANGE', subject: q.dateCol }] : []),
    ...fixed.map((f) => ({ clause: 'WHERE', comparator: null, expressionType: 'SIMPLE', operator: f.op, operatorId: f.op.replace(/ /g, '_'), sqlExpression: null, subject: f.col })),
  ];
  const temporal = Object.fromEntries(q.columns.filter((c) => DATE_COLS.includes(c)).map((c) => [c, true]));
  return {
    datasource: { id: ds, type: 'table' }, force: false,
    queries: [{ filters: flt, extras: { having: '', where: '' }, applied_time_extras: {}, columns: q.columns, orderby: ob, annotation_layers: [], row_limit: lim, series_limit: 0, order_desc: true, url_params: {}, custom_params: {}, custom_form_data: {}, post_processing: [], time_offsets: [] }],
    form_data: { datasource: ds + '__table', viz_type: 'table', slice_id: num(e.slice), url_params: {}, query_mode: 'raw', groupby: [], time_grain_sqla: 'P1D', temporal_columns_lookup: temporal, metrics: [], all_columns: q.columns, percent_metrics: [], adhoc_filters: adhoc, order_by_cols: ob.map((o) => `[${JSON.stringify(o[0])}, ${o[1]}]`), row_limit: lim, server_page_length: 10, order_desc: true, table_timestamp_format: 'smart_date', allow_render_html: true, show_cell_bars: true, color_pn: true, comparison_color_scheme: 'Green', comparison_type: 'values', dashboards: dash === undefined ? [] : [dash], extra_form_data: mk().length ? { filters: mk() } : {}, label_colors: {}, shared_label_colors: {}, extra_filters: [], dashboardId: dash, force: false, result_format: 'json', result_type: 'full', include_time: false },
    result_format: 'json', result_type: 'full',
  };
}

const PERIODS = { '7': 'Last 7 days', '30': 'Last 30 days', '90': 'Last 90 days', mtd: 'This month', lm: 'Last month', '180': 'Last 6 months', '365': 'Last 12 months', all: 'All time' };
const ymd = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
function periodRange(k, now0) {
  if (!(k in PERIODS)) throw httpErr(400, 'Unknown period.');
  if (k === 'all') return { range: 'No filter', label: PERIODS[k] };
  const t = new Date(now0 || Date.now()); t.setHours(0, 0, 0, 0);
  let s = new Date(t), e = new Date(t.getFullYear(), t.getMonth(), t.getDate() + 1);
  if (k === 'mtd') s = new Date(t.getFullYear(), t.getMonth(), 1);
  else if (k === 'lm') { s = new Date(t.getFullYear(), t.getMonth() - 1, 1); e = new Date(t.getFullYear(), t.getMonth(), 1); }
  else s = new Date(t.getFullYear(), t.getMonth(), t.getDate() - (Number(k) - 1));
  return { range: `${ymd(s)}T00:00:00 : ${ymd(e)}T00:00:00`, label: PERIODS[k] };
}

// Reads a pasted curl. Headers (cookies, tokens) are never read or stored.
function parseCurl(text) {
  const um = String(text).match(/https?:\/\/[^\s'"\\]+/);
  if (!um) return { error: 'No URL found in that curl.' };
  let url; try { url = new URL(um[0]); } catch { return { error: 'The URL in that curl is not valid.' }; }
  const i = text.indexOf('--data'), a = text.indexOf('{', i), b = text.lastIndexOf('}');
  let body = null;
  if (i >= 0 && a >= 0 && b > a) { try { body = JSON.parse(text.slice(a, b + 1)); } catch { return { error: 'The --data body is not valid JSON.' }; } }
  return { url: url.origin + url.pathname, body };
}

// Pulls the login headers out of a pasted curl (Cookie, X-CSRFToken, Authorization). Only these are kept.
function parseCurlAuth(text) {
  const out = {}, want = { cookie: 'Cookie', 'x-csrftoken': 'X-CSRFToken', authorization: 'Authorization', 'user-agent': 'User-Agent' };
  const re = /(?<![\w-])(?:-H|--header)\s+(?:'([^']*)'|"((?:[^"\\]|\\.)*)")|(?<![\w-])(?:-b|--cookie)\s+(?:'([^']*)'|"([^"]*)")/g;
  let m;
  while ((m = re.exec(text))) {
    const cookieOnly = m[3] != null || m[4] != null;
    if (cookieOnly) { out.Cookie = (m[3] != null ? m[3] : m[4]).trim(); continue; }
    const h = (m[1] != null ? m[1] : m[2]), i = h.indexOf(':'); if (i < 1) continue;
    const name = want[h.slice(0, i).trim().toLowerCase()]; if (name) out[name] = h.slice(i + 1).trim();
  }
  return out;
}

// Superset returns dates as epoch milliseconds. Keep them as numbers and format at the edges.
function rowsFrom(resp) {
  const r = resp && resp.result && resp.result[0];
  if (!r) throw httpErr(502, 'Superset returned no result.');
  if (r.error) throw httpErr(502, 'Superset reported an error: ' + String(r.error).slice(0, 200));
  return { rows: r.data || [], rowcount: r.rowcount != null ? r.rowcount : (r.data || []).length };
}

module.exports = { num, active, urlFor, queryString, cleanValue, variants, buildBody, periodRange, parseCurl, parseCurlAuth, rowsFrom, httpErr, PERIODS };
