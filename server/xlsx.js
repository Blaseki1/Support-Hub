const ExcelJS = require('exceljs');
const DATES = { TRANS_DATE: 'yyyy-mm-dd', TRANSACTION_DATE: 'yyyy-mm-dd hh:mm:ss' };
const TEXT = /(^|_)(ID|MSISDN|PARTNER_ID|WALLET_ID)$|^(OP_ID|DP_ID|OU_ID|ACCOUNT_DETAIL|ACCOUNT_DETAIL_2)$/;

// sheet "Transactions": every column as returned; dates are real Excel dates, IDs and phone numbers are text.
async function buildWorkbook(cols, rows, info) {
  const wb = new ExcelJS.Workbook(); wb.created = new Date();
  const ws = wb.addWorksheet('Transactions', { views: [{ state: 'frozen', ySplit: 1 }] });
  ws.columns = cols.map((c) => ({ header: c, key: c, width: DATES[c] ? 20 : Math.min(34, Math.max(c.length + 2, 12)) }));
  ws.getRow(1).font = { bold: true };
  ws.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFC300' } };
  for (const r of rows) {
    const row = {};
    for (const c of cols) {
      const v = r[c];
      if (v == null) row[c] = null;
      else if (DATES[c]) row[c] = new Date(Number(v));
      else if (TEXT.test(c)) row[c] = String(v);
      else row[c] = v;
    }
    ws.addRow(row);
  }
  cols.forEach((c, i) => { if (DATES[c]) ws.getColumn(i + 1).numFmt = DATES[c]; });
  ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: cols.length } };
  const wi = wb.addWorksheet('About this file');
  wi.columns = [{ width: 22 }, { width: 60 }];
  info.forEach((r) => wi.addRow(r));
  wi.getColumn(1).font = { bold: true };
  return wb.xlsx.writeBuffer();
}
module.exports = { buildWorkbook };
