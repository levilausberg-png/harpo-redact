// Content-free exports: only metadata the console already shows. There is no request content to export.
export const stamp = () => new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
export function download(name, text, type = "application/json") {
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([text], { type })), download: name });
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
/** cols: [[key or (row) => value, header]] */
export function toCSV(rows, cols) {
  const q = (v) => { const s = v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v); return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  return `${cols.map(([, h]) => q(h)).join(",")}\n${rows.map((r) => cols.map(([k]) => q(typeof k === "function" ? k(r) : r[k])).join(",")).join("\n")}\n`;
}
