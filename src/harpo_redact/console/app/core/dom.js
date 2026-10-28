import { ICONS } from "./icons.js";

export const $ = (s, el = document) => el.querySelector(s);
export const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ESC[c]);
export const icon = (n, c = "") =>
  `<svg class="i ${c}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ""}</svg>`;
export const fmt = (n) => (n == null ? "—" : n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${(n / 1e3).toFixed(1)}k` : Number(n).toLocaleString("en-US"));
export const ms = (v) => (v == null ? "—" : v < 10 ? `${(+v).toFixed(1)} ms` : `${Math.round(v).toLocaleString("en-US")} ms`);
export const pct = (v, d = 1) => (v == null ? "—" : `${(v * 100).toFixed(d)}%`);
export const bytes = (n) => (n == null ? "—" : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : n >= 1e3 ? `${Math.round(n / 1e3)} kB` : `${n} B`);
export const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
export const dur = (s) => (s < 90 ? `${Math.round(s)}s` : s < 5400 ? `${Math.round(s / 60)}m` : s < 172800 ? `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m` : `${Math.floor(s / 86400)}d ${Math.round((s % 86400) / 3600)}h`);
export const ago = (ts) => (ts ? `${dur(Math.max(0, Date.now() / 1000 - ts))} ago` : "never");
export const inline = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");
export const yes = (b) => (b ? "on" : "off");

/** Styles that depend on data are set through the CSSOM, which the strict CSP allows (inline style attributes are not). */
export function paint(root = document) {
  requestAnimationFrame(() => {
    for (const el of $$("[data-w]", root)) el.style.width = `${Math.max(0, Math.min(100, +el.dataset.w))}%`;
    for (const el of $$("[data-grow]", root)) el.style.flexGrow = el.dataset.grow;
    for (const el of $$("[data-bg]", root)) el.style.background = el.dataset.bg;
    for (const el of $$("[data-l]", root)) el.style.left = `${Math.max(0, Math.min(100, +el.dataset.l))}%`;
  });
}
export function toast(msg, bad = false) {
  const t = document.createElement("div");
  t.className = `toast glass${bad ? " bad" : ""}`;
  t.innerHTML = `${icon(bad ? "triangle-alert" : "circle-check")}<span>${esc(msg)}</span>`;
  $("#toasts")?.append(t);
  setTimeout(() => t.remove(), 2600);
}
export async function copy(text, what = "Copied") {
  try { await navigator.clipboard.writeText(text); }
  catch { const ta = Object.assign(document.createElement("textarea"), { value: text }); document.body.append(ta); ta.select(); document.execCommand("copy"); ta.remove(); }
  toast(what);
}
export function highlight(code) {
  const rx = /(\[[A-Z][A-Z0-9_]*?(?:_\d+)?\])|((?<=^|\s)(?:#|\/\/)[^\n]*)|("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')|\b(import|from|const|let|await|async|def|return|new|export|true|false|null|None|True|False)\b|\b(\d+(?:\.\d+)?)\b|(\$\{?[A-Z_]+\}?)/gm;
  let out = "", last = 0;
  for (const m of code.matchAll(rx)) {
    out += esc(code.slice(last, m.index));
    if (m[1]) out += `<span class="tk-p">${esc(m[0])}</span>`;
    else if (m[3] && /\[[A-Z][A-Z0-9_]*?(?:_\d+)?\]/.test(m[0])) out += `<span class="tk-s">${esc(m[0]).replace(/\[[A-Z][A-Z0-9_]*?(?:_\d+)?\]/g, (p) => `<span class="tk-p">${p}</span>`)}</span>`;
    else out += `<span class="tk-${m[2] ? "c" : m[3] ? "s" : m[4] ? "k" : m[5] ? "n" : "v"}">${esc(m[0])}</span>`;
    last = m.index + m[0].length;
  }
  return out + esc(code.slice(last));
}

export const TYPES = {
  EMAIL: ["Email", 0, "Contact"], PHONE: ["Phone", 1, "Contact"], ADDRESS: ["Address", 6, "Contact"], IP_ADDRESS: ["IP address", 1, "Network"],
  DEVICE_ID: ["Device ID", 9, "Network"], CREDIT_CARD: ["Card number", 2, "Financial"], IBAN: ["IBAN", 3, "Financial"],
  ACCOUNT_ID: ["Account number", 3, "Financial"], CRYPTO_ADDRESS: ["Crypto address", 3, "Financial"], SECRET: ["Secret", 4, "Credentials"],
  PRIVATE_KEY: ["Private key", 4, "Credentials"], ENCODED_DATA: ["Encoded data", 9, "Credentials"], NL_BSN: ["BSN", 8, "Government ID"],
  US_SSN: ["SSN", 8, "Government ID"], UK_NINO: ["NINO", 8, "Government ID"], NATIONAL_ID: ["National ID", 8, "Government ID"],
  ID_DOCUMENT: ["ID document", 8, "Government ID"], DATE_OF_BIRTH: ["Date of birth", 2, "Identity"], PERSON: ["Person", 5, "Identity"],
  LOCATION: ["Location", 6, "Identity"], ORGANIZATION: ["Organization", 7, "Identity"], QUASI_ID: ["Quasi-identifier", 7, "Identity"],
  PROTECTED_TERM: ["Protected term", 4, "Registry"], DATE: ["Date", 9, "Identity"],
};
/** Custom types from the policy: their own name as the label, a colour of their own, and a category of their own. */
export function registerCustomTypes(list = []) { for (const c of list || []) TYPES[c.name] = [c.name, 10, "Your types"]; }
export const tlabel = (t) => (TYPES[t] || [String(t ?? "").replace(/_/g, " ").toLowerCase()])[0];
export const tcol = (t) => `c${(TYPES[t] || [0, 9])[1]}`;
export const tcat = (t) => (TYPES[t] || [0, 0, "Other"])[2];
/** Which layers can report each type, as implemented in detectors/. */
export const COVERAGE = {
  EMAIL: "patterns, decoded views", PHONE: "libphonenumber, spelled-out view", CREDIT_CARD: "Luhn + issuer, line-join view", IBAN: "mod-97",
  SECRET: "221 gitleaks rules, prompt rules", PRIVATE_KEY: "PEM detector", ENCODED_DATA: "base64 ×2, escapes", NL_BSN: "11-check + cue",
  US_SSN: "format + cue", UK_NINO: "format", NATIONAL_ID: "python-stdnum checksums", ID_DOCUMENT: "cue-gated", ACCOUNT_ID: "cue-gated",
  CRYPTO_ADDRESS: "base58check, bech32, EIP-55", IP_ADDRESS: "pattern", DEVICE_ID: "MAC, IMEI (Luhn), VIN", DATE_OF_BIRTH: "date + cue",
  ADDRESS: "street and postcode patterns", PERSON: "NER, name rules, SLM", LOCATION: "NER, SLM", ORGANIZATION: "NER, SLM", QUASI_ID: "SLM only",
  PROTECTED_TERM: "registry", DATE: "pattern",
};
