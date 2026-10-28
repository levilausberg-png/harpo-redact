import { $, $$, esc, icon, paint } from "../core/dom.js";

export const head = (title, sub = "", actions = "", eyebrow = "") =>
  `<div class="head"><div>${eyebrow ? `<div class="eyebrow">${esc(eyebrow)}</div>` : ""}<h1>${title}</h1>${sub ? `<p>${sub}</p>` : ""}</div><div class="actions">${actions}</div></div>`;
export const panel = (title, body, { r = "", cls = "", id = "" } = {}) =>
  `<section class="panel ${cls}"${id ? ` id="${id}"` : ""}>${title ? `<div class="ph"><h3>${title}</h3><div class="r">${r}</div></div>` : ""}${body}</section>`;
export const stats = (items) =>
  `<div class="stats">${items.map((s) => `<div class="stat"><div class="k">${esc(s.k)}</div><div class="v ${s.tone ? `t-${s.tone}` : ""}">${s.v}${s.u ? `<small>${esc(s.u)}</small>` : ""}</div>${s.f ? `<div class="f">${s.f}</div>` : ""}</div>`).join("")}</div>`;
export const kv = (rows) => rows.map(([k, v, crit]) => `<div class="kv${crit ? " crit" : ""}"><span>${esc(k)}</span><span>${v}</span></div>`).join("");
export const mx = (rows) => rows.map((r) => `<div class="mx"><div class="ico ${r.kind || ""}">${icon(r.icon || "circle-dashed", "sm")}</div><div><div class="n">${esc(r.n)}</div>${r.d ? `<div class="d">${r.d}</div>` : ""}</div><div>${r.s || ""}</div></div>`).join("");
export const st = (kind, text) => `<span class="st ${kind}">${esc(text)}</span>`;
export const tag = (text, kind = "") => `<span class="tag ${kind}">${esc(text)}</span>`;
export const ent = (t, label) => `<span class="ent ${t}">${esc(label)}</span>`;
export const empty = (title, body, row = "") => `<div class="empty"><h4>${esc(title)}</h4><p>${body}</p>${row ? `<div class="row">${row}</div>` : ""}</div>`;
export const banner = (kind, html, ic = kind === "warn" ? "triangle-alert" : kind === "bad" ? "octagon-x" : "info") => `<div class="banner ${kind}">${icon(ic)}<div>${html}</div></div>`;
export const code = (text, id = "") => `<div class="code inset"><pre${id ? ` id="${id}"` : ""}>${text}</pre></div>`;
export const seg = (id, items, on) => `<div class="seg" id="${id}">${items.map(([v, l]) => `<button data-v="${esc(v)}" class="${v === on ? "on" : ""}">${esc(l)}</button>`).join("")}</div>`;

/** Sortable, keyboard-navigable table. cols: {k, l, f(row) -> html, v(row) -> sort value, r: right-aligned, sort: false}. */
export function table(el, { cols, rows, sort = [], onRow, emptyHtml = "" }) {
  let [key, dir] = sort;
  const cmp = (a, b) => (a == null ? -1 : b == null ? 1 : typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b)));
  const draw = () => {
    const col = cols.find((c) => c.k === key);
    const order = rows.map((r, i) => i);
    if (col) order.sort((i, j) => cmp(col.v ? col.v(rows[i]) : rows[i][col.k], col.v ? col.v(rows[j]) : rows[j][col.k]) * (dir === "asc" ? 1 : -1));
    if (!rows.length) { el.innerHTML = emptyHtml; return; }
    el.innerHTML = `<div class="tw" tabindex="0" role="region" aria-label="Table"><table class="tbl"><thead><tr>${cols.map((c) => `<th${c.sort === false ? "" : ` data-sort="${c.k}"`} class="${c.r ? "r" : ""}" scope="col">${esc(c.l)}${key === c.k ? `<span class="dir">${dir === "asc" ? "↑" : "↓"}</span>` : ""}</th>`).join("")}</tr></thead>
      <tbody>${order.map((i) => `<tr${onRow ? ` class="click" tabindex="0" data-i="${i}"` : ""}>${cols.map((c) => `<td class="${c.r ? "r num" : ""} ${c.cls || ""}">${c.f ? c.f(rows[i]) : esc(rows[i][c.k] ?? "—")}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
    paint(el);
    for (const th of $$("th[data-sort]", el)) th.onclick = () => { dir = key === th.dataset.sort && dir === "desc" ? "asc" : "desc"; key = th.dataset.sort; draw(); };
    if (onRow) for (const tr of $$("tbody tr", el)) {
      tr.onclick = () => onRow(rows[+tr.dataset.i]);
      tr.onkeydown = (e) => {
        if (e.key === "Enter") onRow(rows[+tr.dataset.i]);
        if (e.key === "ArrowDown") { tr.nextElementSibling?.focus(); e.preventDefault(); }
        if (e.key === "ArrowUp") { tr.previousElementSibling?.focus(); e.preventDefault(); }
      };
    }
  };
  draw();
}
export function drawer(title, sub, body) {
  const layer = $("#layer");
  layer.innerHTML = `<div class="scrim" data-close></div><aside class="drawer glass" role="dialog" aria-label="${esc(title)}"><div class="dh"><div><h2>${title}</h2>${sub ? `<p>${sub}</p>` : ""}</div><button class="btn ghost ic" data-close aria-label="Close">${icon("x")}</button></div><div class="db">${body}</div></aside>`;
  for (const b of $$("[data-close]", layer)) b.onclick = () => { layer.innerHTML = ""; };
  paint(layer);
  return layer;
}
/** Horizontal stages with a single flow gradient under them. */
export const pipe = (stages) => `<div class="pipe">${stages.map((s) => `<div class="stage ${s.state || ""}"><div class="node">${icon(s.icon, "lg")}</div><div class="sn">${esc(s.n)}</div><div class="sv">${s.v}</div>${s.v2 ? `<div class="sv">${s.v2}</div>` : ""}</div>`).join("")}</div>`;
export const vstages = (rows) => `<div class="vstages">${rows.map((r) => `<div class="vs ${r.state || ""}"><span class="pt"></span><div><div class="n">${esc(r.n)}</div>${r.d ? `<div class="d">${r.d}</div>` : ""}</div><span class="m">${r.m ?? ""}</span></div>`).join("")}</div>`;
