import { api, session, setKey, onUnauthorized } from "./core/api.js";
import { $, $$, esc, icon, copy, toast, dur, ago, clock, TYPES, tlabel, registerCustomTypes } from "./core/dom.js";
import { prefs } from "./core/prefs.js";
import { stream } from "./core/stream.js";
import { download, toCSV, stamp } from "./core/exports.js";
import { drawer } from "./ui/kit.js";
import { openMenu, menuOpen } from "./ui/menu.js";

// The console's rooms, named after Harpo's parts. Shield: the proxy that traffic passes through. Mask: what is
// redacted and how. Vault: what never leaves (keys, the configuration). Proof: what you can check for yourself.
const GROUPS = [
  ["", "", [["overview", "Overview", "layout-dashboard", "o"]]],
  ["SHIELD", "Traffic in and out", [["setup", "Setup", "play", "w"], ["integrations", "Integrations", "blocks", "i"], ["providers", "Providers & adapters", "route", "r"], ["activity", "Activity", "activity", "a"], ["observability", "Observability", "chart-line", "b"]]],
  ["MASK", "What is redacted, and how", [["playground", "Playground", "scan-text", "p"], ["documents", "Documents", "file-lock", "d"], ["policy", "Policy", "shield-check", "y"], ["detection", "Detection", "scan-search", "e"], ["lab", "Detector lab", "binary", "x"]]],
  ["VAULT", "What never leaves", [["access", "Access", "key-round", "k"], ["configuration", "Configuration", "sliders-horizontal", "c"]]],
  ["PROOF", "What you can check", [["guarantees", "Security guarantees", "badge-check", "s"], ["leakbench", "LeakBench", "flask-conical", "l"], ["system", "System", "server", "m"]]],
];
const PAGES = Object.fromEntries(GROUPS.flatMap(([g, , items]) => items.map(([id, label, ic, key]) => [id, { label, ic, group: g, key }])));
const NAVKEYS = Object.fromEntries(Object.entries(PAGES).map(([id, p]) => [p.key, id]));
const INVARIANTS = [["INV-01", "Raw blocked values never cross the boundary"], ["INV-02", "No reverse map outlives a request"], ["INV-03", "Probabilistic layers cannot approve egress"],
  ["INV-04", "Uninspectable content is never silently forwarded"], ["INV-05", "No prompt content in telemetry"], ["INV-06", "Overrides never restore raw values"],
  ["INV-07", "Adapters declare every surface"], ["INV-08", "Unknown fields fail by explicit policy"], ["INV-09", "Documents are verified before release"], ["INV-10", "Images stay blocked; no OCR"], ["INV-11", "Keys are always redacted"]];
const app = $("#app");
const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

export const ctx = {
  cleanups: [], policy: null, system: null, selftest: null, route: "overview", params: [], query: new URLSearchParams(), poll: null, admin: false,
  models() {
    const p = this.policy || {};
    const openai = (p.models || []).map((m) => ({ id: m, style: "openai" }));
    const anthropic = (p.upstreams || []).filter((u) => u.style === "anthropic").flatMap((u) => u.models.filter((m) => !/[*?[]/.test(m)).map((m) => ({ id: m, style: "anthropic" })));
    return [...openai, ...anthropic];
  },
  go(id) { location.hash = `#/${id}`; },
  /** Rewrites the current URL's query (and optional sub-path) without a navigation: filters survive refresh and back. */
  setQuery(obj, params = this.params) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(obj)) if (v && v !== "all") q.set(k, v);
    const path = [this.route, ...params.map(encodeURIComponent)].join("/"), s = q.toString();
    history.replaceState(null, "", `#/${path}${s ? `?${s}` : ""}`);
    this.query = q; this.params = params; crumbs();
  },
  link(path) { return `${location.origin}/#/${path}`; },
  /** Marks the live indicator active for a moment: called when new real events arrive, never on a timer. */
  pulse() { const l = $("#live"); if (!l) return; l.classList.add("active"); clearTimeout(this._pt); this._pt = setTimeout(() => l.classList.remove("active"), 1600); },
  needAdmin(view, what) {
    view.innerHTML = `<div class="panel"><div class="empty"><h4>ADMIN KEY REQUIRED</h4><p>${esc(what)} is part of the control plane. Connect with a gateway key that has <code>admin: true</code>.</p></div></div>`;
  },
};

function applyTheme(t) { prefs.set("theme", t); if (t === "system") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t; }
const theme = () => document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
function toggleTheme() { applyTheme(theme() === "dark" ? "light" : "dark"); $("#theme") && ($("#theme").innerHTML = icon(theme() === "dark" ? "sun" : "moon")); }
function toggleCompact() { const on = !app.classList.contains("compact"); app.classList.toggle("compact", on); prefs.set("compact", on); $("#compact").innerHTML = icon(on ? "panel-left-open" : "panel-left-close"); }

function gate(message = "") {
  clearInterval(ctx.poll);
  app.className = "boot";
  app.innerHTML = `<form class="panel elev lumen gate" id="gate" autocomplete="off"><div class="pb"><img src="/console/logo.svg" alt="" width="34" height="34">
      <h1>Connect to Harpo</h1><p class="t2">Paste a gateway key. It is kept for this tab only and sent only to this gateway.</p>
      <label class="sr" for="gate-key">Gateway key</label><input class="input mono-in" id="gate-key" type="password" placeholder="harpo_…">
      <p class="t-bad" id="gate-err" role="alert">${esc(message)}</p>
      <button class="btn pri" type="submit">${icon("arrow-right")} Connect</button>
      <p class="t3">No key yet? <code>harpo init</code> creates one; <code>harpo demo</code> runs without keys.</p></div></form>`;
  $("#gate-key").focus();
  $("#gate").onsubmit = async (e) => {
    e.preventDefault(); setKey($("#gate-key").value.trim());
    try { await boot(); } catch (err) { setKey(""); $("#gate-err").textContent = err.status === 401 ? "That key was not accepted." : err.message; }
  };
}
onUnauthorized((msg) => gate(msg || "Your key is no longer accepted."));

function shell() {
  const p = ctx.policy;
  app.className = prefs.get("compact", false) ? "app compact" : "app";
  app.innerHTML = `
    <div class="ambient" aria-hidden="true"></div>
    <a class="skip" href="#view">Skip to content</a>
    <aside class="side" id="side" aria-label="Navigation">
      <a class="brand" href="#/overview"><img src="/console/logo.svg" alt=""><div><b>Harpo</b><small>harpo-redact ${esc(p.version)}</small></div></a>
      <button class="side-search" data-act="palette" aria-keyshortcuts="Control+K Meta+K">${icon("search", "sm")}<span>Search, jump, run</span><kbd>⌘K</kbd></button>
      <nav aria-label="Pages"><div id="favs"></div>${GROUPS.map(([g, about, items]) => `<div class="group" role="group" aria-label="${g ? `${g.toLowerCase()}: ${about.toLowerCase()}` : "home"}">${g ? `<div class="group-label" aria-hidden="true" title="${about}">${g}</div>` : ""}${items.map(([id, label, ic]) => `<a class="nav" data-route="${id}" href="#/${id}" title="${esc(label)}">${icon(ic)}<span>${esc(label)}</span></a>`).join("")}</div>`).join("")}</nav>
      <div class="side-foot">
        <div class="health" id="health" role="status"><span class="dot"></span><span>Checking gateway…</span></div>
        <div class="side-meta" id="meta">${esc(p.environment)}${p.auth?.enabled ? ` · key ${esc(session.key.slice(0, 6))}…${p.admin ? " · admin" : ""}` : " · auth off"}</div>
        <div class="side-tools">
          <button class="btn ghost ic" id="compact" data-act="compact" title="Compact navigation" aria-label="Compact navigation">${icon(app.classList.contains("compact") ? "panel-left-open" : "panel-left-close")}</button>
          <button class="btn ghost ic" id="theme" data-act="theme" title="Theme" aria-label="Switch theme">${icon(theme() === "dark" ? "sun" : "moon")}</button>
          <button class="btn ghost ic" data-act="keys" title="Keyboard shortcuts (?)" aria-label="Keyboard shortcuts">${icon("command")}</button>
          ${session.key ? `<button class="btn ghost ic" data-act="logout" title="Disconnect" aria-label="Disconnect">${icon("circle-x")}</button>` : ""}
        </div>
      </div>
    </aside>
    <div class="main">
      <header class="top"><button class="btn ghost ic menu" data-act="menu" aria-label="Menu">${icon("menu")}</button>
        <nav class="crumbs" id="crumbs" aria-label="Breadcrumb"></nav>
        <div class="top-r">${ctx.admin ? `<button class="btn ghost ic att" id="att" data-act="attention" aria-label="Attention center">${icon("bell")}<span class="att-n" id="att-n" hidden></span></button>` : ""}<span class="live hide-sm" id="live" data-state="off" title="Live event stream: lights up as requests arrive"><span class="dot"></span><span class="lv-t">connecting</span></span>
          <a class="btn" href="#/playground" aria-label="Inspect a request">${icon("scan-text", "sm")}<span class="hide-sm">Inspect a request</span></a></div></header>
      <main class="page" id="view" tabindex="-1"></main>
    </div>
    <div id="layer"></div><div class="toasts" id="toasts" role="status" aria-live="polite"></div>`;
  app.onclick = (e) => {
    const b = e.target.closest("[data-act]");
    if (!b) { if (e.target.closest(".nav")) $("#side").classList.remove("open"); return; }
    ({ palette, compact: toggleCompact, theme: toggleTheme, keys: shortcuts, menu: () => $("#side").classList.toggle("open"), attention: openAttention,
       tour: () => import("./ui/tour.js").then((m) => m.startTour(ctx)), "tour-dismiss": () => { prefs.set("tour", "dismissed"); b.closest("[data-tour]")?.remove(); },
       export: () => exportMenu(b),
       logout: () => { setKey(""); location.hash = ""; location.reload(); } })[b.dataset.act]?.();
  };
  manageLayer();
  renderFavs();
  // Inputs inside a labelled .field get that label as their accessible name, whichever view rendered them.
  let queued = false;
  new MutationObserver(() => {
    if (queued) return; queued = true;
    requestAnimationFrame(() => {
      queued = false;
      for (const f of $$(".field")) {
        const l = f.querySelector("label"), i = f.querySelector("input, select, textarea");
        if (l && i && !i.getAttribute("aria-label") && !(l.htmlFor && l.htmlFor === i.id)) i.setAttribute("aria-label", l.textContent.trim());
      }
      extras();
      for (const pre of $$(".code pre:not([tabindex]), pre:not([tabindex])")) { pre.tabIndex = 0; pre.setAttribute("role", "region"); pre.setAttribute("aria-label", "Code"); }
      for (const t of $$(".tw:not([tabindex])")) {
        const h = t.closest(".panel, section")?.querySelector("h3, h2, .ph h3");
        Object.assign(t, { tabIndex: 0 }); t.setAttribute("role", "region"); t.setAttribute("aria-label", h?.textContent.trim() || "Table");
      }
    });
  }).observe(app, { childList: true, subtree: true });
}
function crumbs() {
  const pg = PAGES[ctx.route];
  const extra = ctx.params.length ? `${icon("chevron-right", "sm")}<span class="t2">${esc(ctx.params[0])}</span>${ctx.params[1] ? `${icon("chevron-right", "sm")}<span class="mono">${esc(ctx.params[1].slice(0, 12))}</span>` : ""}` : "";
  $("#crumbs").innerHTML = `<span class="hide-sm t3">${pg.group ? pg.group.charAt(0) + pg.group.slice(1).toLowerCase() : "Harpo"}</span>${icon("chevron-right", "sm hide-sm")}<a href="#/${ctx.route}"><b>${esc(pg.label)}</b></a>${extra}`;
}
/** Dialogs: focus moves in, Tab stays in, focus returns to where it was on close. */
function manageLayer() {
  const layer = $("#layer");
  let before = null;
  new MutationObserver(() => {
    const dlg = layer.querySelector('[role="dialog"]');
    if (dlg && !before) {
      before = document.activeElement;
      dlg.setAttribute("aria-modal", "true");
      requestAnimationFrame(() => { if (!dlg.contains(document.activeElement)) (dlg.querySelector("input, select, textarea, button, a[href], [tabindex]:not([tabindex='-1'])") || dlg).focus?.(); });
    }
    if (!dlg && before) { before.focus?.(); before = null; }
  }).observe(layer, { childList: true });
  layer.addEventListener("keydown", (e) => {
    if (e.key !== "Tab") return;
    const dlg = layer.querySelector('[role="dialog"]');
    const f = dlg ? [...dlg.querySelectorAll("input, select, textarea, button, a[href], [tabindex]:not([tabindex='-1'])")].filter((x) => !x.disabled && x.offsetParent !== null) : [];
    if (!f.length) return;
    if (e.shiftKey && document.activeElement === f[0]) { f[f.length - 1].focus(); e.preventDefault(); }
    else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { f[0].focus(); e.preventDefault(); }
  });
}
async function health() {
  if (document.hidden) return;
  try {
    if (ctx.admin) {
      ctx.system = await api("/v1/system");
      const ready = ctx.system.readiness?.status === "ready" || ctx.system.gateway?.ready === true;
      $("#health").innerHTML = `<span class="dot ${ready ? "ok" : "bad"}"></span><span>${ready ? "Gateway ready" : "Gateway not ready"} · up ${dur(ctx.system.uptime_s ?? ctx.system.gateway?.uptime_s ?? 0)}</span>`;
    } else {
      const r = await fetch("/healthz", { cache: "no-store" });
      $("#health").innerHTML = `<span class="dot ${r.ok ? "ok" : "bad"}"></span><span>${r.ok ? "Gateway live" : "Gateway unhealthy"}</span>`;
    }
  } catch { $("#health").innerHTML = `<span class="dot bad"></span><span>Gateway unreachable</span>`; }
}
async function route() {
  const raw = location.hash.replace(/^#\/?/, "") || "overview";
  const [path, query = ""] = raw.split("?");
  const [id, ...params] = path.split("/").filter(Boolean);
  const known = !!PAGES[id];
  ctx.route = known ? id : "overview"; ctx.params = known ? params.map(decodeURIComponent) : []; ctx.query = new URLSearchParams(query);
  clearInterval(ctx.poll); ctx.poll = null;
  for (const fn of ctx.cleanups.splice(0)) fn();  // stream subscriptions and timers of the previous view
  for (const a of $$(".nav")) { const on = a.dataset.route === ctx.route; a.classList.toggle("on", on); if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); }
  const pg = PAGES[ctx.route];
  crumbs();
  document.title = `${pg.label} · Harpo`;
  prefs.set("recents", [ctx.route, ...prefs.get("recents", []).filter((r) => r !== ctx.route && PAGES[r])].slice(0, 6));
  $("#layer").innerHTML = "";
  const view = $("#view");
  const mod = await import(`./views/${ctx.route}.js`);
  const swap = async () => { view.onclick = null; view.oninput = null; view.onchange = null; view.oncontextmenu = null; view.onkeydown = null; await mod.default(view, ctx); };
  if (document.startViewTransition && !reduced() && ctx.rendered) {
    await document.startViewTransition(swap).updateCallbackDone.catch(() => null);
  } else {
    view.classList.remove("enter"); void view.offsetWidth; view.classList.add("enter");
    await swap();
  }
  ctx.rendered = true;
}

/** Subsequence match: consecutive letters and word starts score higher. 0 means no match. */
function fuzzy(q, text) {
  if (!q) return 1;
  const t = text.toLowerCase();
  let i = 0, score = 0, prev = -2, run = 0;
  for (let j = 0; j < t.length && i < q.length; j++) {
    if (t[j] !== q[i]) continue;
    run = j === prev + 1 ? run + 2 : 0;
    score += 1 + run + (j === 0 || " -_/·(".includes(t[j - 1]) ? 4 : 0);
    prev = j; i++;
  }
  return i === q.length ? score / Math.pow(t.length, 0.15) : 0;
}
function palette() {
  const layer = $("#layer"), origin = location.origin;
  const page = (id) => ({ g: "Pages", l: PAGES[id].label, i: PAGES[id].ic, k: `G ${PAGES[id].key.toUpperCase()}`, run: () => ctx.go(id) });
  const cmds = [
    ...prefs.get("recents", []).filter((id) => PAGES[id]).slice(0, 4).map((id) => ({ ...page(id), g: "Recent" })),
    ...Object.keys(PAGES).map(page),
    ...prefs.get("favorites", []).map((f) => ({ g: "Favorites", l: f.label, i: f.icon || "star", run: () => { location.hash = f.href; } })),
    ...prefs.get("views", []).map((v) => ({ g: "Saved views", l: v.name, i: "bookmark", run: () => { location.hash = `#/${v.page}${v.query ? `?${v.query}` : ""}`; } })),
    { g: "Actions", l: "Run the setup wizard", i: "play", run: () => ctx.go("setup") },
    ...(ctx.admin ? [{ g: "Actions", l: "Open the attention center", i: "bell", run: openAttention }] : []),
    { g: "Actions", l: "Take the product tour", i: "sparkles", run: () => import("./ui/tour.js").then((m) => m.startTour(ctx)) },
    { g: "Actions", l: "Open the detector lab", i: "binary", run: () => ctx.go("lab") },
    { g: "Actions", l: isFav() ? "Remove this page from favorites" : "Add this page to favorites", i: "star", run: toggleFav },
    { g: "Actions", l: "Run the security self-test", i: "badge-check", run: () => ctx.go("guarantees") },
    { g: "Actions", l: "Inspect a request (playground)", i: "scan-text", run: () => ctx.go("playground") },
    { g: "Actions", l: "Process a document", i: "file-lock", run: () => ctx.go("documents") },
    { g: "Actions", l: "Validate a configuration", i: "list-checks", k: "⌘ ,", run: () => ctx.go("configuration") },
    { g: "Actions", l: "Generate a gateway key", i: "key", run: () => ctx.go("access") },
    { g: "Actions", l: "Show blocked requests", i: "octagon-x", run: () => ctx.go("activity?decision=blocked") },
    { g: "Actions", l: "Copy the OpenAI-compatible base URL", i: "copy", run: () => copy(`${origin}/v1`, "Base URL copied") },
    { g: "Actions", l: "Copy the Anthropic base URL", i: "copy", run: () => copy(origin, "Base URL copied") },
    ...(ctx.policy.upstreams || []).map((u) => ({ g: "Providers", l: u.name, sub: u.style, i: "route", run: () => ctx.go("providers") })),
    ...Object.keys(TYPES).map((t) => ({ g: "Entity types", l: tlabel(t), sub: t, i: "fingerprint", run: () => ctx.go(`activity?entity=${t}`) })),
    ...INVARIANTS.map(([id, t]) => ({ g: "Invariants", l: `${id} · ${t}`, i: "shield-check", run: () => ctx.go("guarantees") })),
    { g: "Interface", l: "Switch light / dark", i: "sun", run: toggleTheme },
    { g: "Interface", l: "Toggle compact navigation", i: "panel-left-close", run: toggleCompact },
    { g: "Interface", l: "Reset workspace layout", i: "refresh-cw", run: () => { prefs.reset(["compact", "panes", "columns", "density"]); toast("Layout reset"); setTimeout(() => location.reload(), 400); } },
    { g: "Interface", l: "Keyboard shortcuts", i: "command", k: "?", run: shortcuts },
  ];
  let sel = 0, list = cmds;
  layer.innerHTML = `<div class="palette-back" id="pb"><div class="palette glass" role="dialog" aria-label="Command palette"><div class="pi">${icon("search")}<input id="pq" role="combobox" aria-expanded="true" aria-controls="pl" aria-label="Command" placeholder="Pages, actions, providers, entity types, invariants…" autocomplete="off"><kbd>esc</kbd></div><div class="pl" id="pl" role="listbox"></div></div></div>`;
  const draw = () => {
    let g = "";
    $("#pl").innerHTML = list.slice(0, 60).map((c, i) => `${c.g !== g ? `<div class="pg" role="presentation">${esc((g = c.g).toUpperCase())}</div>` : ""}<button class="po${i === sel ? " on" : ""}" role="option" aria-selected="${i === sel}" data-i="${i}">${icon(c.i)}<span>${esc(c.l)}${c.sub ? ` <em>${esc(c.sub)}</em>` : ""}</span>${c.k ? `<kbd>${esc(c.k)}</kbd>` : ""}</button>`).join("") || '<div class="pg">NOTHING MATCHES</div>';
    $(".po.on")?.scrollIntoView({ block: "nearest" });
  };
  const close = () => { layer.innerHTML = ""; }, run = (c) => { close(); c?.run(); };
  $("#pq").oninput = (e) => {
    const q = e.target.value.trim().toLowerCase();
    list = q ? cmds.filter((c) => c.g !== "Recent").map((c) => [fuzzy(q, `${c.l} ${c.sub || ""}`), c]).filter(([s]) => s > 0).sort((a, b) => b[0] - a[0]).map(([, c]) => c) : cmds;
    sel = 0; draw();
  };
  $("#pq").onkeydown = (e) => {
    if (e.key === "ArrowDown") { sel = Math.min(list.length - 1, sel + 1); draw(); e.preventDefault(); }
    else if (e.key === "ArrowUp") { sel = Math.max(0, sel - 1); draw(); e.preventDefault(); }
    else if (e.key === "Enter") run(list[sel]);
  };
  $("#pb").onclick = (e) => { if (e.target.id === "pb") close(); const b = e.target.closest("[data-i]"); if (b) run(list[+b.dataset.i]); };
  draw(); $("#pq").focus();
}
function shortcuts() {
  const rows = [["⌘ K", "Command palette"], ["?", "This sheet"], ["⌘ ,", "Configuration"], ["/", "Search or filter this page"], ["J  K", "Next / previous row"], ["Enter", "Open the selected row"],
    ["[  ]", "Previous / next record in an inspector"], ["Esc", "Close a panel or dialog"], ...Object.entries(PAGES).map(([, p]) => [`G ${p.key.toUpperCase()}`, p.label])];
  $("#layer").innerHTML = `<div class="palette-back" id="kb"><div class="palette glass keys-sheet" role="dialog" aria-label="Keyboard shortcuts"><div class="dh"><h2>Keyboard shortcuts</h2><button class="btn ghost ic" data-close aria-label="Close">${icon("x")}</button></div>
    <dl>${rows.map(([k, l]) => `<div><dt><kbd>${esc(k)}</kbd></dt><dd>${esc(l)}</dd></div>`).join("")}</dl></div></div>`;
  $("#kb").onclick = (e) => { if (e.target.id === "kb" || e.target.closest("[data-close]")) $("#layer").innerHTML = ""; };
}
let gAt = 0;
document.addEventListener("keydown", (e) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable;
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); if (ctx.policy) palette(); return; }
  if ((e.metaKey || e.ctrlKey) && e.key === ",") { e.preventDefault(); ctx.go("configuration"); return; }
  if (e.key === "Escape") { if ($("#layer")?.innerHTML) $("#layer").innerHTML = ""; return; }
  if (typing || e.metaKey || e.ctrlKey || e.altKey || !ctx.policy || $("#layer")?.innerHTML || menuOpen() || document.getElementById("tour")) return;
  if (e.key === "?") { e.preventDefault(); shortcuts(); return; }
  if (e.key === "/") { const f = $("#view input.input:not([type=password]), #view input[type=search]"); if (f) { e.preventDefault(); f.focus(); } return; }
  if (e.key === "g") { gAt = Date.now(); return; }
  if (Date.now() - gAt < 1000) { const hit = NAVKEYS[e.key.toLowerCase()]; gAt = 0; if (hit) { e.preventDefault(); ctx.go(hit); } return; }
  if (e.key === "j" || e.key === "k") {
    const rows = $$("#view tbody tr.click"); if (!rows.length) return;
    e.preventDefault(); const i = rows.indexOf(document.activeElement);
    rows[i < 0 ? 0 : e.key === "j" ? Math.min(rows.length - 1, i + 1) : Math.max(0, i - 1)].focus();
  }
});
document.addEventListener("visibilitychange", () => { if (!document.hidden) health(); });
async function boot() {
  ctx.policy = await api("/v1/policy", { quiet401: true }).catch((err) => { if (err.status === 401) { gate(session.key ? "That key was not accepted." : ""); throw err; } throw err; });
  ctx.admin = !!ctx.policy.admin;
  registerCustomTypes(ctx.policy.custom_types);
  shell();
  window.onhashchange = route;
  if (!location.hash) history.replaceState(null, "", "#/overview");
  health(); setInterval(health, 20000);
  stream.watch((st) => { const l = $("#live"); if (!l) return; l.dataset.state = st; l.querySelector(".lv-t").textContent = { live: "live", connecting: "connecting", reconnecting: "reconnecting", off: "off" }[st] || st; });
  stream.on((type) => { if (type === "request") ctx.pulse(); if (type === "posture") refreshAttention(); });
  stream.start();
  if (ctx.admin) { refreshAttention(); setInterval(() => { if (!document.hidden) refreshAttention(); }, 30000); }
  await route();
}
applyTheme(prefs.get("theme", "system"));
boot().catch((err) => { if (err.status !== 401) { app.className = "boot"; app.innerHTML = `<div class="panel pb"><b>Cannot reach the gateway.</b><p class="t2">${esc(err.message)}</p></div>`; } });

/* ------------------------------------------------------------------ favorites */
function isFav() { return prefs.get("favorites", []).some((f) => f.href === location.hash); }
function toggleFav() {
  const favs = prefs.get("favorites", []), href = location.hash || "#/overview";
  const pg = PAGES[ctx.route];
  prefs.set("favorites", isFav() ? favs.filter((f) => f.href !== href) : [...favs, { label: ctx.params.length || ctx.query.toString() ? `${pg.label} (filtered)` : pg.label, href, icon: pg.ic }]);
  renderFavs(); toast(isFav() ? "Added to favorites" : "Removed from favorites");
}
function renderFavs() {
  const el = $("#favs"); if (!el) return;
  const favs = prefs.get("favorites", []);
  el.innerHTML = favs.length ? `<div class="group" role="group" aria-label="favorites"><div class="group-label" aria-hidden="true">FAVORITES</div>${favs.map((f) => `<a class="nav fav" href="${esc(f.href)}" title="${esc(f.label)}">${icon(f.icon || "star")}<span>${esc(f.label)}</span></a>`).join("")}</div>` : "";
}
ctx.renderFavs = renderFavs;

/* ------------------------------------------------------------------ attention center */
const POSTURE = { healthy: "All enforced boundaries healthy", degraded: "Degraded", critical: "Needs attention now" };
const sig = (i) => `${i.severity}|${i.title}|${i.detail}`;
async function refreshAttention() {
  if (!ctx.admin) return;
  try { ctx.attention = await api("/v1/attention"); } catch { return; }
  const a = ctx.attention, dismissed = prefs.get("dismissed", {});
  const active = a.items.filter((i) => i.severity !== "info" && dismissed[i.id] !== sig(i));
  const n = $("#att-n");
  if (n) { n.hidden = !active.length; n.textContent = String(active.length); }
  $("#att")?.setAttribute("aria-label", `Attention center: ${active.length} item${active.length === 1 ? "" : "s"} need attention`);
  $("#att")?.classList.toggle("on", active.length > 0);
  document.documentElement.dataset.posture = a.posture;
  if ($("#layer [data-att]")) openAttention();
}
function openAttention() {
  const a = ctx.attention;
  if (!a) { refreshAttention().then(() => ctx.attention && openAttention()); return; }
  const dismissed = prefs.get("dismissed", {});
  const item = (i) => { const hidden = dismissed[i.id] === sig(i); return `<div class="att-item ${i.severity}${hidden ? " muted" : ""}"><span class="lvl ${i.severity === "critical" ? "required" : i.severity === "warning" ? "recommended" : "info"}">${i.severity.toUpperCase()}</span>
    <div><b>${esc(i.title)}</b><p>${esc(i.detail)}</p><small class="t3">${esc(i.subsystem)} · first seen ${ago(i.first_seen)} · last seen ${ago(i.last_seen)}</small></div>
    <div class="att-act"><button class="btn" data-go="${esc(i.action)}">Open</button><button class="btn ghost" data-dismiss="${esc(i.id)}">${hidden ? "Restore" : "Dismiss"}</button></div></div>`; };
  const layer = drawer("Attention", `${esc(POSTURE[a.posture] || a.posture)} · checked ${a.evaluated_at ? ago(a.evaluated_at) : "now"}`,
    `<div data-att>${a.items.length ? a.items.map(item).join("") : '<p class="t2">Nothing needs attention. Conditions are re-checked every 15 seconds.</p>'}</div>
     <div><h5>POSTURE TIMELINE</h5><ol class="ptl">${(a.timeline || []).slice(0, 12).map((t) => `<li><span class="mono t3">${clock(t.ts)}</span><span class="st ${t.state === "healthy" ? "ok" : t.state === "degraded" ? "warn" : "bad"}">${esc(t.state)}</span><span>${esc(t.reason)}</span></li>`).join("") || "<li class='t3'>No changes recorded yet.</li>"}</ol></div>
     <p class="t3">Dismissed items stay hidden until their condition changes. State is held in memory and resets when the gateway restarts.</p>`);
  layer.onclick = (e) => {
    const go = e.target.closest("[data-go]"), dis = e.target.closest("[data-dismiss]");
    if (go) { $("#layer").innerHTML = ""; ctx.go(go.dataset.go); }
    if (dis) { const d = prefs.get("dismissed", {}), it = a.items.find((x) => x.id === dis.dataset.dismiss); if (d[it.id] === sig(it)) delete d[it.id]; else d[it.id] = sig(it); prefs.set("dismissed", d); refreshAttention(); }
  };
}

/* ------------------------------------------------------------------ page extras: exports, tour prompt, pointer light */
function extras() {
  const acts = $("#view .head .actions");
  if (!acts) return;
  if ((ctx.route === "observability" || ctx.route === "leakbench") && !acts.querySelector("[data-act=export]"))
    acts.insertAdjacentHTML("afterbegin", `<button class="btn" data-act="export" aria-haspopup="menu">${icon("download", "sm")} Export</button>`);
}
async function exportMenu(btn) {
  if (ctx.route === "observability") {
    const s = await api("/v1/stats");
    const data = { kind: "harpo.observability", generated_at: new Date().toISOString(), window_s: s.window_s, totals: s.totals, latency_ms: s.latency_ms, stages: s.stages, upstreams: s.upstreams, by_type: s.by_type, by_reason: s.by_reason, series: s.series };
    const cols = Object.keys(s.series?.[0] || { t: 0 }).map((k) => [k === "t" ? (r) => new Date(r.t * 1000).toISOString() : k, k === "t" ? "time" : k]);
    openMenu(btn, [{ label: "Traffic series (CSV)", icon: "table-2", run: () => download(`harpo-traffic-${stamp()}.csv`, toCSV(s.series || [], cols), "text/csv") },
      { label: "Telemetry snapshot (JSON)", icon: "file-code", run: () => download(`harpo-observability-${stamp()}.json`, JSON.stringify(data, null, 2)) }], { label: "Export" });
  } else if (ctx.route === "leakbench") {
    const lb = await (await fetch("/console/leakbench.json", { cache: "no-store" })).json();
    const tables = Object.entries(lb).filter(([, v]) => Array.isArray(v) && v.length && typeof v[0] === "object");
    const [name, rows] = tables.sort((x, y) => y[1].length - x[1].length)[0] || ["rows", []];
    const keys = [...new Set(rows.flatMap((r) => Object.keys(r).filter((k) => typeof r[k] !== "object")))];
    openMenu(btn, [{ label: `${name} (CSV)`, icon: "table-2", run: () => download(`harpo-leakbench-${name}.csv`, toCSV(rows, keys.map((k) => [k, k])), "text/csv") },
      { label: "Full results (JSON)", icon: "file-code", run: () => download("harpo-leakbench.json", JSON.stringify(lb, null, 2)) }], { label: "Export" });
  }
}
// Pointer light on a few surfaces only; never on touch screens or with reduced motion.
if (matchMedia("(hover: hover) and (pointer: fine)").matches && !reduced()) {
  let raf = 0, last = null;
  document.addEventListener("pointermove", (e) => {
    last = e;
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = 0;
      const el = last.target.closest?.(".posture, [data-pane='egress'], .lit");
      if (!el) return;
      if (!el.querySelector(":scope > .plight")) el.insertAdjacentHTML("afterbegin", '<i class="plight" aria-hidden="true"></i>');
      const r = el.getBoundingClientRect();
      el.style.setProperty("--mx", `${last.clientX - r.left}px`); el.style.setProperty("--my", `${last.clientY - r.top}px`);
    });
  }, { passive: true });
}
document.addEventListener("visibilitychange", () => document.documentElement.classList.toggle("bg-paused", document.hidden));
