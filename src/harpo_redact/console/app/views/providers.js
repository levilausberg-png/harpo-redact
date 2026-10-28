import { api } from "../core/api.js";
import { surfaceExplorer, bindSurfaceExplorer, shownAdapters, ADAPTER_LABEL } from "../ui/surfaces.js";
import { $, $$, esc, icon, fmt, ms, bytes } from "../core/dom.js";
import { head, panel, table, tag, st, kv } from "../ui/kit.js";

const HANDLING = { scanned: ["inspected", "det"], identifier: ["shape-checked", "det"], stripped: ["stripped", "ver"], provider: ["provider-signed", "prob"], unsupported: ["refused", "warn"] };

export default async function providers(view, ctx) {
  if (!ctx.admin) return ctx.needAdmin(view, "Providers and adapters");
  const checks = (ctx.checks ||= {});
  const { providers: rows } = await api("/v1/providers");
  const p = ctx.policy;
  view.innerHTML = `${head("Providers & adapters", "Where requests go, and how each request format is inspected before it does. Provider keys stay on the gateway and are never shown.", "", "SHIELD")}
    ${panel("Upstream providers", '<div id="prov"></div>', { r: `${rows.length} configured` })}
    <div class="grid g2 mt">${shownAdapters(p).map(([name, a]) => panel(`${esc(ADAPTER_LABEL[name] || name)} adapter`,
      `${kv([["Undeclared fields", p.unknown_fields === "reject" ? '<span class="st ok">refused, with the field path</span>' : '<span class="st warn">scanned as text</span>', true], ["Identifier rules", fmt(a.identifier_rules)], ["Conformance", '<span class="st ok">tests/test_conformance.py</span>']])}
       <div class="tw"><table class="tbl"><thead><tr><th>Surface</th><th>Handling</th></tr></thead><tbody>${Object.entries(a.surfaces).flatMap(([h, list]) => list.map((path) => `<tr><td class="mono wrap">${esc(path)}</td><td><span class="tag ${HANDLING[h]?.[1] || ""}">${esc(HANDLING[h]?.[0] || h)}</span></td></tr>`)).join("")}</tbody></table></div>
       <div class="pf">${esc(a.guarantees)}</div>`, { r: `${Object.values(a.surfaces).flat().length} surfaces` })).join("")}</div>${surfaceExplorer(p)}`;
  bindSurfaceExplorer(view, p);
  const draw = () => table($("#prov"), { rows, sort: ["name", "asc"], cols: [
    { k: "name", l: "Upstream", f: (u) => `<b>${esc(u.name)}</b>` },
    { k: "style", l: "Protocol", f: (u) => `${u.style === "openai" ? "OpenAI-compatible" : "Anthropic"}${u.dialect === "openrouter" ? ' <span class="tag prob">OpenRouter</span>' : ""}` },
    { k: "routing", l: "Routing policy", sort: false, f: routing },
    { k: "base_url", l: "Endpoint", f: (u) => `<span class="mono t2">${esc(u.base_url)}</span>` },
    { k: "models", l: "Models", v: (u) => u.models.length, f: (u) => `<span class="mono t2">${esc(u.models.slice(0, 3).join(", "))}${u.models.length > 3 ? ` +${u.models.length - 3}` : ""}</span>` },
    { k: "key_env", l: "Key variable", f: (u) => (u.key_env ? `<span class="mono">${esc(u.key_env)}</span> ${u.key_present ? st("ok", "set") : st("bad", "missing")}` : '<span class="t3">none</span>') },
    { k: "requests", l: "Requests", r: true, v: (u) => u.traffic.requests, f: (u) => fmt(u.traffic.requests) },
    { k: "p95", l: "p95", r: true, v: (u) => u.traffic.p95, f: (u) => ms(u.traffic.p95) },
    { k: "errors", l: "Errors", r: true, v: (u) => u.traffic.errors, f: (u) => (u.traffic.errors ? `<span class="t-warn">${fmt(u.traffic.errors)}</span>` : "0") },
    { k: "check", l: "Connection", sort: false, f: (u) => { const c = checks[u.name]; return `<button class="btn" data-check="${esc(u.name)}">${icon("plug", "sm")} Test</button>${c ? `<div class="chk">` + (c.reachable ? st(c.auth === "accepted" ? "ok" : c.auth === "rejected" ? "bad" : "warn", `HTTP ${c.status} · key ${c.auth} · ${ms(c.latency_ms)}`) + account(c.account) : st("bad", `unreachable · ${c.error}`)) + "</div>" : ""}`; } },
  ] });
  draw();
  view.onclick = async (e) => {
    const b = e.target.closest("[data-check]"); if (!b) return;
    b.disabled = true; b.textContent = "Testing…";
    try { checks[b.dataset.check] = await api(`/v1/providers/${encodeURIComponent(b.dataset.check)}/check`, { method: "POST" }); } catch (err) { checks[b.dataset.check] = { reachable: false, error: err.message }; }
    draw();
  };
}

/** OpenRouter's routing policy as the gateway enforces it on every request. */
function routing(u) {
  if (!u.routing) return '<span class="t3">—</span>';
  const r = u.routing, chips = [];
  chips.push(r.data_collection === "deny" ? '<span class="tag ver" title="Enforced: only providers that do not store prompts">no prompt storage</span>' : '<span class="tag warn" title="The client decides whether providers may store prompts">storage: client decides</span>');
  if (r.zdr) chips.push('<span class="tag ver" title="Enforced: zero-data-retention endpoints only">zero retention</span>');
  if (r.only?.length) chips.push(`<span class="tag" title="${esc(r.only.join(", "))}">only ${r.only.length}</span>`);
  if (r.ignore?.length) chips.push(`<span class="tag" title="${esc(r.ignore.join(", "))}">ignore ${r.ignore.length}</span>`);
  return `<span class="chips">${chips.join("")}</span>`;
}
/** Spend and limits from OpenRouter's key endpoint: never the key's label or account identifiers. */
function account(a) {
  if (!a) return "";
  const usd = (v) => (v == null ? "no limit" : `$${Number(v).toFixed(2)}`);
  const bits = [a.limit != null ? `${usd(a.limit_remaining)} of ${usd(a.limit)} left` : "no spending limit", `today ${usd(a.usage_daily ?? 0)}`];
  if (a.is_free_tier) bits.push("free tier");
  if (a.allowed_data_regions?.length) bits.push(`regions: ${a.allowed_data_regions.join(", ")}`);
  if (a.expires_at) bits.push(`expires ${new Date(a.expires_at).toLocaleDateString()}`);
  return `<div class="t3 acct">${esc(bits.join(" · "))}</div>`;
}
