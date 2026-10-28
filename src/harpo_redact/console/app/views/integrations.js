import { session } from "../core/api.js";
import { $, $$, esc, icon, inline, highlight, copy } from "../core/dom.js";
import { head, panel, seg, drawer, empty } from "../ui/kit.js";

export default async function integrations(view, ctx) {
  ctx.catalog ||= await (await fetch("/console/integrations.json", { cache: "no-store" })).json();
  const I = (ctx.integ ||= { q: "", cat: "All", verified: false });
  const cat = ctx.catalog, models = ctx.models(), origin = location.origin;
  const fill = (s, real = false) => s.replaceAll("{OPENAI_BASE}", `${origin}/v1`).replaceAll("{ANTHROPIC_BASE}", origin)
    .replaceAll("{KEY}", !ctx.policy.auth?.enabled ? "any-value" : session.key ? (real ? session.key : `${session.key.slice(0, 6)}…`) : "<gateway-key>")
    .replaceAll("{MODEL}", models.find((m) => m.style === "openai")?.id || "gpt-4o-mini").replaceAll("{CLAUDE_MODEL}", models.find((m) => m.style === "anthropic")?.id || "claude-sonnet-4-5");
  view.innerHTML = `${head("Integrations", "Every integration is one setting: the base URL. The configuration below is filled in with this gateway's address.", `<span class="tag ok">${cat.items.filter((x) => x.verified).length} verified end to end</span><span class="tag">${cat.items.length} documented</span>`, "SHIELD")}
    <div class="grid g3">${[["OpenAI-compatible base URL", `${origin}/v1`], ["Anthropic base URL", origin], ["API key", ctx.policy.auth?.enabled ? "your gateway key (never the provider key)" : "any value: auth is off"]].map(([k, v], i) => `<div class="panel pb"><div class="field"><label>${k}</label><div class="actions"><input class="input mono-in" readonly value="${esc(v)}">${i < 2 ? `<button class="btn ic" data-cp="${esc(v)}" title="Copy">${icon("copy", "sm")}</button>` : ""}</div></div></div>`).join("")}</div>
    <div class="panel pg-bar mt">${seg("int-cat", ["All", ...cat.categories].map((c) => [c, c]), I.cat)}<span class="grow"></span><label class="sw"><input type="checkbox" id="int-ver" ${I.verified ? "checked" : ""}>Verified only</label><input class="input" id="int-q" placeholder="Search" value="${esc(I.q)}"></div>
    <div class="int-grid mt" id="ints"></div>`;
  $("#int-q").style.width = "200px";
  const draw = () => {
    const q = I.q.trim().toLowerCase();
    const items = cat.items.filter((x) => (I.cat === "All" || x.category === I.cat) && (!I.verified || x.verified) && (!q || `${x.name} ${x.category} ${x.summary}`.toLowerCase().includes(q)));
    $("#ints").innerHTML = items.length ? items.map((x) => `<button class="panel int" data-int="${x.id}"><span class="mono-tile">${esc(x.mono)}</span><span><h4>${esc(x.name)}</h4><div class="cat">${esc(x.category)}</div></span><p>${esc(x.summary)}</p>
      <span class="marks">${x.verified ? '<span class="tag ok">verified</span>' : '<span class="tag">vendor docs</span>'}${x.caveat ? '<span class="tag warn">read the note</span>' : ""}</span></button>`).join("") : `<div class="panel">${empty("NO MATCH", "Anything that lets you set an OpenAI or Anthropic base URL works the same way.")}</div>`;
    for (const b of $$("[data-int]", view)) b.onclick = () => open(cat.items.find((x) => x.id === b.dataset.int));
  };
  const open = (x, tab = 0) => {
    const sn = x.snippets[tab];
    const layer = drawer(esc(x.name), `${esc(x.category)} · ${x.verified ? "verified end to end against the gateway" : "configured per the vendor's documentation"}`,
      `<p class="t2">${inline(x.summary)}</p>
       ${x.steps.length ? `<div><h5>STEPS</h5><ol class="t2">${x.steps.map((s) => `<li>${inline(fill(s))}</li>`).join("")}</ol></div>` : ""}
       ${sn ? `<div><h5>CONFIGURATION</h5>${x.snippets.length > 1 ? seg("int-tab", x.snippets.map((s, i) => [String(i), s.label]), String(tab)) : ""}<div class="code inset mt-s"><pre>${highlight(fill(sn.code))}</pre><button class="btn copy" id="int-copy">${icon("copy", "sm")} Copy</button></div></div>` : ""}
       ${x.notes.map((n) => `<div class="banner ${n.kind === "info" ? "info" : "warn"}">${icon(n.kind === "info" ? "info" : "triangle-alert")}<div>${inline(n.text)}</div></div>`).join("")}
       ${x.docs ? `<a class="btn" href="${esc(x.docs)}" target="_blank" rel="noopener noreferrer">${icon("external-link", "sm")} Vendor documentation</a>` : ""}`);
    $("#int-tab", layer)?.addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) open(x, +b.dataset.v); });
    $("#int-copy", layer)?.addEventListener("click", () => copy(fill(sn.code, true), session.key && /\{KEY\}/.test(sn.code) ? "Copied with your key" : "Copied"));
  };
  view.onclick = (e) => { const c = e.target.closest("[data-cp]"); if (c) copy(c.dataset.cp, "Base URL copied"); const s = e.target.closest("#int-cat button"); if (s) { I.cat = s.dataset.v; for (const b of $$("#int-cat button")) b.classList.toggle("on", b === s); draw(); } };
  $("#int-q").oninput = (e) => { I.q = e.target.value; draw(); };
  $("#int-ver").onchange = (e) => { I.verified = e.target.checked; draw(); };
  draw();
}
