// Detector lab: a sample through each detection stage separately. Transient: nothing is stored, logged or counted.
import { api } from "../core/api.js";
import { $, esc, ms, paint, tlabel } from "../core/dom.js";
import { head, banner, seg, ent } from "../ui/kit.js";

const SAMPLES = [
  ["Support ticket", "Hi, this is Priya Raman (priya.raman@northwind.example, +44 20 7946 0958). Please refund invoice 7731 to IBAN GB33BUKB20201555555555."],
  ["Obfuscated", "Reach me at jane\u200b.doe@leak-test.example or j4n3.d03@l34k-t3st.3x4mpl3, card 4111-1111-1111-1111, phone +31 20\n794 6095"],
  ["Encoded", "payload amFuZS5kb2VAbGVhay10ZXN0LmV4YW1wbGU= and callback ?email=jane.doe%40leak-test.example"],
  ["Look-alikes", "Contact j\u0430ne.d\u043ee@leak-test.example (Cyrillic letters) or \uff0b\uff13\uff11 \uff12\uff10 \uff17\uff19\uff14 \uff16\uff10\uff19\uff15"],
  ["Secrets", "deploy with AKIAZ4X7Q2LMWN3RT5PJ, then rotate the token ghp_R8xV2mQ9tL4wK7nB3cY6hJ1sD5fG0aZ2eU8i"],
  ["Structured and disguised", "name,bsn,date_of_birth\nJ. Smit,298163871,14 March 1985\ncard \u202e4111 4357 1749 3014\u202c, DNI 74913826\u0421, IMEI (hex) 33352d3938373130302d3537303036312d33"],
  ["Dutch HR note", "Sanne de Vries (BSN 111222333) woont op Keizersgracht 12, Amsterdam. Haar manager is Pieter Jansen."],
  ["Clean", "Summarize the Q3 roadmap and list three risks for the platform team."],
];
const decoded = (v) => {
  try {
    if (/^[A-Za-z0-9+/_-]{12,}={0,2}$/.test(v)) { const t = new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(atob(v.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))); if (/^[\x20-\x7e]+$/.test(t)) return t; }
    if (/%[0-9a-f]{2}/i.test(v)) return decodeURIComponent(v);
  } catch { /* not decodable: show the value as is */ }
  return null;
};
const spans = (list) => `<ul class="spans">${list.map((s) => { const d = decoded(s.value); return `<li>${ent(s.type, tlabel(s.type))}<code>${esc(s.value)}</code>${d ? `<span class="dec">decodes to <code>${esc(d)}</code></span>` : ""}<small>${esc(s.sources.join(", "))}</small></li>`; }).join("")}</ul>`;

export default function lab(view, ctx) {
  const S = (ctx.lab ||= { text: SAMPLES[0][1], sample: "0", result: null });
  let seq = 0, timer = null;
  view.innerHTML = `${head("Detector lab", "One sample through each detection stage separately: normalization, shadow views, rules, secrets, encoded data and NER, then the merged result and policy.", "", "MASK")}
    ${banner("info", "<b>Transient.</b> The sample goes to this gateway's lab endpoint and comes back to this tab only. It is not stored, logged, counted or sent to a provider. Use synthetic or test text.")}
    <div class="panel pg-bar mt">${seg("lab-s", SAMPLES.map(([n], i) => [String(i), n]), S.sample)}<span class="tag">synthetic samples</span></div>
    <div class="lab mt"><section class="panel lab-input"><div class="ph"><h3>Sample</h3><div class="r t3" id="lab-n"></div></div><label class="sr" for="lab-t">Sample text</label><textarea id="lab-t" spellcheck="false"></textarea></section>
      <div id="lab-out" class="lab-out" aria-live="polite"></div></div>`;
  const ta = $("#lab-t");
  ta.value = S.text;
  const render = (r) => {
    const n = r.normalized, f = r.final;
    $("#lab-out").innerHTML = `
      <section class="panel"><div class="ph"><h3>1 · Normalized view</h3><div class="r">${n.changed ? '<span class="tag warn">changed</span>' : '<span class="tag">unchanged</span>'}<span class="tag">${n.removed_format_chars} hidden chars removed</span><span class="tag">${n.mixed_script_tokens} mixed-script tokens</span></div></div><pre class="lab-text">${esc(n.text)}</pre></section>
      <section class="panel"><div class="ph"><h3>2 · Shadow views</h3><div class="r t3">decoded copies the rules also read</div></div>${r.shadow_views.length ? r.shadow_views.map((v) => `<div class="view"><b>${esc(v.name)}</b><pre class="lab-text">${esc(v.text)}</pre></div>`).join("") : '<p class="pb t3">No escapes, split lines, spelled runs or leetspeak emails to decode.</p>'}</section>
      <div class="lab-layers">${r.layers.map((l) => `<section class="panel"><div class="ph"><h3>${esc(l.name)}</h3><div class="r"><span class="tag ${l.kind === "probabilistic" ? "prob" : "det"}">${l.kind}</span><b class="num">${l.enabled ? l.spans.length : "off"}</b></div></div>
        ${!l.enabled ? '<p class="pb t3">Not enabled on this gateway.</p>' : l.spans.length ? spans(l.spans) : '<p class="pb t3">Nothing found by this stage.</p>'}</section>`).join("")}</div>
      <section class="panel"><div class="ph"><h3>3 · Merged result and policy</h3><div class="r"><span class="st ${f.risk === "red" ? "bad" : f.risk === "yellow" ? "warn" : "ok"}">risk ${esc(f.risk || "none")}</span></div></div>
        ${f.findings.length ? `<div class="tw" tabindex="0" role="region" aria-label="Merged findings"><table class="tbl"><thead><tr><th>Value</th><th>Type</th><th>Placeholder</th><th>Sources</th></tr></thead><tbody>${f.findings.map((x) => `<tr><td><code>${esc(x.value)}</code></td><td>${ent(x.type, tlabel(x.type))}</td><td class="mono">${esc(x.placeholder || "—")}</td><td class="mono t3 wrap">${esc(x.sources.join(", "))}</td></tr>`).join("")}</tbody></table></div>` : '<p class="pb t3">Nothing to redact.</p>'}
        ${f.reasons.length ? `<div class="pb">${f.reasons.map((x) => `<span class="tag bad">${esc(x.code)}</span> <span class="t2">${esc(x.message)}</span>`).join("<br>")}</div>` : ""}
        <div class="pb"><h5>WHAT WOULD LEAVE</h5><pre class="lab-text">${esc(f.text)}</pre></div></section>
      <section class="panel"><div class="ph"><h3>Timings</h3><div class="r t3">${esc(r.slm.note)}</div></div><div class="pb lab-times">${Object.entries(r.timings_ms).map(([k, v]) => `<span><small>${esc(k.replace(/_/g, " "))}</small><b class="num">${ms(v)}</b></span>`).join("")}</div></section>`;
    paint($("#lab-out"));
  };
  const run = async () => {
    const mine = ++seq;
    S.text = ta.value;
    $("#lab-n").textContent = `${ta.value.length} chars`;
    if (!ta.value.trim()) { $("#lab-out").innerHTML = '<div class="panel"><p class="pb t3">Type or choose a sample.</p></div>'; return; }
    try {
      const r = await api("/v1/lab/detect", { method: "POST", body: { text: ta.value } });
      if (mine === seq && ctx.route === "lab") { S.result = r; render(r); }
    } catch (e) { if (mine === seq) $("#lab-out").innerHTML = `<div class="panel"><p class="pb t-bad">${esc(e.message)}</p></div>`; }
  };
  ta.oninput = () => { clearTimeout(timer); timer = setTimeout(run, 350); };
  $("#lab-s").onclick = (e) => { const b = e.target.closest("button"); if (!b) return; S.sample = b.dataset.v; ta.value = SAMPLES[+b.dataset.v][1]; for (const x of $("#lab-s").querySelectorAll("button")) x.classList.toggle("on", x === b); run(); };
  run();
}
