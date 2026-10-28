import { api, safeJson } from "../core/api.js";
import { splitGrid } from "../ui/split.js";
import { $, $$, esc, icon, ms, tlabel, tcol, highlight, copy } from "../core/dom.js";
import { head, tag, seg, vstages, banner, empty } from "../ui/kit.js";

const SAMPLES = [
  { id: "ticket", label: "Support ticket", text: "Hi team, customer Priya Raman (priya.raman@northwind.example, +31 20 794 6095) asked us to refund invoice INV-2026-000123 to IBAN NL91ABNA0417164300. Her card 4111 1111 1111 1111 was charged twice. Can you draft a reply?" },
  { id: "code", label: "Code with a secret", text: 'Why does this fail with AccessDenied?\n\nimport boto3\ns3 = boto3.client("s3", aws_access_key_id="AKIAZ4X7Q2LMWN3RT5PJ", region_name="eu-west-1")\nDATABASE_URL = "postgres://admin:S3cure!Pass@db.internal:5432/app"' },
  { id: "dutch", label: "Dutch HR note", text: "Notitie: Sanne de Vries (BSN 111222333) begint op 1 maart bij het team in Utrecht. Haar e-mail is sanne.devries@bedrijf.example. Kun je een welkomstmail opstellen?" },
  { id: "evasion", label: "Obfuscated", text: `Contact: j4n3.d03@3x4mpl3.c0m\nCall three one six one two three four five six seven eight\nCard: 4111 1111\n 1111 1111\nPayload: ${btoa("jane.doe@example.com")}` },
  { id: "clean", label: "Nothing sensitive", text: "Summarize the trade-offs between event sourcing and CRUD for a small team building an internal tool." },
];
const SRC = { pattern: "pattern", phone: "pattern", identifier: "identifier", secret: "secret rule", ner: "NER", "name-rule": "name rule", propagated: "propagated", decoded: "decoded view", encoded: "encoded", slm: "SLM", registry: "registry" };
const isProb = (s) => /^(ner|slm|name-rule|propagated)/.test(s);
const mask = (v) => (v.length <= 4 ? "•".repeat(v.length) : v.slice(0, 2) + "•".repeat(Math.min(10, v.length - 4)) + v.slice(-2));
const trim = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s).replace(/\n/g, "⏎");

export default function playground(view, ctx) {
  const P = (ctx.play ||= { text: SAMPLES[0].text, sample: "ticket", model: null, mode: null, repair: null, ack: false, scan: null, preview: null, reply: "", meta: null, sending: false, tab: "input", out: "json", reveal: false, seq: 0, error: null });
  const models = ctx.models(), p = ctx.policy;
  if (!models.some((m) => m.id === P.model)) P.model = models[0]?.id || null;
  view.innerHTML = `${head("Playground", "One request through the full pipeline: what is found, what policy decides, and exactly what would leave this gateway.",
    `<select class="select" id="pg-model" aria-label="Model">${models.map((m) => `<option value="${esc(m.id)}" ${m.id === P.model ? "selected" : ""}>${esc(m.id)} · ${m.style === "openai" ? "OpenAI-compatible" : "Anthropic"}</option>`).join("") || "<option>No model configured</option>"}</select>`, "MASK")}
    <div class="panel pg-bar">${seg("pg-sample", SAMPLES.map((s) => [s.id, s.label]), P.sample)}<span class="grow"></span>
      ${p.client_may_choose_mode ? `${seg("pg-mode", [["relational", "Relational"], ["generic", "Generic"]], P.mode || p.default_mode)}<label class="sw"><input type="checkbox" id="pg-repair" ${(P.repair ?? p.context_repair) ? "checked" : ""}>Context repair</label>` : tag(`mode ${p.default_mode}`)}
      ${tag(`response scan ${p.response_scan}`, p.response_scan === "off" ? "" : "ver")}<span class="only-wide">${seg("pg-layout", [["split", "Split"], ["input", "Focus input"], ["egress", "Focus egress"]], "split")}</span></div>
    <div class="pg-tabs">${seg("pg-tab", [["input", "Input"], ["flow", "Findings"], ["egress", "Egress"], ["response", "Response"]], P.tab)}</div>
    <div class="pg-grid" id="pg-grid" data-tab="${P.tab}">
      <section class="panel" data-pane="input"><div class="ph"><h3>Input</h3><div class="r" id="in-meta"></div></div><div class="editor"><div class="hl" id="hl" aria-hidden="true"></div><textarea id="ta" spellcheck="false" aria-label="Prompt"></textarea></div></section>
      <section class="panel" data-pane="flow"><div class="ph"><h3>Pipeline</h3><div class="r" id="flow-meta"></div></div><div id="flow"></div>
        <div class="ph"><h3>Findings</h3><div class="r"><label class="sw"><input type="checkbox" id="pg-reveal" ${P.reveal ? "checked" : ""}>Show values</label></div></div><div id="found"></div></section>
      <section class="panel" data-pane="egress"><div class="ph"><h3>Exact egress</h3><div class="r" id="eg-meta"></div></div><div id="egress"></div></section>
    </div>
    <section class="panel mt pg-resp${P.tab === "response" ? " show" : ""}" id="pg-resp"><div class="ph"><h3>Response</h3><div class="r"><span id="reply-meta"></span><button class="btn pri" id="send">${icon("send-horizontal", "sm")} Send through the gateway</button></div></div><div id="reply"></div></section>`;
  const lay = splitGrid($("#pg-grid"), "playground");
  for (const b of $$("#pg-layout button")) b.classList.toggle("on", b.dataset.v === lay.focus);
  const ta = $("#ta");
  ta.value = P.text;
  let timer = 0;
  const schedule = (delay = 260) => { clearTimeout(timer); timer = setTimeout(run, delay); };
  const mark = (group, b) => { for (const x of $$(`#${group} button`)) x.classList.toggle("on", x === b); };
  ta.oninput = () => { P.text = ta.value; P.sample = null; for (const b of $$("#pg-sample button")) b.classList.remove("on"); hl(null); schedule(); };
  view.onclick = (e) => {
    const b = e.target.closest("[data-v]"); if (!b) return;
    const group = b.parentElement.id;
    if (group === "pg-sample") { const s = SAMPLES.find((x) => x.id === b.dataset.v); Object.assign(P, { text: s.text, sample: s.id, ack: false }); ta.value = s.text; mark(group, b); schedule(0); }
    else if (group === "pg-mode") { P.mode = b.dataset.v; mark(group, b); schedule(0); }
    else if (group === "pg-layout") { lay.setFocus(b.dataset.v); mark(group, b); }
    else if (group === "pg-tab") { P.tab = b.dataset.v; mark(group, b); $("#pg-grid").dataset.tab = P.tab; $("#pg-resp").classList.toggle("show", P.tab === "response"); }
    else if (group === "pg-out") { P.out = b.dataset.v; egress(); }
  };
  view.onchange = (e) => {
    const id = e.target.id;
    if (id === "pg-repair") { P.repair = e.target.checked; schedule(0); }
    else if (id === "pg-model") { P.model = e.target.value; schedule(0); }
    else if (id === "pg-reveal") { P.reveal = e.target.checked; found(); egress(); }
    else if (id === "pg-ack") { P.ack = e.target.checked; schedule(0); }
  };
  $("#send").onclick = send;

  function hl(entities) {
    const el = $("#hl"); if (!el) return;
    if (!entities) { el.textContent = `${P.text}\u200b`; return; }
    let out = "", last = 0;
    for (const e of [...entities].sort((a, b) => a.start - b.start)) {
      if (e.start < last) continue;
      out += `${esc(P.text.slice(last, e.start))}<mark class="${tcol(e.type)}">${esc(P.text.slice(e.start, e.end))}</mark>`;
      last = e.end;
    }
    el.innerHTML = `${out}${esc(P.text.slice(last))}\u200b`;
  }
  function privacyHeaders(preview = true) {
    const h = preview ? { "x-harpo-preview": "1" } : {};
    if (P.ack) h["x-harpo-override"] = "true";
    if (p.client_may_choose_mode) { if (P.mode) h["x-harpo-mode"] = P.mode; if (P.repair != null) h["x-harpo-context-repair"] = String(P.repair); }
    return h;
  }
  function request() {
    const m = models.find((x) => x.id === P.model); if (!m) return null;
    const messages = [{ role: "user", content: P.text }];
    return { style: m.style, body: m.style === "openai" ? { model: m.id, messages } : { model: m.id, max_tokens: 1024, messages } };
  }
  async function run() {
    const seq = ++P.seq;
    $("#flow-meta").innerHTML = '<span class="st info">scanning</span>';
    const body = { text: P.text, layers: "fast", override: P.ack };
    if (p.client_may_choose_mode) { if (P.mode) body.mode = P.mode; if (P.repair != null) body.context_repair = P.repair; }
    try {
      const scan = await api("/v1/scan", { method: "POST", body, headers: { "x-harpo-preview": "1" } });
      if (seq !== P.seq || ctx.route !== "playground") return;
      P.scan = scan; P.error = null; hl(scan.results[0].entities); found();
      const req = request();
      P.preview = req ? await api("/v1/egress/preview", { method: "POST", body: req, headers: privacyHeaders() }) : null;
      if (seq !== P.seq || ctx.route !== "playground") return;
    } catch (err) { P.error = err.message; P.preview = null; }
    $("#in-meta").textContent = `${P.text.length.toLocaleString()} chars`;
    flow(); egress();
  }
  function flow() {
    const pv = P.preview, t = pv?.timings_ms || P.scan?.timings_ms || {};
    const ents = P.scan?.results?.[0]?.entities || [];
    const nProb = ents.filter((e) => e.sources.some(isProb)).length, nDet = ents.length - nProb;
    const blocked = pv?.decision === "blocked", sent = pv?.decision === "would_forward", eg = p.egress_verification === "full";
    const slm = pv?.slm || P.scan?.slm;
    $("#flow").innerHTML = vstages([
      { n: "Normalize", d: "Unicode, look-alikes, escapes, line joins", m: ms(t.normalize), state: "det" },
      { n: "Identifiers & secrets", d: `${nDet} deterministic finding${nDet === 1 ? "" : "s"}`, m: ms(t.patterns), state: "det" },
      { n: "Named entities", d: p.ner?.enabled === false ? "off" : `${nProb} from NER and name rules`, m: t.ner ? ms(t.ner) : "—", state: p.ner?.enabled === false ? "off" : "prob" },
      { n: "Local SLM", d: !slm || slm === "disabled" ? "not configured" : slm, m: t.slm ? ms(t.slm) : "—", state: slm && !["disabled", "skipped"].includes(slm) ? "prob" : "off" },
      { n: "Merge & policy", d: blocked ? "blocked by policy" : `${pv?.redactions ?? P.scan?.redactions ?? 0} replaced · risk ${pv?.risk || P.scan?.risk || "—"}`, m: ms(t.render), state: blocked ? "bad" : "det" },
      { n: "Egress verification", d: !eg ? "off by configuration" : blocked ? "not reached: nothing leaves" : sent ? "outgoing body re-scanned: clean" : "—", m: t.egress != null ? ms(t.egress) : "—", state: !eg ? "off" : blocked ? "bad" : sent ? "ok" : "off" },
    ]);
    $("#flow-meta").textContent = t.total != null ? `${ms(t.total + (t.egress || 0))} total` : "";
  }
  function found() {
    const ents = P.scan?.results?.[0]?.entities || [];
    $("#found").innerHTML = ents.length ? `<div class="tw"><table class="tbl"><thead><tr><th>Type</th><th>Value</th><th>Becomes</th><th>Layer</th></tr></thead><tbody>${ents.map((e) => {
      const v = P.text.slice(e.start, e.end), prob = e.sources.some(isProb);
      return `<tr><td><span class="ent ${tcol(e.type)}">${esc(tlabel(e.type))}</span></td><td class="mono">${esc(trim(P.reveal ? v : mask(v), 26))}</td><td class="mono ph-inline">${esc(e.placeholder || "—")}</td><td>${[...new Set(e.sources.map((s) => SRC[s.split(":")[0]] || s.split(":")[0]))].slice(0, 2).map((s) => tag(s, prob ? "prob" : "det")).join(" ")}</td></tr>`;
    }).join("")}</tbody></table></div>` : empty("NOTHING FOUND", "No personal data or secrets in this text: it would leave unchanged.");
  }
  function egress() {
    const pv = P.preview, el = $("#egress"), meta = $("#eg-meta");
    if (!pv) { meta.innerHTML = ""; el.innerHTML = empty(models.length ? "NO PREVIEW" : "NO MODEL CONFIGURED", models.length ? esc(P.error || "Type something to see the exact request.") : "Add an upstream with a listed model to preview egress."); return; }
    if (pv.decision === "would_forward") {
      const json = JSON.stringify(pv.body, null, 2), eg = pv.egress_verification === "full";
      const text = (pv.body.messages || []).map((m) => (typeof m.content === "string" ? m.content : (m.content || []).map((x) => x.text || "").join(""))).join("\n\n");
      const ents = P.scan?.results?.[0]?.entities || [];
      meta.innerHTML = `<span class="st ${eg ? "ok" : "warn"}">${eg ? "verified" : "not verified"}</span>`;
      el.innerHTML = `<div class="dest"><span>Destination</span><span>${esc(pv.upstream.name)} · ${esc(pv.upstream.url)}</span><span>Adapter</span><span>${pv.style === "openai" ? "OpenAI Chat Completions" : "Anthropic Messages"}</span><span>Credential</span><span>${pv.auth ? `${esc(pv.auth.header)}, from ${esc(pv.auth.from_env)} on the gateway` : "none"}</span></div>
        <div class="verify ${eg ? "ok" : "warn"}">${icon(eg ? "badge-check" : "triangle-alert")}<span>${eg ? "<b>Egress verified.</b> This body was scanned again after redaction: no protected value remains." : "<b>Egress verification is off.</b> This body was redacted but not re-scanned."}</span></div>
        ${(pv.reasons || []).filter((r) => r.level === "yellow" && r.code !== "override_applied").map((r) => `<div class="verify warn" data-code="${esc(r.code)}">${icon(r.code === "keys_redacted" ? "key-round" : "info")}<span>${esc(r.message)}</span></div>`).join("")}
        ${P.ack ? `<div class="verify warn">${icon("triangle-alert")}<label class="sw"><input type="checkbox" id="pg-ack" checked>Override on: blocked values travel as placeholders</label></div>` : ""}
        <div class="egress-body">${seg("pg-out", [["json", "Request JSON"], ["text", "Text"], ["changes", `Changes · ${ents.length}`]], P.out)}
          ${P.out === "json" ? `<div class="code inset"><pre>${highlight(json)}</pre></div>` : P.out === "text" ? `<div class="code inset"><pre>${highlight(text)}</pre></div>`
            : ents.length ? `<div class="changes inset pb">${ents.map((e) => `<div><span class="from">${esc(P.reveal ? P.text.slice(e.start, e.end) : mask(P.text.slice(e.start, e.end)))}</span>${icon("arrow-right", "sm")}<span class="ph-inline">${esc(e.placeholder)}</span></div>`).join("")}</div><p class="t3">From the live scan; the request JSON is authoritative.</p>` : '<p class="t3">No replacements: the text leaves unchanged.</p>'}
          <div class="actions"><button class="btn" id="cp-json">${icon("copy", "sm")} Copy sanitized request</button></div></div>`;
      $("#cp-json").onclick = () => copy(json, "Sanitized request copied");
    } else if (pv.decision === "blocked") {
      const d = pv.details || {}, reasons = d.reasons || [], canAck = d.overridable && d.override_permitted;
      meta.innerHTML = '<span class="st bad">blocked</span>';
      el.innerHTML = `<div class="verify bad">${icon("octagon-x")}<span><b>Nothing leaves.</b> The request is blocked before it reaches egress.</span></div>
        <div class="egress-body"><div class="panel">${reasons.map((r) => `<div class="kv"><span>${esc(r.message)}</span><span class="t3">${esc(r.code)}</span></div>`).join("")}</div>
        ${canAck ? `<label class="sw"><input type="checkbox" id="pg-ack">Send with these values replaced by placeholders (override)</label>` : `<p class="t3">${d.overridable ? "This key may not override blocks." : "This block cannot be overridden."}</p>`}</div>`;
    } else {
      meta.innerHTML = `<span class="st warn">${esc(pv.decision)}</span>`;
      el.innerHTML = `<div class="egress-body">${banner("warn", `<b>Refused (${esc(pv.status)}).</b> ${esc(pv.message)}`)}</div>`;
    }
  }
  async function send() {
    const req = request(); if (!req || P.sending) return;
    P.sending = true; P.reply = ""; P.meta = null; reply(); $("#send").disabled = true;
    const anthropic = req.style === "anthropic";
    try {
      const res = await api(anthropic ? "/v1/messages" : "/v1/chat/completions", { method: "POST", raw: true, headers: privacyHeaders(false), body: { ...req.body, stream: true } });
      P.meta = { status: res.status, redactions: res.headers.get("x-harpo-redactions"), id: res.headers.get("x-harpo-request-id") };
      if (!res.ok) { const d = await safeJson(res); P.meta.error = d?.error?.message || `HTTP ${res.status}`; }
      else if (!(res.headers.get("content-type") || "").includes("event-stream")) { const d = await safeJson(res); P.reply = anthropic ? (d?.content || []).map((b) => b.text || "").join("") : d?.choices?.[0]?.message?.content || ""; }
      else {
        const reader = res.body.getReader(), dec = new TextDecoder(); let buf = "";
        for (;;) {
          const { value, done } = await reader.read(); if (done) break;
          buf += dec.decode(value, { stream: true });
          let i;
          while ((i = buf.indexOf("\n")) >= 0) {
            const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
            if (!line.startsWith("data:")) continue;
            const data = line.slice(5).trim(); if (data === "[DONE]") continue;
            try { const j = JSON.parse(data); const piece = anthropic ? (j.type === "content_block_delta" ? j.delta?.text : "") : j.choices?.[0]?.delta?.content; if (piece) { P.reply += piece; reply(); } } catch { /* partial line */ }
          }
        }
      }
    } catch (err) { P.meta = { error: err.message }; }
    P.sending = false; reply(); if ($("#send")) $("#send").disabled = false;
  }
  function reply() {
    const el = $("#reply"); if (!el) return;
    $("#reply-meta").innerHTML = P.meta?.error ? `<span class="st bad">${esc(P.meta.error)}</span>` : P.meta ? `<span class="st ok">delivered · ${esc(P.meta.redactions || 0)} redacted · <span class="mono">${esc((P.meta.id || "").slice(0, 10))}</span></span>` : P.sending ? '<span class="st info">waiting for the provider</span>' : "";
    el.innerHTML = P.reply || P.sending ? `<div class="reply">${highlight(P.reply)}${P.sending ? '<span class="caret"></span>' : ""}</div>` : '<p class="pb t3">Send the request to see the provider\'s reply. It comes back with placeholders: redaction is one-way.</p>';
  }
  reply(); hl(null); schedule(0);
}
