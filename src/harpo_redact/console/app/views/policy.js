import { api } from "../core/api.js";
import { $, $$, esc, icon, tlabel, tcol, toast, copy, ago, TYPES, registerCustomTypes } from "../core/dom.js";
import { head, panel, kv, banner, drawer, code } from "../ui/kit.js";

// The Policy page: choose what happens to each kind of value, add your own types, try it, apply it live.
// Keys (API keys, tokens, passwords, private keys) are always redacted: they have no switch here or anywhere.

const GROUPS = [
  ["Credentials", ["SECRET", "PRIVATE_KEY", "ENCODED_DATA"]],
  ["Contact", ["EMAIL", "PHONE", "ADDRESS"]],
  ["People and organisations", ["PERSON", "ORGANIZATION", "LOCATION", "QUASI_ID"]],
  ["Government IDs", ["NL_BSN", "US_SSN", "UK_NINO", "NATIONAL_ID", "ID_DOCUMENT"]],
  ["Money", ["IBAN", "CREDIT_CARD", "ACCOUNT_ID", "CRYPTO_ADDRESS"]],
  ["Dates", ["DATE_OF_BIRTH", "DATE"]],
  ["Network and devices", ["IP_ADDRESS", "DEVICE_ID"]],
  ["Registry", ["PROTECTED_TERM"]],
];
const HINT = {
  SECRET: "API keys, tokens, passwords", PRIVATE_KEY: "PEM and SSH private keys", ENCODED_DATA: "base64 or hex hiding a value",
  EMAIL: "jane@corp.example", PHONE: "+31 20 794 6095", ADDRESS: "Keizersgracht 123, 1015 CJ", PERSON: "Anna de Vries",
  ORGANIZATION: "Acme Holding B.V.", LOCATION: "Rotterdam", QUASI_ID: "details that single someone out", NL_BSN: "Dutch citizen service number",
  US_SSN: "US Social Security number", UK_NINO: "UK National Insurance number", NATIONAL_ID: "national and tax IDs, 13 countries",
  ID_DOCUMENT: "passport and licence numbers", IBAN: "NL91 ABNA 0417 1643 00", CREDIT_CARD: "4111 1111 1111 1111",
  ACCOUNT_ID: "account and record numbers", CRYPTO_ADDRESS: "Bitcoin and Ethereum addresses", DATE_OF_BIRTH: "born 14 March 1985",
  DATE: "any other date", IP_ADDRESS: "203.0.113.7", DEVICE_ID: "MAC, IMEI, VIN", PROTECTED_TERM: "terms in detection.registry",
};
const ACTIONS = [["redact", "Redact"], ["block", "Block"], ["allow", "Allow"]];
const MEANS = { redact: "Replace it with a placeholder", block: "Stop the request", allow: "Send it as written" };
const SAMPLE = "Refund Anna de Vries (anna.devries@acme.example, +31 20 794 6095)\nto NL91 ABNA 0417 1643 00. Staff ref EMP-204811.\nDATABASE_PASSWORD=Qz7vL2mX9pR4tW8k";
const NAME_RE = /^[A-Z][A-Z0-9_]{1,39}$/;

const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
const families = (live) => (live.library?.groups || []).flatMap((g) => g.families);
const snap = (live) => ({ entities: Object.fromEntries(live.types.map((t) => [t.type, t.action])), custom: structuredClone(live.custom_types),
  detectors: Object.fromEntries(families(live).filter((f) => f.live).map((f) => [f.id, f.enabled])) });
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** What to send: actions and detector switches that differ from the configuration file, and the custom types if they differ from it. */
function body(S) {
  const entities = {}, detectors = {};
  for (const t of S.live.types) if (!t.locked && S.draft.entities[t.type] !== t.configured) entities[t.type] = S.draft.entities[t.type];
  for (const f of families(S.live)) if (f.live && S.draft.detectors[f.id] !== f.configured) detectors[f.id] = S.draft.detectors[f.id];
  return { entities, detectors, custom_types: same(S.draft.custom, S.live.config_custom_types) ? null : S.draft.custom };
}
function changes(S) {
  let n = S.live.types.filter((t) => S.draft.entities[t.type] !== S.saved.entities[t.type]).length;
  n += Object.keys(S.draft.detectors).filter((id) => S.draft.detectors[id] !== S.saved.detectors[id]).length;
  const before = Object.fromEntries(S.saved.custom.map((c) => [c.name, c])), after = Object.fromEntries(S.draft.custom.map((c) => [c.name, c]));
  for (const name of new Set([...Object.keys(before), ...Object.keys(after)])) if (!same(before[name], after[name])) n++;
  return n;
}
function placeholders(text) {
  const names = Object.keys(TYPES).sort((a, b) => b.length - a.length).map((n) => n.replace(/[^A-Z0-9_]/g, ""));
  const re = new RegExp(`\\[(${names.join("|")})(?:_(?:\\d{1,6}|[A-Z]{1,3}))?\\]`, "g");
  return esc(text).replace(re, (m, name) => `<span class="ph-chip ${tcol(name)}">${m}</span>`);
}

function typeRow(t, S, editable) {
  const now = S.draft.entities[t.type], was = S.saved.entities[t.type], dirty = now !== was;
  const control = t.locked
    ? `<span class="pol-lock" title="Keys are always redacted">${icon("lock", "sm")}Always redacted</span>`
    : `<div class="seg pol-seg${editable ? "" : " ro"}" data-t="${t.type}" role="radiogroup" aria-label="${esc(tlabel(t.type))}">${ACTIONS.filter(([v]) => t.choices.includes(v)).map(([v, l]) =>
      `<button data-v="${v}" class="${v === now ? `on ${v}` : ""}" title="${esc(MEANS[v])}" role="radio" aria-checked="${v === now}"${editable ? "" : " disabled"}>${l}</button>`).join("")}</div>`;
  return `<div class="pol-row${dirty ? " dirty" : ""}${t.locked ? " locked" : ""}"><span class="ent ${tcol(t.type)}">${esc(tlabel(t.type))}</span>
    <span class="pol-hint">${esc(HINT[t.type] || "")}</span>${dirty ? `<span class="pol-was">was ${esc(was)}</span>` : ""}${control}</div>`;
}
function typesHtml(S, editable) {
  const by = Object.fromEntries(S.live.types.map((t) => [t.type, t]));
  return GROUPS.map(([g, list]) => `<div class="pol-group"><div class="pol-gl">${esc(g)}</div>${list.filter((t) => by[t]).map((t) => typeRow(by[t], S, editable)).join("")}</div>`).join("");
}
// The detection library: every detector family under the kind of data it protects. Families the live policy can
// switch have On and Off; credentials are always on; model families are set in the configuration file (a restart).
function libRow(f, S, editable) {
  const hint = `<span class="pol-hint" title="${esc(f.detail)}">${esc(f.detail)}</span>`;
  if (!f.live) {
    const keys = (f.locked || "").startsWith("Credentials");
    const lock = f.locked
      ? `<span class="pol-lock${keys ? "" : " soft"}" title="${esc(f.locked)}">${icon(keys ? "lock" : "sliders-horizontal", "sm")}${keys ? "Always on" : f.enabled ? "On" : "Off"}</span>`
      : `<span class="pol-lock soft" title="Set in the configuration file (${esc(f.setting || "")}): it loads a model, so a change needs a restart.">${icon("rotate-ccw", "sm")}${f.enabled ? "On" : "Off"} · restart</span>`;
    return `<div class="pol-row lib locked"><span class="lib-t">${esc(f.title)}</span>${hint}${lock}</div>`;
  }
  const now = S.draft.detectors[f.id], was = S.saved.detectors[f.id], dirty = now !== was;
  return `<div class="pol-row lib${dirty ? " dirty" : ""}"><span class="lib-t">${esc(f.title)}</span>${hint}${dirty ? `<span class="pol-was">was ${was ? "on" : "off"}</span>` : ""}
    <div class="seg pol-seg${editable ? "" : " ro"}" data-f="${esc(f.id)}" role="radiogroup" aria-label="${esc(f.title)}">${[[true, "On"], [false, "Off"]].map(([v, l]) =>
      `<button data-v="${v ? "on" : "off"}" class="${v === now ? `on ${v ? "redact" : "allow"}` : ""}" title="${esc(f.setting || "")}" role="radio" aria-checked="${v === now}"${editable ? "" : " disabled"}>${l}</button>`).join("")}</div></div>`;
}
function libraryHtml(S, editable) {
  return (S.live.library?.groups || []).map((g) => `<div class="pol-group"><div class="pol-gl">${esc(g.name)}</div>${g.families.map((f) => libRow(f, S, editable)).join("")}</div>`).join("");
}
function customHtml(S, editable) {
  if (!S.draft.custom.length) {
    return `<div class="pol-empty"><div class="pe-ic">${icon("tag", "lg")}</div><p>Add what only your organisation knows about: staff numbers, case IDs, project names. Placeholders carry your name for it, like <code>[EMPLOYEE_ID_1]</code>.</p></div>`;
  }
  const saved = Object.fromEntries(S.saved.custom.map((c) => [c.name, c]));
  return S.draft.custom.map((c, i) => `<div class="pol-ct${same(saved[c.name], c) ? "" : " dirty"}"><div class="ct-top"><span class="ent c10 mono">${esc(c.name)}</span>
      <div class="seg pol-seg${editable ? "" : " ro"}" data-c="${i}">${ACTIONS.map(([v, l]) => `<button data-v="${v}" class="${v === c.action ? `on ${v}` : ""}" title="${esc(v === "allow" ? "Switched off: not looked for" : MEANS[v])}"${editable ? "" : " disabled"}>${v === "allow" ? "Off" : l}</button>`).join("")}</div>
      ${editable ? `<button class="btn ghost ic" data-edit="${i}" aria-label="Edit ${esc(c.name)}">${icon("pencil", "sm")}</button><button class="btn ghost ic" data-del="${i}" aria-label="Remove ${esc(c.name)}">${icon("trash-2", "sm")}</button>` : ""}</div>
    <div class="ct-meta">${c.description ? `${esc(c.description)} · ` : ""}${plural(c.terms.length, "term")} · ${plural(c.patterns.length, "pattern")} · <span class="mono">[${esc(c.name)}_1]</span></div></div>`).join("");
}
function stateHtml(S) {
  const l = S.live;
  const notes = l.notices?.length ? banner("info", `<b>${plural(l.notices.length, "setting")} in the configuration file no longer ${l.notices.length === 1 ? "does" : "do"} anything:</b> ${l.notices.map((n) => `<code>${esc(n)}</code>`).join(" ")}`) : "";
  if (!l.editable) {
    return `${banner("warn", `<b>This gateway cannot save from the console.</b> ${esc(l.reason || "")} You can still try changes here; <b>Get the YAML</b> gives the lines for the configuration file.`)}${notes}`;
  }
  const when = l.updated_at ? `changed ${ago(Date.parse(l.updated_at) / 1000)} by <b>${esc(l.updated_by || "an admin")}</b>` : "no changes from the console yet";
  return `<div class="pol-state"><span class="dot"></span><span>Live policy</span><span class="t3">·</span><span class="mono t2">${esc(l.file)}</span><span class="t3">·</span><span class="t2">${when}</span>${l.error ? `<span class="st bad">the file is not valid; the previous policy stays: ${esc(l.error)}</span>` : ""}</div>${notes}`;
}
function globalPanel(p, eff) {
  return panel("Global policy", kv([
    ["Default placeholder mode", esc(p.default_mode)], ["Context repair", p.context_repair ? "on" : "off"], ["Clients may choose the mode", p.client_may_choose_mode ? "yes" : "no"],
    ["Undeclared request fields", esc(p.unknown_fields), true], ["Remote MCP servers", esc(p.remote_mcp), true], ["Images, audio, provider files", esc(p.unsupported_content), true],
    ["Who may override a block", esc(eff?.override ?? "listed keys"), true], ["Egress verification", esc(p.egress_verification), true], ["Response scanning", esc(p.response_scan)],
    ...(eff ? [["Context-rot threshold", esc(eff.rot_threshold)], ["Allow-listed terms", esc(eff.allow_terms)]] : []),
  ]), { cls: "mt", r: `<a class="btn ghost" href="#/configuration">${icon("sliders-horizontal", "sm")} Stage a change</a>` });
}
const KEYS = `<section class="pol-keys panel"><div class="pk-ic">${icon("lock-keyhole", "lg")}</div><div class="pk-t"><h3>Keys are always redacted</h3>
  <p>API keys, tokens, passwords and private keys are replaced with placeholders before anything leaves, and the request goes on. No policy, override or switch changes that.</p></div>
  <div class="pk-chips">${["API keys", "Tokens", "Passwords", "Private keys"].map((x) => `<span class="tag ver">${icon("check", "sm")}${x}</span>`).join("")}</div></section>`;

export default async function policy(view, ctx) {
  const p = ctx.policy;
  if (!ctx.admin) {
    // Read-only: the same matrix, without switches.
    const types = Object.entries(p.entities || {}).map(([type, e]) => ({ type, action: e.action, configured: e.action, locked: (p.always_redacted || []).includes(type), choices: [] }));
    const S = { live: { types, custom_types: p.custom_types || [] }, saved: null, draft: null };
    S.saved = S.draft = { entities: Object.fromEntries(types.map((t) => [t.type, t.action])), custom: (p.custom_types || []).map((c) => ({ ...c, terms: Array(c.terms).fill(""), patterns: Array(c.patterns).fill("") })) };
    view.innerHTML = `${head("Policy", "What happens to each kind of value. Changing it needs an admin key.", "", "MASK")}${KEYS}
      <div class="pol-grid mt"><section class="panel"><div class="ph"><h3>What happens to each type</h3></div>${typesHtml(S, false)}</section>
      <div class="pol-side"><section class="panel"><div class="ph"><h3>Custom types</h3></div>${customHtml(S, false)}</section></div></div>${globalPanel(p, null)}`;
    return;
  }

  let live;
  try { live = await api("/v1/policy/live"); } catch (err) { view.innerHTML = `${head("Policy", "", "", "MASK")}${banner("bad", esc(err.message))}`; return; }
  const eff = (await api("/v1/config/effective").catch(() => null))?.config?.policy;
  const S = { live, saved: snap(live), draft: snap(live), seq: 0, timer: 0 };

  view.innerHTML = `${head("Policy", "Choose what matters to you. A change applies to new requests at once, on every worker, and survives restarts.",
    `<button class="btn" id="pol-reset">${icon("rotate-ccw", "sm")} Back to the configuration</button>`, "MASK")}
    ${KEYS}<div id="pol-state"></div>
    <div class="pol-grid mt">
      <section class="panel"><div class="ph"><h3>What matters to you</h3><div class="r" id="pol-count"></div></div><div id="pol-types"></div></section>
      <div class="pol-side">
        <section class="panel"><div class="ph"><h3>Your own types</h3><div class="r"><button class="btn" id="pol-add">${icon("plus", "sm")} Add a type</button></div></div><div id="pol-custom"></div></section>
        <section class="panel pol-try"><div class="ph"><h3>Try it</h3><div class="r" id="pol-verdict"></div></div>
          <div class="pb"><textarea class="area pol-in" id="pol-text" spellcheck="false" aria-label="Sample text">${esc(SAMPLE)}</textarea>
          <div class="pol-arrow">${icon("arrow-right", "sm")}<span>What leaves the gateway with this policy</span></div><div class="pol-out" id="pol-out"></div><div class="pol-reasons" id="pol-reasons"></div></div></section>
      </div>
    </div>
    <section class="panel mt"><div class="ph"><h3>Detection library</h3><div class="r" id="pol-lib-count"></div></div>
      <p class="pol-lib-sub">Every detector, under the kind of data it protects. Switching one off stops it looking; the actions above still decide what happens to what the others find.</p><div id="pol-lib"></div></section>
    ${globalPanel(p, eff)}
    <div class="pol-bar glass" id="pol-bar" hidden></div>`;

  const draw = () => {
    registerCustomTypes(S.draft.custom);
    $("#pol-state").innerHTML = stateHtml(S);
    $("#pol-types").innerHTML = typesHtml(S, true);
    $("#pol-custom").innerHTML = customHtml(S, true);
    $("#pol-lib").innerHTML = libraryHtml(S, true);
    const custom = S.draft.custom.length, total = S.live.types.length;
    $("#pol-count").textContent = `${total} types${custom ? ` · ${custom} of your own` : ""}`;
    const fams = families(S.live), on = fams.filter((f) => (f.live ? S.draft.detectors[f.id] : f.enabled)).length;
    $("#pol-lib-count").textContent = `${on} of ${fams.length} families on`;
    const n = changes(S), bar = $("#pol-bar");
    bar.hidden = !n;
    bar.innerHTML = n ? `<span class="pb-dot"></span><b>${plural(n, "change")} not applied</b><span class="t3 hide-sm">Nothing changes until you apply.</span><span class="grow"></span>
      <button class="btn" id="pol-discard">Discard</button><button class="btn pri" id="pol-apply">${icon("check", "sm")} ${S.live.editable ? "Apply now" : "Get the YAML"}</button>` : "";
  };
  const preview = () => { clearTimeout(S.timer); S.timer = setTimeout(run, 260); };
  async function run() {
    const seq = ++S.seq, text = $("#pol-text")?.value || "";
    if (!text.trim()) { $("#pol-out").innerHTML = ""; $("#pol-reasons").innerHTML = ""; $("#pol-verdict").innerHTML = ""; return; }
    try {
      const r = await api("/v1/policy/preview", { method: "POST", body: { text, policy: body(S) } });
      if (seq !== S.seq) return;
      $("#pol-verdict").innerHTML = r.blocked ? '<span class="st bad">would be blocked</span>' : '<span class="st ok">would be sent</span>';
      $("#pol-out").innerHTML = placeholders(r.text);
      $("#pol-out").classList.toggle("blocked", r.blocked);
      $("#pol-reasons").innerHTML = r.reasons.filter((x) => x.level !== "green").map((x) => `<div class="pr ${x.level}">${icon(x.level === "red" ? "octagon-x" : "info", "sm")}<span>${esc(x.message)}</span></div>`).join("");
    } catch (err) {
      if (seq !== S.seq) return;
      const errs = err.data?.error?.harpo?.errors;
      $("#pol-verdict").innerHTML = '<span class="st warn">not valid</span>';
      $("#pol-out").innerHTML = `<span class="t-bad">${esc(errs?.length ? errs.map((e) => e.message).join("; ") : err.message)}</span>`;
      $("#pol-reasons").innerHTML = "";
    }
  }
  const showYaml = (info) => {
    const yaml = info?.config_yaml || "";
    const layer = drawer("Policy as configuration", "This gateway cannot save from the console. Put these lines in the configuration file, or set policy.live_file and apply again.",
      `${code(esc(yaml), "pol-yaml")}<div class="row"><button class="btn pri" id="pol-copy">${icon("copy", "sm")} Copy</button></div>`);
    $("#pol-copy", layer).onclick = () => copy(yaml, "YAML copied");
  };
  async function apply() {
    const btn = $("#pol-apply");
    if (btn) btn.disabled = true;
    try {
      const res = await api("/v1/policy/live", { method: "PUT", body: body(S) });
      S.live = res; S.saved = snap(res); S.draft = snap(res);
      ctx.policy = await api("/v1/policy");
      ctx.system = await api("/v1/system").catch(() => ctx.system);  // the Detection page shows the library as it is now
      registerCustomTypes(ctx.policy.custom_types);
      toast("Applied. New requests use this policy now.");
      draw(); preview();
    } catch (err) {
      if (err.status === 409) showYaml(err.data?.error?.harpo);
      else toast(err.data?.error?.harpo?.errors?.[0]?.message || err.message, true);
      if (btn) btn.disabled = false;
    }
  }
  function confirmReset() {
    const layer = drawer("Back to the configuration", "Remove every change made on this page. The configuration file alone decides again, on every worker.",
      `<p class="t2">The live policy file is deleted. Nothing in the configuration file changes.</p><div class="row"><button class="btn" data-close>Cancel</button><button class="btn danger" id="pol-go">${icon("rotate-ccw", "sm")} Go back</button></div>`);
    $("#pol-go", layer).onclick = async () => {
      try {
        const res = await api("/v1/policy/live", { method: "DELETE" });
        S.live = res; S.saved = snap(res); S.draft = snap(res);
        ctx.policy = await api("/v1/policy"); registerCustomTypes(ctx.policy.custom_types);
        ctx.system = await api("/v1/system").catch(() => ctx.system);
        layer.innerHTML = ""; toast("Back to the configuration file."); draw(); preview();
      } catch (err) { toast(err.message, true); }
    };
  }
  function editType(index) {
    const c = index == null ? { name: "", description: "", terms: [], patterns: [], action: "redact", overridable: false } : S.draft.custom[index];
    const layer = drawer(index == null ? "Add a type" : `Edit ${esc(c.name)}`, "Values it finds are replaced with placeholders that carry its name. Terms match whole words in any case; patterns use RE2.",
      `<div class="field"><label>Name</label><input class="input mono-in" id="ct-name" value="${esc(c.name)}" placeholder="EMPLOYEE_ID" maxlength="40" autocomplete="off"></div>
      <p class="t3 ct-ph">Placeholders: <code id="ct-ph">[${esc(c.name || "EMPLOYEE_ID")}_1]</code></p>
      <div class="field"><label>Description</label><input class="input" id="ct-desc" value="${esc(c.description)}" placeholder="Staff numbers from HR" maxlength="200"></div>
      <div class="field"><label>Terms, one per line</label><textarea class="area" id="ct-terms" rows="4" placeholder="Project Bluefin">${esc(c.terms.join("\n"))}</textarea></div>
      <div class="field"><label>Patterns, one per line (RE2)</label><textarea class="area mono-in" id="ct-pats" rows="3" placeholder="\\bEMP-\\d{6}\\b">${esc(c.patterns.join("\n"))}</textarea></div>
      <div class="field"><label>When it is found</label><div class="seg pol-seg" id="ct-act">${ACTIONS.map(([v, l]) => `<button data-v="${v}" class="${v === c.action ? `on ${v}` : ""}">${v === "allow" ? "Off" : l}</button>`).join("")}</div></div>
      <div class="field"><label>Test it</label><input class="input" id="ct-test" placeholder="Paste a line that should match" autocomplete="off"><div class="pol-out sm" id="ct-out"></div></div>
      <p class="t-bad" id="ct-err" role="alert"></p>
      <div class="row"><button class="btn" data-close>Cancel</button><button class="btn pri" id="ct-save">${icon("check", "sm")} ${index == null ? "Add to the policy" : "Keep changes"}</button></div>`);
    let action = c.action;
    const read = () => ({ name: $("#ct-name", layer).value.trim().toUpperCase().replace(/[\s-]+/g, "_"), description: $("#ct-desc", layer).value.trim(),
      terms: $("#ct-terms", layer).value.split("\n").map((x) => x.trim()).filter(Boolean), patterns: $("#ct-pats", layer).value.split("\n").map((x) => x.trim()).filter(Boolean), action, overridable: false });
    const candidate = () => { const list = structuredClone(S.draft.custom), next = read(); if (index == null) list.push(next); else list[index] = next; return { list, next }; };
    let t = 0;
    const test = () => { clearTimeout(t); t = setTimeout(async () => {
      const sample = $("#ct-test", layer).value, { list, next } = candidate();
      $("#ct-ph", layer).textContent = `[${next.name || "EMPLOYEE_ID"}_1]`;
      if (!sample.trim() || !NAME_RE.test(next.name) || !(next.terms.length || next.patterns.length)) { $("#ct-out", layer).innerHTML = ""; return; }
      try {
        registerCustomTypes([next]);
        const r = await api("/v1/policy/preview", { method: "POST", body: { text: sample, policy: { ...body(S), custom_types: list } } });
        $("#ct-out", layer).innerHTML = placeholders(r.text); $("#ct-err", layer).textContent = "";
      } catch (err) { $("#ct-err", layer).textContent = err.data?.error?.harpo?.errors?.map((e) => e.message).join("; ") || err.message; }
    }, 250); };
    for (const id of ["#ct-name", "#ct-terms", "#ct-pats", "#ct-test"]) $(id, layer).addEventListener("input", test);
    $("#ct-act", layer).onclick = (e) => { const b = e.target.closest("button"); if (!b) return; action = b.dataset.v; for (const x of $$("button", $("#ct-act", layer))) x.className = x === b ? `on ${action}` : ""; test(); };
    $("#ct-save", layer).onclick = async () => {
      const { list, next } = candidate();
      if (!NAME_RE.test(next.name)) { $("#ct-err", layer).textContent = "The name is 2 to 40 capital letters, digits or underscores, starting with a letter."; return; }
      if (!next.terms.length && !next.patterns.length) { $("#ct-err", layer).textContent = "Give at least one term or pattern."; return; }
      if (list.filter((x) => x.name === next.name).length > 1) { $("#ct-err", layer).textContent = `There is already a type called ${next.name}.`; return; }
      try { await api("/v1/policy/preview", { method: "POST", body: { text: "check", policy: { ...body(S), custom_types: list } } }); }
      catch (err) { $("#ct-err", layer).textContent = err.data?.error?.harpo?.errors?.map((e) => e.message).join("; ") || err.message; return; }
      S.draft.custom = list; layer.innerHTML = ""; draw(); preview();
    };
    $("#ct-name", layer).focus();
  }

  view.onclick = (e) => {
    const b = e.target.closest("button");
    if (!b || b.disabled) return;
    const seg = b.closest(".pol-seg");
    if (seg?.dataset.t) { S.draft.entities[seg.dataset.t] = b.dataset.v; draw(); preview(); return; }
    if (seg?.dataset.c) { S.draft.custom[+seg.dataset.c].action = b.dataset.v; draw(); preview(); return; }
    if (seg?.dataset.f) { S.draft.detectors[seg.dataset.f] = b.dataset.v === "on"; draw(); preview(); return; }
    if (b.dataset.edit) return editType(+b.dataset.edit);
    if (b.dataset.del) { S.draft.custom.splice(+b.dataset.del, 1); draw(); preview(); return; }
    ({ "pol-add": () => editType(null), "pol-apply": apply, "pol-discard": () => { S.draft = structuredClone(S.saved); draw(); preview(); }, "pol-reset": confirmReset })[b.id]?.();
  };
  $("#pol-text").addEventListener("input", preview);
  draw();
  run();
}
