// First-run setup: produces a validated configuration file. Nothing is saved or applied by this page.
import { api } from "../core/api.js";
import { $, $$, esc, icon, copy, fmt, ms, toast } from "../core/dom.js";
import { head } from "../ui/kit.js";

const STEPS = ["Welcome", "Deployment", "Provider", "Gateway key", "Protection", "Local SLM", "Documents", "Verify", "Connect"];
const PROFILES = {
  strict: { label: "Strict", note: "Recommended", unknown_fields: "reject", unsupported_content: "block", response_scan: "report",
    why: ["Request fields the adapter does not declare are refused, with the field path in the error.", "Images, audio and provider-side files are refused, never forwarded.", "Non-streamed answers are checked for secrets and identifiers, and counted."] },
  balanced: { label: "Balanced", note: "Fewer refusals", unknown_fields: "pass", unsupported_content: "drop", response_scan: "off",
    why: ["Undeclared fields are scanned as text instead of refused.", "Images and audio are removed from requests, with a visible marker.", "Provider answers are not scanned."] },
};
const yaml = (v, ind = "") => {
  if (Array.isArray(v)) return v.length ? v.map((x) => (x && typeof x === "object" ? `\n${ind}- ${yaml(x, `${ind}  `).trimStart()}` : `\n${ind}- ${yaml(x)}`)).join("") : " []";
  if (v && typeof v === "object") return Object.entries(v).map(([k, x]) => `\n${ind}${k}:${x && typeof x === "object" ? yaml(x, `${ind}  `) : ` ${yaml(x)}`}`).join("");
  return typeof v === "string" ? JSON.stringify(v) : String(v);
};

export default async function setup(view, ctx) {
  if (!ctx.admin) return ctx.needAdmin(view, "Setup");
  const S = { step: 0, deploy: "local", env: "production", provider: null, models: [], key: null, sha: null, profile: "strict", orZdr: false,
    slm: { enabled: false, base_url: "http://127.0.0.1:11434", model: "llama3.2:3b", on_failure: "fail_closed" }, docs: { enabled: true, images: "block" },
    validation: null, checks: null };
  const presets = (await api("/v1/setup/presets")).providers;
  S.provider = presets[0]; S.models = presets[0].models.filter((m) => !/[*?[]/.test(m));
  const config = () => {
    const p = S.provider;
    return {
      environment: S.env,
      server: { host: S.deploy === "local" ? "127.0.0.1" : "0.0.0.0", port: 8080 },
      auth: { enabled: true, keys: S.sha ? [{ id: "owner", sha256: S.sha, admin: true }] : [] },
      upstreams: [{ name: p.id, style: p.style, base_url: p.base_url, ...(p.key_env ? { api_key_env: p.key_env } : {}), models: [...S.models, ...p.models.filter((m) => /[*?[]/.test(m))] },
        ...(p.companions || []).map((c) => ({ name: c.name, style: c.style, base_url: c.base_url, ...(c.key_env ? { api_key_env: c.key_env } : {}), models: c.models }))]
        .map((u) => (u.base_url.includes("openrouter.ai") ? { ...u, openrouter: { data_collection: "deny", zdr: S.orZdr } } : u)),
      policy: { egress_verification: "full", unknown_fields: PROFILES[S.profile].unknown_fields, unsupported_content: PROFILES[S.profile].unsupported_content, response_scan: PROFILES[S.profile].response_scan },
      detection: { slm: S.slm.enabled ? { enabled: true, base_url: S.slm.base_url, model: S.slm.model, on_failure: S.slm.on_failure } : { enabled: false } },
      documents: { enabled: S.docs.enabled, images: S.docs.images },
    };
  };
  const text = () => `# Written by the Harpo setup wizard. Every option: config/harpo.example.yaml${yaml(config())}\n`;
  const choice = (group, value, title, body, on) => `<button class="choice${on ? " on" : ""}" data-g="${group}" data-v="${esc(value)}" aria-pressed="${on}"><b>${title}</b><span>${body}</span></button>`;
  const body = () => {
    const p = S.provider;
    switch (STEPS[S.step]) {
      case "Welcome": return `<h2>Set up Harpo in a couple of minutes</h2><p class="t2">You choose a provider, a protection profile and a few options. The page writes a configuration file and checks it with the gateway's own loader.</p>
        <div class="checks">${[["shield-check", "Secure defaults are pre-selected; anything that weakens protection says so."], ["file-text", "The result is a file. Nothing changes until you restart the gateway with it."], ["key", "Your provider's API key never enters this page: you set it as an environment variable."]].map(([i, t]) => `<div class="check-row">${icon(i, "sm")}<span>${t}</span><span></span></div>`).join("")}</div>`;
      case "Deployment": return `<h2>Where will the gateway run?</h2><div class="choices">${choice("deploy", "local", "This machine", "Listens on 127.0.0.1: only apps on this computer can reach it.", S.deploy === "local")}${choice("deploy", "server", "A server or Docker", "Listens on 0.0.0.0 inside the container or host. Put it behind TLS.", S.deploy === "server")}</div>
        <h3>Mode</h3><div class="choices">${choice("env", "production", "Production", "Startup refuses unsafe settings: missing keys, plain-HTTP providers.", S.env === "production")}${choice("env", "development", "Development", "Fewer startup checks. For trying things out only.", S.env === "development")}</div>`;
      case "Provider": return `<h2>Which provider should requests go to?</h2><div class="choices">${presets.map((x) => choice("provider", x.id, esc(x.id), `<span class="mono">${esc(x.base_url)}</span>${x.key_env ? ` · key from <code>${esc(x.key_env)}</code>` : " · no key"}`, x.id === p.id)).join("")}</div>
        ${p.id === "openrouter" ? `<h3>OpenRouter privacy routing</h3><p class="t3">Enforced on every request; apps cannot loosen it. Claude Code and Anthropic SDKs get OpenRouter's Anthropic-style API as well.</p>
        <div class="choices">${choice("orzdr", "off", "No prompt storage <em>Recommended</em>", "Only providers that do not store prompts (data_collection: deny).", !S.orZdr)}${choice("orzdr", "on", "Zero data retention", "Only endpoints that retain nothing. Strictest; fewer models are available.", S.orZdr)}</div>` : ""}
        <h3>Models to list for chat apps</h3><label class="sr" for="models">Models</label><input class="input mono-in" id="models" value="${esc(S.models.join(", "))}"><p class="t3">Patterns such as <code>${esc(p.models.find((m) => /[*?[]/.test(m)) || "gpt-*")}</code> are kept as well, so any matching model is routed.</p>`;
      case "Gateway key": return `<h2>A key for your apps</h2><p class="t2">Apps send this key instead of your provider key. Only its SHA-256 hash goes into the file, so it cannot be recovered later: copy it now.</p>
        ${S.key ? `<div class="keybox"><code class="mono">${esc(S.key)}</code><button class="btn" id="copy-key">${icon("copy", "sm")} Copy</button></div><p class="t3">This page forgets the key when you leave it.</p>` : `<button class="btn pri" id="gen">${icon("key")} Generate a gateway key</button>`}`;
      case "Protection": return `<h2>Protection profile</h2><p class="t2">Egress verification is always on: it is security-critical and not offered as a setup choice.</p><div class="choices">${Object.entries(PROFILES).map(([k, x]) => choice("profile", k, `${x.label} <em>${x.note}</em>`, x.why.map(esc).join("<br>"), S.profile === k)).join("")}</div>`;
      case "Local SLM": return `<h2>Optional: a local model for indirect identifiers</h2><p class="t2">A small model on your own machine (via Ollama) finds what patterns cannot, such as quasi-identifiers. It can only add findings; it never approves a request.</p>
        <div class="choices">${choice("slm", "off", "Not now", "Deterministic layers and NER only. You can add it later.", !S.slm.enabled)}${choice("slm", "on", "Use a local model", "Requests wait for the model, within its timeout.", S.slm.enabled)}</div>
        ${S.slm.enabled ? `<div class="form2"><label>Endpoint<input class="input mono-in" id="slm-url" value="${esc(S.slm.base_url)}"></label><label>Model<input class="input mono-in" id="slm-model" value="${esc(S.slm.model)}"></label></div>
        <div class="choices">${choice("slmfail", "fail_closed", "If it is down: block", "Nothing leaves without the model's check. Safest.", S.slm.on_failure === "fail_closed")}${choice("slmfail", "degrade", "If it is down: continue", "Deterministic layers still run; the request is marked degraded.", S.slm.on_failure === "degrade")}</div>` : ""}`;
      case "Documents": return `<h2>Documents</h2><div class="choices">${choice("docs", "on", "Redact documents", "PDF, Word, Excel, PowerPoint and text, in an isolated worker, verified before release.", S.docs.enabled)}${choice("docs", "off", "Turn documents off", "The document endpoint is disabled.", !S.docs.enabled)}</div>
        ${S.docs.enabled ? `<h3>Pictures inside documents</h3><p class="t3">There is no OCR, so text in pictures cannot be checked.</p><div class="choices">${choice("images", "block", "Refuse files with pictures", "Recommended: nothing unchecked is released.", S.docs.images === "block")}${choice("images", "blank", "Replace pictures with blanks", "The file is released without its pictures.", S.docs.images === "blank")}</div>` : ""}`;
      case "Verify": return `<h2>Checks</h2>${S.checks ? checkList() : `<p class="t2">Validates the file with the gateway's loader and checks this running gateway.</p><button class="btn pri" id="verify">${icon("list-checks")} Run the checks</button>`}`;
      case "Connect": return connect();
      default: return "";
    }
  };
  const row = (state, name, detail) => `<div class="check-row ${state}">${icon(state === "ok" ? "circle-check" : state === "bad" ? "octagon-x" : state === "warn" ? "triangle-alert" : "circle-dashed", "sm")}<span><b>${esc(name)}</b>${detail ? `<small>${detail}</small>` : ""}</span><span class="st ${state}">${{ ok: "passed", bad: "failed", warn: "attention", off: "skipped" }[state]}</span></div>`;
  const checkList = () => {
    const c = S.checks, v = S.validation;
    const ready = !c.error && v?.valid && c.ready && c.selftest?.ok === true;  // READY only when every required check passed
    return `${ready ? `<div class="ready lumen assure"><div class="eyebrow">HARPO READY</div><h3>The configuration is valid and this gateway is healthy.</h3><p class="t2">Restart the gateway with the file to apply it.</p></div>` : ""}
      <div class="checks">${row(v?.valid ? "ok" : "bad", "Configuration valid", v?.valid ? "checked by the gateway's own loader" : esc((v?.errors || []).map((e) => `${e.line ? `line ${e.line}: ` : ""}${e.loc ? `${e.loc}: ` : ""}${e.message}`).join(" · ") || "invalid"))}
        ${(v?.production_problems || []).map((pr) => row("warn", "Production guard", esc(pr))).join("")}
        ${row(c.ready ? "ok" : "bad", "Gateway ready", "this running gateway")}
        ${row(c.ner ? "ok" : "warn", "Named-entity models loaded", c.nerDetail)}
        ${row(c.rules ? "ok" : "warn", "Secret rules loaded", c.rules ? `${fmt(c.rules)} rules` : "")}
        ${row("ok", "Egress verification", "enabled in this file")}
        ${row(c.selftest?.ok ? "ok" : c.selftest ? "bad" : "off", "Live self-test", c.selftest ? esc(c.selftest.detail) : "not run")}
        ${row(c.provider?.reachable ? (c.provider.auth === "accepted" ? "ok" : "warn") : c.provider ? "bad" : "off", `Provider · ${S.provider.id}`, c.provider ? esc(c.provider.reachable ? `HTTP ${c.provider.status} · key ${c.provider.auth} · ${ms(c.provider.latency_ms)}` : `unreachable${c.provider.error ? ` · ${c.provider.error}` : ""}`) : "checked after you restart with this file")}
        ${row(S.slm.enabled ? "off" : "off", "Local SLM", S.slm.enabled ? "checked when the gateway starts with this file" : "not configured")}
        ${row(S.docs.enabled ? "ok" : "off", "Documents", S.docs.enabled ? `pictures: ${S.docs.images}` : "off")}</div>
      <button class="btn" id="verify">${icon("refresh-cw", "sm")} Run again</button>`;
  };
  const connect = () => {
    const p = S.provider, base = location.origin, key = S.key || "<your gateway key>";
    const env = p.style === "openai" ? `export OPENAI_BASE_URL=${base}/v1\nexport OPENAI_API_KEY=${key}` : `export ANTHROPIC_BASE_URL=${base}\nexport ANTHROPIC_API_KEY=${key}`;
    return `<h2>Apply it and connect your first app</h2>
      <div class="steps-n"><div><b>1</b><span>Save the file and set your provider key on the gateway host.</span></div><div><b>2</b><span>Restart: <code>harpo serve --config harpo.yaml</code></span></div><div><b>3</b><span>Point an app at the gateway with the gateway key.</span></div></div>
      <div class="row-btns"><button class="btn pri" id="dl">${icon("download", "sm")} Download harpo.yaml</button><button class="btn" id="cp-yaml">${icon("copy", "sm")} Copy YAML</button></div>
      ${p.key_env ? `<div class="code"><pre>export ${esc(p.key_env)}=…   # your provider key, on the gateway host only</pre></div>` : ""}
      <div class="code"><pre>${esc(env)}</pre></div><p class="t3">More apps, agents and SDKs: <a href="#/integrations">Integrations</a>.</p><button class="btn" id="tour-go">${icon("sparkles", "sm")} Take the 5-step tour</button>`;
  };
  const render = () => {
    view.innerHTML = `${head("Setup", "A guided configuration with secure defaults. It produces a validated file; nothing is applied until you restart with it.", "", "SHIELD")}
      <div class="wiz"><nav class="panel wiz-rail" aria-label="Setup steps"><div class="wiz-progress"><i data-w="${(S.step / (STEPS.length - 1)) * 100}"></i></div>
        ${STEPS.map((n, i) => `<button data-step="${i}" class="${i === S.step ? "on" : i < S.step ? "done" : ""}" ${i === S.step ? 'aria-current="step"' : ""}><span class="n">${i < S.step ? icon("check", "sm") : i + 1}</span>${n}</button>`).join("")}</nav>
        <section class="panel wiz-body" aria-live="polite"><div class="pb">${body()}</div>
          <div class="wiz-nav"><button class="btn" id="back" ${S.step === 0 ? "disabled" : ""}>Back</button><span class="t3">Step ${S.step + 1} of ${STEPS.length}</span><button class="btn pri" id="next" ${S.step === STEPS.length - 1 ? "disabled" : ""}>${S.step === 0 ? "Start" : "Continue"} ${icon("arrow-right", "sm")}</button></div></section></div>`;
    for (const el of $$("[data-w]", view)) requestAnimationFrame(() => { el.style.width = `${el.dataset.w}%`; });
  };
  const verify = async () => {
    const b = $("#verify"); if (b) { b.disabled = true; b.textContent = "Checking…"; }
    const checks = {};
    try {
      S.validation = await api("/v1/config/validate", { method: "POST", body: { yaml: text() } });
      const sys = await api("/v1/system");
      checks.ready = sys.readiness?.status === "ready" || sys.gateway?.ready === true;
      const models = sys.models || sys.detection?.models || [];
      checks.ner = sys.readiness?.checks?.ner === "ok" || sys.checks?.ner === "ok";
      checks.nerDetail = Array.isArray(models) && models.length ? models.map((m) => m.name || m).join(", ") : "";
      checks.rules = sys.secret_rules ?? sys.detection?.secret_rules ?? null;
      try {
        const t = await api("/v1/selftest", { method: "POST", body: {} });
        const results = t.results || [], passing = results.filter((r) => r.status === "pass").length;
        checks.selftest = { ok: t.passed === true, detail: `${passing} of ${results.length} live checks passed` };
      } catch (err) { checks.selftest = { ok: false, detail: err.message }; }
      const running = (ctx.policy.upstreams || []).find((u) => u.name === S.provider.id);
      if (running) checks.provider = await api(`/v1/providers/${encodeURIComponent(running.name)}/check`, { method: "POST", body: {} }).catch((err) => ({ reachable: false, error: err.message }));
    } catch (err) { checks.error = err.message; toast(err.message, true); }
    S.checks = checks; render();
  };
  view.onclick = async (e) => {
    const step = e.target.closest("[data-step]"); if (step) { S.step = +step.dataset.step; return render(); }
    const c = e.target.closest(".choice");
    if (c) {
      const g = c.dataset.g, v = c.dataset.v;
      if (g === "provider") { S.provider = presets.find((x) => x.id === v); S.models = S.provider.models.filter((m) => !/[*?[]/.test(m)); }
      else if (g === "orzdr") S.orZdr = v === "on";
      else if (g === "slm") S.slm.enabled = v === "on"; else if (g === "slmfail") S.slm.on_failure = v;
      else if (g === "docs") S.docs.enabled = v === "on"; else if (g === "images") S.docs.images = v; else S[g] = v;
      S.checks = null; return render();
    }
    const id = e.target.closest("button")?.id;
    if (id === "next") { S.step = Math.min(STEPS.length - 1, S.step + 1); render(); $("#next")?.focus(); }
    else if (id === "back") { S.step = Math.max(0, S.step - 1); render(); }
    else if (id === "gen") { const r = await api("/v1/keys/generate", { method: "POST", body: { id: "owner", admin: true } }); S.key = r.key; S.sha = r.sha256 || r.entry?.sha256; S.checks = null; render(); }
    else if (id === "copy-key") copy(S.key, "Key copied");
    else if (id === "tour-go") import("../ui/tour.js").then((m) => m.startTour(ctx));
    else if (id === "verify") verify();
    else if (id === "cp-yaml") copy(text(), "Configuration copied");
    else if (id === "dl") { const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([text()], { type: "text/yaml" })), download: "harpo.yaml" }); a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }
  };
  view.onchange = (e) => {
    if (e.target.id === "models") S.models = e.target.value.split(",").map((m) => m.trim()).filter(Boolean);
    if (e.target.id === "slm-url") S.slm.base_url = e.target.value.trim();
    if (e.target.id === "slm-model") S.slm.model = e.target.value.trim();
    S.checks = null;
  };
  render();
}
