import { api } from "../core/api.js";
import { $, esc, icon, fmt, ago, copy } from "../core/dom.js";
import { head, panel, table, st, banner } from "../ui/kit.js";

export default async function access(view, ctx) {
  if (!ctx.admin) return ctx.needAdmin(view, "Key management");
  const data = await api("/v1/keys");
  view.innerHTML = `${head("Access", "Gateway keys: who may call the gateway, with which permissions and limits. Existing keys are stored only as hashes and can never be shown.", `<span class="tag">override policy: ${esc(data.override_policy)}</span>`, "VAULT")}
    ${data.auth_enabled ? "" : banner("warn", "<b>Authentication is off.</b> Anyone who can reach this gateway can use it. Turn on <code>auth.enabled</code> for anything but a local demo.")}
    ${panel("Keys", '<div id="keys"></div>', { cls: "mt", r: `${data.keys.length} configured` })}
    ${panel("Create a key", `<div class="pb grid g4"><div class="field"><label>Key id</label><input class="input mono-in" id="k-id" placeholder="team-support"></div>
        <div class="field"><label>Expires (optional)</label><input class="input" id="k-exp" type="date"></div>
        <div class="field"><label>Requests per minute (optional)</label><input class="input" id="k-rpm" type="number" min="1" placeholder="unlimited"></div>
        <div class="field"><label>Permissions</label><div class="actions"><label class="sw"><input type="checkbox" id="k-admin">admin</label><label class="sw"><input type="checkbox" id="k-ovr">may override</label></div></div></div>
      <div class="pf"><button class="btn pri" id="k-gen">${icon("key-round", "sm")} Generate key</button><span>The key is created here and shown once. It is not stored: add it to your configuration to activate it.</span></div><div id="k-out"></div>`, { cls: "mt" })}`;
  table($("#keys"), { rows: data.keys, sort: ["id", "asc"], cols: [
    { k: "id", l: "Key", f: (k) => `<b class="mono">${esc(k.id)}</b>` }, { k: "fingerprint", l: "Fingerprint", f: (k) => `<span class="mono t3">${esc(k.fingerprint)}…</span>` },
    { k: "admin", l: "Role", v: (k) => (k.admin ? 1 : 0), f: (k) => (k.admin ? '<span class="tag prob">admin</span>' : '<span class="tag">client</span>') },
    { k: "can_override", l: "Override", v: (k) => (k.can_override ? 1 : 0), f: (k) => (k.can_override ? "yes" : '<span class="t3">no</span>') },
    { k: "expires_at", l: "Expires", f: (k) => (k.expires_at ? `<span class="mono">${esc(k.expires_at.slice(0, 10))}</span>` : '<span class="t3">never</span>') },
    { k: "requests_per_minute", l: "Rate limit", r: true, f: (k) => (k.requests_per_minute ? `${fmt(k.requests_per_minute)}/min` : '<span class="t3">none</span>') },
    { k: "requests", l: "Requests", r: true, f: (k) => fmt(k.requests) }, { k: "last_seen", l: "Last seen", f: (k) => `<span class="t2">${ago(k.last_seen)}</span>` },
    { k: "expired", l: "State", v: (k) => (k.expired ? 1 : 0), f: (k) => (k.expired ? st("bad", "expired") : st("ok", "active")) },
  ], emptyHtml: '<p class="pb t3">No keys configured.</p>' });
  $("#k-gen").onclick = async () => {
    const exp = $("#k-exp").value, rpm = +$("#k-rpm").value || null;
    try {
      const r = await api("/v1/keys/generate", { method: "POST", body: { id: $("#k-id").value.trim(), admin: $("#k-admin").checked, can_override: $("#k-ovr").checked, expires_at: exp ? `${exp}T00:00:00Z` : null, requests_per_minute: rpm } });
      $("#k-out").innerHTML = `<div class="pb"><div class="panel lumen danger pb"><div class="eyebrow">SHOWN ONCE · NOT RECOVERABLE</div><div class="actions"><input class="input mono-in" readonly value="${esc(r.key)}" id="k-val"><button class="btn" id="k-copy">${icon("copy", "sm")} Copy key</button></div>
        <p class="t2 mt">Add this under <code>auth.keys</code> in your configuration and restart the gateway. Only the hash is in the snippet.</p><div class="code inset mt-s"><pre>${esc(r.yaml)}</pre></div></div></div>`;
      $("#k-copy").onclick = () => copy(r.key, "Key copied: store it now");
    } catch (err) { $("#k-out").innerHTML = `<div class="pb">${banner("bad", esc(err.message))}</div>`; }
  };
}
