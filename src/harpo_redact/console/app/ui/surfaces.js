// Adapter surface explorer: every field of a provider request and what the adapter does with it (INV-07, INV-08).
import { $, $$, esc } from "../core/dom.js";
import { drawer, kv } from "./kit.js";

const HANDLING = {
  scanned: ["Scanned", "det", "Free text. Normalised, checked by every detection layer and redacted; egress verification scans it again before it leaves.", "INV-01"],
  identifier: ["Identifier", "ver", "A short machine name: model, role, tool name, enum value. Shape-checked instead of scanned, so an email or a sentence does not fit.", "INV-07"],
  stripped: ["Stripped", "warn", "Removed before forwarding (user ids, cache keys, locations). The provider never receives it.", "INV-07"],
  provider: ["Provider-signed", "prob", "Content the provider produced and signed, such as thinking blocks. Forwarded unchanged; egress verification still scans it.", "INV-01"],
  unsupported: ["Unsupported", "bad", "Cannot be inspected (images, audio, provider-side files, remote tools): refused, or dropped with a visible marker, by policy.", "INV-04"],
};
function tree(surfaces) {
  const root = { kids: new Map(), leaves: [] };
  for (const [h, paths] of Object.entries(surfaces || {})) {
    for (const raw of paths) {
      const m = /^(\S+)(?:\s+(.*))?$/.exec(raw) || [raw, raw, ""];
      let node = root;
      for (const part of m[1].split(".").filter(Boolean)) {
        if (!node.kids.has(part)) node.kids.set(part, { name: part, kids: new Map(), leaves: [] });
        node = node.kids.get(part);
      }
      node.leaves.push({ h, note: m[2] || "", path: raw });
    }
  }
  return root;
}
const badge = (l) => { const [label, cls] = HANDLING[l.h] || [l.h, ""]; return `<button class="hb ${cls}" data-surf="${esc(l.h)}" data-path="${esc(l.path)}">${esc(label)}</button>`; };
function list(node, depth = 0) {
  const kids = [...node.kids.values()];
  return `<ul${depth ? "" : ' class="stree"'}>${kids.map((k) => {
    const marks = k.leaves.map((l) => `${badge(l)}${l.note ? `<span class="note">${esc(l.note)}</span>` : ""}`).join("");
    return k.kids.size
      ? `<li><details ${depth < 1 ? "open" : ""}><summary><span>${esc(k.name)}</span></summary>${marks ? `<div class="leaf marks">${marks}</div>` : ""}${list(k, depth + 1)}</details></li>`
      : `<li class="leaf"><span>${esc(k.name)}</span>${marks}</li>`;
  }).join("")}</ul>`;
}
export const ADAPTER_LABEL = { openai: "OpenAI-compatible", anthropic: "Anthropic Messages", openrouter: "OpenRouter · OpenAI-compatible", openrouter_anthropic: "OpenRouter · Anthropic Messages" };
/** The adapters to show: the two base ones always, OpenRouter's only when an upstream uses them. */
export const shownAdapters = (p) => Object.entries(p.adapters || {}).filter(([name, a]) => name === "openai" || name === "anthropic" || a.in_use);
export function surfaceExplorer(p) {
  const unknown = p.unknown_fields === "reject" ? ["Refused", "bad", "refused with the field path"] : ["Scanned", "det", "scanned as text"];
  return `<div class="grid g2 mt">${shownAdapters(p).map(([name, a]) => `<section class="panel"><div class="ph"><h3>Surface explorer · ${esc(ADAPTER_LABEL[name] || name)}</h3><div class="r t3">click a badge</div></div>
    <div class="pb">${list(tree(a.surfaces))}<ul class="stree"><li class="leaf"><span>any other field</span><button class="hb ${unknown[1]}" data-surf="unknown" data-path="(any field the adapter does not declare)">${unknown[0]}</button><span class="note">${unknown[2]} · policy.unknown_fields</span></li></ul></div></section>`).join("")}</div>`;
}
export function bindSurfaceExplorer(root, p) {
  for (const b of $$(".hb", root)) {
    b.onclick = (e) => {
      e.preventDefault();
      const h = b.dataset.surf;
      const [label, , what, inv] = h === "unknown"
        ? [p.unknown_fields === "reject" ? "Refused" : "Scanned as text", "", p.unknown_fields === "reject" ? "A field no adapter rule declares is refused, and the error names its path, never its value." : "A field no adapter rule declares is scanned as text before it can leave.", "INV-08"]
        : HANDLING[h];
      drawer(esc(b.dataset.path), `Handling: ${esc(label)}`, `<div class="panel">${kv([["Handling", esc(label)], ["What happens", esc(what)], ["Guarantee", `<a href="#/guarantees">${esc(inv)}</a>`], ["Verified by", '<span class="mono">tests/test_conformance.py</span> puts a canary in every declared field']])}</div>`);
    };
  }
}
