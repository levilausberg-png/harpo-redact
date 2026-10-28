import { $, esc, fmt, ms, pct, paint } from "../core/dom.js";
import { head, panel, stats, table, seg, banner } from "../ui/kit.js";
import { hbars } from "../ui/charts.js";
import { bench } from "./shared.js";

const NAMES = { deterministic: "Deterministic only", ner: "English NER only", "default-image": "Docker default (MIT models)", multilingual: "+ nl, fr, es models (opt-in)" };
export default async function leakbench(view, ctx) {
  const b = await bench(ctx);
  let sel = ctx.lbSel || "default-image";
  const draw = () => {
    const c = b.configs[sel];
    const rec = (m) => Object.entries(m).map(([k, [n, esc_]]) => [k, 1 - esc_ / n]).sort((a, z) => a[1] - z[1]);
    view.innerHTML = `${head("LeakBench", "1,280 labelled values under 18 attacks in five languages, beside look-alike traps that must come out untouched. Results come from <code>bench/leakbench.py</code>; nothing here is estimated.", seg("lb-cfg", Object.keys(b.configs).map((k) => [k, NAMES[k] || k]), sel), "PROOF")}
      <section class="panel elev lumen">${stats([{ k: "Raw escapes", v: fmt(c.raw_identifier_escapes), tone: c.raw_identifier_escapes ? "" : "ok" }, { k: "Recall", v: pct(c.recall) }, { k: "Text damaged", v: pct(c.false_positive_rate, 2) }, { k: "False blocks", v: pct(c.false_block_rate) }, { k: "p95 per prompt", v: c.latency_ms.p95, u: "ms" }, { k: "Labelled values", v: fmt(b.corpus.secrets) }, { k: "Languages", v: Object.keys(c.by_language).length }, { k: "Attack classes", v: Object.keys(c.by_attack).length }])}
        <div class="pb"><div class="band"></div></div></section>
      ${panel("Configurations", '<div id="lb-cmp"></div>', { cls: "mt" })}
      <div class="grid g3 mt">${panel("Recall by attack", `<div class="pb">${hbars(rec(c.by_attack), { label: (k) => esc(k.replace(/_/g, " ")), val: (v) => pct(v), flow: true })}</div>`)}
        ${panel("Recall by kind of data", `<div class="pb">${hbars(rec(c.by_category), { label: (k) => esc(k.replace(/_/g, " ")), val: (v) => pct(v), flow: true })}</div>`)}
        ${panel("Recall by language", `<div class="pb">${hbars(rec(c.by_language), { label: (k) => esc(k), val: (v) => pct(v), flow: true })}</div>`)}</div>
      <div class="mt">${banner("info", "<b>What this does not measure.</b> The corpus is synthetic, so this is behaviour under known attacks, not recall on your traffic. Quasi-identifier combinations and contextual attacks are not in the corpus yet. The local SLM configuration needs Ollama and has not been run for these results.")}</div>`;
    paint(view);
    table($("#lb-cmp"), { rows: Object.entries(b.configs).map(([k, v]) => ({ k, ...v })), cols: [
      { k: "k", l: "Configuration", f: (r) => `${r.k === sel ? "<b>" : ""}${esc(NAMES[r.k] || r.k)}${r.k === sel ? "</b>" : ""}` },
      { k: "raw_identifier_escapes", l: "Escapes", r: true, f: (r) => fmt(r.raw_identifier_escapes) }, { k: "recall", l: "Recall", r: true, f: (r) => pct(r.recall) },
      { k: "false_positive_rate", l: "Text damaged", r: true, f: (r) => pct(r.false_positive_rate, 2) }, { k: "p50", l: "p50", r: true, v: (r) => r.latency_ms.p50, f: (r) => ms(r.latency_ms.p50) }, { k: "p95", l: "p95", r: true, v: (r) => r.latency_ms.p95, f: (r) => ms(r.latency_ms.p95) },
    ] });
    $("#lb-cfg").onclick = (e) => { const t = e.target.closest("button"); if (t) { sel = ctx.lbSel = t.dataset.v; draw(); } };
  };
  draw();
}
