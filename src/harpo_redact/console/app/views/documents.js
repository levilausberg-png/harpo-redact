import { api, safeJson } from "../core/api.js";
import { $, $$, esc, icon, fmt, ms, bytes, paint } from "../core/dom.js";
import { head, panel, kv, pipe, banner, empty } from "../ui/kit.js";

const STAGES = [["Uploaded", "upload"], ["Parse", "file-scan"], ["Surfaces", "layers"], ["Detect", "scan-search"], ["Redact", "lock"], ["Rebuild", "boxes"], ["Re-parse", "refresh-cw"], ["Verify", "badge-check"], ["Ready", "download"]];
// Where a refusal happens, by the documented error codes (documents/service.py STATUS).
const FAIL_AT = { too_large: 0, zip_bomb: 0, unsupported_format: 1, corrupt: 1, encrypted: 1, macros_present: 1, parse_timeout: 1, images_present: 2, too_many_segments: 2, too_many_pages: 2, privacy_block: 3, residual_sensitive_data: 7, verify_failed: 7 };

export default function documents(view, ctx) {
  const jobs = (ctx.jobs ||= []);
  RECEIPTS.jobs = jobs; RECEIPTS.ctx = ctx;
  const d = ctx.policy.documents || {}, images = ctx.system?.documents?.images;
  const render = () => {
    const sel = jobs.find((j) => j.id === ctx.jobSel) || jobs[0];
    view.innerHTML = `${head("Documents", "Redact PDF, Word, Excel, PowerPoint and text files. Each file is parsed in an isolated worker, rebuilt with values replaced, re-opened and verified before it is released.", "", "MASK")}
      ${d.enabled === false ? banner("warn", "<b>Document redaction is off</b> in this gateway's configuration (<code>documents.enabled</code>).") : ""}
      <div class="doc-grid">
        ${panel("Jobs", `<label class="drop" id="drop"><input type="file" id="file" accept=".pdf,.docx,.xlsx,.pptx,.txt,.csv,.md,.json,.log"><b>Drop a file or choose one</b><span>${esc((d.formats || []).join(" · ").toUpperCase() || "PDF · DOCX · XLSX · PPTX · TXT")} · up to ${bytes(d.max_bytes)}${d.max_pages ? ` · ${d.max_pages} pages` : ""}</span><span>Images are not read: ${esc(images ? (images === "block" ? "files with pictures are refused" : "pictures are replaced by blank ones") : "they are refused or blanked by policy")}. There is no OCR.</span></label>
          <div>${jobs.length ? jobs.map((j) => `<button class="job${sel && j.id === sel.id ? " on" : ""}" data-job="${j.id}"><span class="fmt">${esc(j.ext)}</span><span><div class="nm">${esc(j.name)}</div><div class="mt2">${j.busy ? "processing…" : j.error ? "refused" : `${fmt(j.redactions)} redacted · ${ms(j.ms)}`}</div></span>${j.busy ? '<span class="st info">running</span>' : j.error ? '<span class="st bad">refused</span>' : '<span class="st ok">verified</span>'}</button>`).join("") : '<p class="pb t3">Files you process appear here, for this tab only. Nothing is kept on the gateway.</p>'}</div>`)}
        <div id="inspector">${sel ? inspector(sel) : idle()}</div>
      </div>`;
    paint(view);
    const drop = $("#drop"), input = $("#file");
    if (drop) {
      input.onchange = () => input.files[0] && run(input.files[0]);
      for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); });
      for (const ev of ["dragleave", "drop"]) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); });
      drop.addEventListener("drop", (e) => e.dataTransfer.files[0] && run(e.dataTransfer.files[0]));
    }
    for (const b of $$("[data-job]", view)) b.onclick = () => { ctx.jobSel = b.dataset.job; render(); };
  };
  const idle = () => `<section class="panel doc-idle"><div class="ph"><h3>How a document is processed</h3><span class="t3">no file selected</span></div>
    <div class="pb">${pipe(STAGES.map(([n, ic]) => ({ n, icon: ic, v: "—", state: "off" })))}</div>
    <div class="grid g2 pb"><div class="panel">${kv([["Isolation", "separate worker process, no network"], ["Formats", esc((d.formats || []).join(", ").toUpperCase() || "—")], ["Largest file", bytes(d.max_bytes)], ["Most pages", d.max_pages ? fmt(d.max_pages) : "—"]])}</div>
    <div class="panel">${kv([["Before release", "rebuilt file re-opened and re-scanned"], ["Office files", "authors, thumbnails, macros, embedded objects removed"], ["PDF files", "rebuilt as image-only pages"], ["Images", esc(images === "block" ? "files with pictures refused" : images ? "pictures replaced by blank ones" : "per policy")]])}</div></div>
    <p class="facts-note">Every value comes from this gateway's configuration. There is no OCR: text inside pictures is never read, so pictures are refused or blanked.</p></section>`;
  const inspector = (j) => {
    const failAt = j.error ? FAIL_AT[j.error.code] : null;
    const stages = STAGES.map(([n, ic], i) => ({ n, icon: ic, v: j.busy ? (i === 0 ? "done" : "…") : j.error ? (failAt == null ? "—" : i < failAt ? "done" : i === failAt ? "refused" : "—") : "done",
      state: j.busy ? (i === 0 ? "ok" : "off") : j.error ? (failAt == null ? "off" : i < failAt ? "ok" : i === failAt ? "bad" : "off") : "ok" }));
    const ok = !j.busy && !j.error;
    return `<section class="panel elev ${ok ? "lumen assure" : ""}"><div class="pb">${pipe(stages)}</div>
      ${j.busy ? '<p class="pb t3">Parsing, redacting, rebuilding and verifying…</p>' : j.error ? `<div class="assure fail"><div class="eyebrow">DOCUMENT REFUSED · NOTHING RELEASED</div><h2>${esc((j.error.code || j.error.type || "refused").replace(/_/g, " "))}</h2><p class="t2 mt-s">${esc(j.error.message || "")}</p></div>${failAt == null ? '<p class="pb t3">The gateway did not say which stage refused it.</p>' : ""}`
      : `<div class="assure"><div class="eyebrow">DOCUMENT VERIFIED</div><h2>${esc(j.out)}</h2></div>
        <div class="grid g2 pb"><div class="panel">${kv([["Protected values remaining", '<span class="t-ok">0</span>'], ["Reconstruction verification", '<span class="t-ok">passed</span>'], ["Redactions", fmt(j.redactions)], ["Surfaces inspected", fmt(j.segments)]])}</div>
        <div class="panel">${kv([["Format", esc(j.kind || j.ext)], ["Size", bytes(j.size)], ["Processing", ms(j.ms)], ["Images", esc(images || "per policy")]])}</div></div>
        <div class="pf"><a class="btn pri" href="${j.url}" download="${esc(j.out)}">${icon("download", "sm")} Download redacted file</a><button class="btn" data-receipt="${esc(j.id)}">${icon("file-text", "sm")} Assurance receipt</button><span>The release is the verified file. Its raw values never left this gateway.</span></div>`}</section>`;
  };
  const run = async (file) => {
    const job = { id: String(Date.now()), name: file.name, size: file.size, ext: (file.name.split(".").pop() || "").toUpperCase().slice(0, 4), busy: true };
    jobs.unshift(job); ctx.jobSel = job.id; render();
    const t0 = performance.now();
    try {
      const res = await api("/v1/documents/redact", { method: "POST", body: file, raw: true, headers: { "x-harpo-filename": encodeURIComponent(file.name), "x-harpo-response": "file", "content-type": "application/octet-stream" } });
      job.ms = performance.now() - t0;
      if (!res.ok) { const e = await safeJson(res); job.error = { ...(e?.error || {}), code: e?.error?.harpo?.code || e?.error?.type, message: e?.error?.message }; }
      else {
        const blob = await res.blob(), cd = res.headers.get("content-disposition") || "", star = /filename\*=UTF-8''([^;]+)/i.exec(cd), plain = /filename="?([^";]+)"?/i.exec(cd);
        Object.assign(job, { url: URL.createObjectURL(blob), blob, out: star ? decodeURIComponent(star[1]) : plain ? plain[1] : `redacted-${file.name}`, redactions: +(res.headers.get("x-harpo-redactions") || 0),
          segments: +(res.headers.get("x-harpo-segments") || 0), kind: res.headers.get("x-harpo-document"), verified: res.headers.get("x-harpo-verified") === "true" });
      }
    } catch (err) { job.error = { code: err.type, message: err.message }; }
    job.busy = false;
    if (ctx.route === "documents") render();
  };
  render();
}

/** A content-free record of a document release: formats, sizes, counts, verification and the output's SHA-256. */
const RECEIPTS = { jobs: [], ctx: null };
document.addEventListener("click", async (e) => {
  const b = e.target.closest?.("[data-receipt]");
  if (!b) return;
  const j = RECEIPTS.jobs.find((x) => x.id === b.dataset.receipt);
  if (!j?.blob) return;
  let sha256;
  try { sha256 = [...new Uint8Array(await crypto.subtle.digest("SHA-256", await j.blob.arrayBuffer()))].map((x) => x.toString(16).padStart(2, "0")).join(""); }
  catch { sha256 = "unavailable: hashing needs a secure context (https or localhost)"; }
  const receipt = { kind: "harpo.document-receipt", schema: 1, gateway_version: RECEIPTS.ctx?.policy?.version || null, time: new Date().toISOString(),
    input: { format: j.kind || j.ext || null, bytes: j.size }, output: { format: (j.out || "").split(".").pop() || null, bytes: j.blob.size, sha256 },
    redactions: j.redactions ?? null, surfaces_inspected: j.segments ?? null, verification: "passed: the rebuilt file was re-opened and re-scanned before release",
    processing_ms: j.ms ?? null, content: "none: no document text, values or file names" };
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([JSON.stringify(receipt, null, 2)], { type: "application/json" })), download: `harpo-document-receipt-${j.id}.json` });
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});
