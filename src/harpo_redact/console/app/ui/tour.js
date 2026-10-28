// A five-step tour of the ideas that matter. Optional; Esc ends it; it never returns once finished or dismissed.
import { $, esc } from "../core/dom.js";
import { prefs } from "../core/prefs.js";

const STEPS = [
  ["overview", ".posture", "Protection posture", "The live state of every enforced boundary. It changes only when the gateway's real state does; traffic moves along the path as it happens."],
  ["playground", "[data-pane='egress']", "Exact egress", "Type anything on the left. This pane shows byte for byte what would leave, after the gateway's own final check."],
  ["documents", "#drop", "Documents", "Files are parsed in an isolated worker, rebuilt, re-opened and verified before release. Each release has a content-free receipt."],
  ["activity", ".pg-bar", "Activity and traces", "Every request as metadata only. Open one for its timing waterfall; click a chart point elsewhere to land here."],
  ["guarantees", ".suites, .inv", "Assurance", "Ten invariants with the tests that enforce them, and self-test suites you can run against this gateway now."],
];
const wait = async (sel) => { for (let i = 0; i < 40; i++) { const el = document.querySelector(sel); if (el?.getBoundingClientRect().height) return el; await new Promise((r) => setTimeout(r, 75)); } return null; };

export async function startTour(ctx) {
  document.getElementById("tour")?.remove();
  const root = Object.assign(document.createElement("div"), { id: "tour" });
  document.body.appendChild(root);
  let step = 0;
  const end = (done) => { root.remove(); document.removeEventListener("keydown", keys, true); prefs.set("tour", done ? "done" : "dismissed"); };
  const keys = (e) => {
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); end(false); }
    else if (e.key === "ArrowRight") { e.preventDefault(); next(1); }
    else if (e.key === "ArrowLeft") { e.preventDefault(); next(-1); }
  };
  document.addEventListener("keydown", keys, true);
  const show = async () => {
    const [route, sel, title, body] = STEPS[step];
    if (ctx.route !== route) ctx.go(route);
    const el = await wait(sel);
    if (!document.body.contains(root)) return;
    el?.scrollIntoView({ block: "center", behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
    await new Promise((r) => setTimeout(r, 260));
    const r = el ? el.getBoundingClientRect() : { left: innerWidth / 2 - 120, top: innerHeight / 2 - 60, width: 240, height: 120 };
    const pad = 8, card = 320;
    const below = r.top + r.height + 180 < innerHeight;
    const cx = Math.max(12, Math.min(r.left, innerWidth - card - 12));
    root.innerHTML = `<div class="tour-spot"></div><div class="tour-card glass" role="dialog" aria-modal="false" aria-labelledby="tour-t">
      <div class="eyebrow">TOUR · ${step + 1} OF ${STEPS.length}</div><h2 id="tour-t">${esc(title)}</h2><p>${esc(body)}</p>
      <div class="tour-nav"><button class="btn ghost" data-t="skip">Skip tour</button><span></span>${step ? '<button class="btn" data-t="back">Back</button>' : ""}<button class="btn pri" data-t="next">${step === STEPS.length - 1 ? "Finish" : "Next"}</button></div></div>`;
    const spot = root.querySelector(".tour-spot"), c = root.querySelector(".tour-card");
    Object.assign(spot.style, { left: `${r.left - pad}px`, top: `${r.top - pad}px`, width: `${r.width + pad * 2}px`, height: `${Math.min(r.height + pad * 2, innerHeight - 24)}px` });
    Object.assign(c.style, { left: `${cx}px`, top: below ? `${Math.min(r.top + Math.min(r.height, innerHeight * 0.6) + pad * 2, innerHeight - 200)}px` : `${Math.max(12, r.top - 196)}px` });
    root.onclick = (e) => { const t = e.target.closest("[data-t]")?.dataset.t; if (t === "skip") end(false); else if (t === "next") next(1); else if (t === "back") next(-1); };
    root.querySelector('[data-t="next"]').focus();
  };
  const next = (d) => { step += d; if (step >= STEPS.length) return end(true); step = Math.max(0, step); show(); };
  show();
}
