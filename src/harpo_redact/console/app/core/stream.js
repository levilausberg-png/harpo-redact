// The gateway's live event stream (GET /v1/events), read with fetch because EventSource cannot send the gateway key.
// Records are the same content-free metadata the console already shows; nothing is stored.
import { session } from "./api.js";

const subscribers = new Set(), watchers = new Set();
let state = "off", ctrl = null, retry = 1000;
const set = (s) => { state = s; for (const w of watchers) w(s); };

async function connect() {
  ctrl = new AbortController();
  set("connecting");
  try {
    const res = await fetch("/v1/events", { headers: session.key ? { authorization: `Bearer ${session.key}` } : {}, signal: ctrl.signal, cache: "no-store" });
    if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
    set("live"); retry = 1000;
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += value;
      for (let i = buf.indexOf("\n\n"); i >= 0; i = buf.indexOf("\n\n")) {
        const block = buf.slice(0, i); buf = buf.slice(i + 2);
        let type = "message", data = "";
        for (const line of block.split("\n")) { if (line.startsWith("event: ")) type = line.slice(7); else if (line.startsWith("data: ")) data += line.slice(6); }
        if (!data) continue;
        let payload; try { payload = JSON.parse(data); } catch { continue; }
        for (const fn of [...subscribers]) fn(type, payload);
      }
    }
    throw new Error("stream closed");
  } catch {
    if (ctrl?.signal.aborted) return;
    ctrl = null; set("reconnecting");
    setTimeout(() => { if (!ctrl) connect(); }, retry);
    retry = Math.min(retry * 2, 30000);
  }
}
export const stream = {
  get state() { return state; },
  start() { if (!ctrl) connect(); },
  /** Subscribe to (type, record); returns the unsubscribe function. */
  on(fn) { subscribers.add(fn); return () => subscribers.delete(fn); },
  watch(fn) { watchers.add(fn); fn(state); return () => watchers.delete(fn); },
};
