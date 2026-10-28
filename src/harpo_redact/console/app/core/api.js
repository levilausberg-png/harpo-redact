// The gateway key lives in sessionStorage for this tab only: never localStorage, never a cookie.
export const session = { key: sessionStorage.getItem("pai.key") || "" };
export function setKey(key) { session.key = key; if (key) sessionStorage.setItem("pai.key", key); else sessionStorage.removeItem("pai.key"); }
let unauthorized = () => {};
export const onUnauthorized = (fn) => { unauthorized = fn; };

export class ApiError extends Error {
  constructor(status, type, message, data) { super(message || type || `HTTP ${status}`); Object.assign(this, { status, type, data }); }
}
export async function safeJson(res) { try { return await res.json(); } catch { return null; } }
export async function api(path, { method = "GET", body, headers = {}, raw = false, signal, quiet401 = false } = {}) {
  const h = { ...headers };
  if (session.key) h.authorization = `Bearer ${session.key}`;
  if (body !== undefined && !(body instanceof Blob)) { h["content-type"] = "application/json"; body = JSON.stringify(body); }
  const res = await fetch(path, { method, headers: h, body, cache: "no-store", credentials: "omit", signal });
  if (res.status === 401 && !quiet401) {
    const data = await safeJson(res);
    unauthorized(data?.error?.message);
    throw new ApiError(401, "authentication_error", data?.error?.message, data);
  }
  if (raw) return res;
  const data = await safeJson(res);
  if (!res.ok) throw new ApiError(res.status, data?.error?.type, data?.error?.message, data);
  return data;
}
