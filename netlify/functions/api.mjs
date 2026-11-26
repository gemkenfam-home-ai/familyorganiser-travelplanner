// Family Trip Portal - Netlify Function (the "server" part)
//
// Every /api/* request from the browser lands here. The Supabase address and
// key are read from Netlify environment variables, which are never sent to
// the browser. The sign-in session is kept in an encrypted, HttpOnly, Secure
// cookie that page JavaScript cannot read.

import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";

const env = (k) => (globalThis.Netlify?.env?.get?.(k) ?? process.env[k] ?? "").trim();
const SUPABASE_URL = env("SUPABASE_URL").replace(/\/+$/, "");
const ANON = env("SUPABASE_ANON_KEY");
const SECRET = env("SECRET_KEY");
const SECURE = env("SECURE_COOKIES").toLowerCase() !== "false";
// Stateless client used only for auth.verifyOtp; the session lives in our own cookie.
const supabase = createClient(SUPABASE_URL || "http://localhost", ANON || "missing", {
  auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
});
const BUCKET = "receipts";
const COOKIE = "ftp_session";
const MAX_AGE = 60 * 60 * 24 * 30;
const MAX_RECEIPT_BYTES = 4 * 1024 * 1024; // Netlify functions accept up to 6 MB per request

const ID_RE = /^[A-Za-z0-9_-]{1,60}$/;
const PATH_RE = /^[A-Za-z0-9_-]{1,60}\/[A-Za-z0-9_.-]{1,120}$/;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const TYPE_RE = /^(image\/[a-z0-9.+-]+|application\/pdf)$/;

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers } });

// ---------- encrypted session cookie ----------
const KEY = crypto.createHash("sha256").update(SECRET || "missing").digest();
const b64u = (b) => Buffer.from(b).toString("base64url");
function seal(obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), "utf8"), c.final()]);
  return b64u(Buffer.concat([iv, c.getAuthTag(), ct]));
}
function unseal(token) {
  try {
    const raw = Buffer.from(token, "base64url");
    const d = crypto.createDecipheriv("aes-256-gcm", KEY, raw.subarray(0, 12));
    d.setAuthTag(raw.subarray(12, 28));
    return JSON.parse(Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString("utf8"));
  } catch { return null; }
}
function readCookie(req) {
  const m = (req.headers.get("cookie") || "").match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  return m ? unseal(m[1]) : null;
}
const cookieHeader = (value, maxAge) =>
  `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${SECURE ? "; Secure" : ""}`;

// ---------- best-effort sign-in rate limit (per function instance) ----------
const hits = new Map();
function rateLimit(key, limit = 12, perMs = 600_000) {
  const now = Date.now(), list = (hits.get(key) || []).filter((t) => t > now - perMs);
  if (list.length >= limit) throw new ApiError(429, "Too many attempts - wait a few minutes and try again.");
  list.push(now); hits.set(key, list);
}

// ---------- Supabase calls ----------
async function supa(method, path, { token, body, headers = {}, raw } = {}) {
  const init = { method, headers: { apikey: ANON, Authorization: `Bearer ${token || ANON}`, ...headers } };
  if (body !== undefined) {
    if (raw) init.body = body;
    else { init.body = JSON.stringify(body); init.headers["Content-Type"] = "application/json"; }
  }
  try { return await fetch(SUPABASE_URL + path, { ...init, signal: AbortSignal.timeout(9000) }); }
  catch { throw new ApiError(502, "The database can't be reached right now - try again shortly."); }
}
async function check(r, fallback) {
  if (r.status === 401 || r.status === 403) throw new ApiError(403, "You don't have permission to do that.");
  if (r.status >= 400) { console.warn("Supabase", r.status, (await r.text()).slice(0, 300)); throw new ApiError(r.status < 500 ? 400 : 502, fallback); }
  return r;
}
const sessionFrom = (d) => ({
  at: d.access_token, rt: d.refresh_token,
  exp: Math.floor(Date.now() / 1000) + Number(d.expires_in || 3600),
  email: String(d.user?.email || "").toLowerCase(),
});
async function bodyJson(req) {
  try { const b = await req.json(); if (b && typeof b === "object" && !Array.isArray(b)) return b; } catch {}
  throw new ApiError(400, "Expected JSON.");
}

// ---------- routes ----------
async function route(req, ctx, st) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api/, "") || "/";
  const m = req.method;
  const write = m !== "GET" && m !== "HEAD";
  if (write && req.headers.get("x-portal") !== "1") throw new ApiError(403, "Blocked request."); // CSRF guard

  // --- sign-in (no session needed) ---
  if (path.startsWith("/auth/")) {
    if (path === "/auth/logout" && m === "POST") {
      if (st.sess) await supa("POST", "/auth/v1/logout", { token: st.sess.at }).catch(() => {});
      st.sess = null; st.changed = true;
      return json({ ok: true });
    }
    if (m !== "POST") throw new ApiError(404, "Not found.");
    rateLimit("auth:" + (ctx?.ip || "?"));
    const b = await bodyJson(req);
    const email = String(b.email || "").trim().toLowerCase();
    if (!EMAIL_RE.test(email)) throw new ApiError(400, "Enter a valid email address.");

    if (path === "/auth/code") {
      const r = await supa("POST", "/auth/v1/otp", { body: { email, create_user: true } });
      if (r.status === 429) throw new ApiError(429, "Too many emails sent - wait a while, or sign in with a password.");
      await check(r, "Couldn't send the code - try again.");
      return json({ ok: true });
    }
    if (path === "/auth/verify") {
      const code = String(b.code || "").replace(/\D/g, "");
      if (code.length < 6) throw new ApiError(400, "Enter the code from the email.");
      let res;
      try { res = await supabase.auth.verifyOtp({ email, token: code, type: "email" }); }
      catch { throw new ApiError(502, "The database can't be reached right now - try again shortly."); }
      const { data, error } = res;
      if (error || !data?.session) throw new ApiError(400, "That code is wrong or has expired - request a new one.");
      const s = data.session;
      st.sess = sessionFrom({ ...s, user: s.user || data.user }); st.changed = true;
      return json({ ok: true });
    }
    if (path === "/auth/password") {
      const pw = String(b.password || "");
      if (b.signup) {
        if (pw.length < 8) throw new ApiError(400, "Passwords need at least 8 characters.");
        const r = await check(await supa("POST", "/auth/v1/signup", { body: { email, password: pw } }),
          "Couldn't create the account - you may already have one; try signing in.");
        const d = await r.json();
        if (d.access_token) { st.sess = sessionFrom(d); st.changed = true; return json({ ok: true }); }
        return json({ ok: true, confirm: true });
      }
      const r = await supa("POST", "/auth/v1/token?grant_type=password", { body: { email, password: pw } });
      if (r.status !== 200) throw new ApiError(400, "That email and password don't match. Try the email code instead.");
      st.sess = sessionFrom(await r.json()); st.changed = true;
      return json({ ok: true });
    }
    throw new ApiError(404, "Not found.");
  }

  // --- everything else needs a signed-in person ---
  if (!st.sess) throw new ApiError(401, "Please sign in.");
  if (st.sess.exp - 60 < Date.now() / 1000) {
    const r = await supa("POST", "/auth/v1/token?grant_type=refresh_token", { body: { refresh_token: st.sess.rt } });
    if (r.status !== 200) { st.sess = null; st.changed = true; throw new ApiError(401, "Your sign-in has expired - please sign in again."); }
    st.sess = sessionFrom(await r.json()); st.changed = true;
  }
  const token = st.sess.at;
  let mm;

  if (path === "/me" && m === "GET") {
    const r = await check(await supa("GET", `/rest/v1/family?select=role,name&email=eq.${encodeURIComponent(st.sess.email)}`, { token }), "Couldn't check access.");
    const rows = await r.json();
    return json({ email: st.sess.email, role: rows[0]?.role || "none" });
  }

  if (path === "/trips" && m === "GET") {
    const r = await check(await supa("GET", "/rest/v1/trips?select=id,data,updated_at,updated_by", { token }), "Couldn't load trips.");
    return json(await r.json());
  }
  if ((mm = path.match(/^\/trips\/([^/]+)$/))) {
    const id = decodeURIComponent(mm[1]);
    if (!ID_RE.test(id)) throw new ApiError(400, "Bad trip id.");
    if (m === "PUT") {
      const text = await req.text();
      if (text.length > 900_000) throw new ApiError(413, "This trip is too large to save.");
      let data; try { data = JSON.parse(text); } catch { throw new ApiError(400, "Expected JSON."); }
      if (!data || typeof data !== "object" || Array.isArray(data)) throw new ApiError(400, "Expected JSON.");
      const r = await check(await supa("POST", "/rest/v1/trips", { token, body: { id, data },
        headers: { Prefer: "resolution=merge-duplicates,return=representation" } }), "Couldn't save the trip.");
      if (!(await r.json()).length) throw new ApiError(403, "You don't have permission to save this.");
      return json({ ok: true });
    }
    if (m === "DELETE") {
      const r = await check(await supa("DELETE", `/rest/v1/trips?id=eq.${encodeURIComponent(id)}`, { token,
        headers: { Prefer: "return=representation" } }), "Couldn't delete the trip.");
      const rows = await r.json();
      if (!rows.length) throw new ApiError(403, "Only admins can delete trips.");
      const paths = (rows[0].data?.expenses || []).map((e) => e.receipt?.id).filter((p) => p && PATH_RE.test(p));
      if (paths.length) await supa("DELETE", `/storage/v1/object/${BUCKET}`, { token, body: { prefixes: paths } });
      return json({ ok: true });
    }
  }

  if (path === "/family" && m === "GET") {
    const r = await check(await supa("GET", "/rest/v1/family?select=*&order=added_at", { token }), "Couldn't load the family list.");
    return json(await r.json());
  }
  if (path === "/family" && m === "POST") {
    const b = await bodyJson(req);
    const email = String(b.email || "").trim().toLowerCase();
    if (!EMAIL_RE.test(email)) throw new ApiError(400, "Enter a valid email address.");
    const role = b.role === "admin" ? "admin" : "member";
    const r = await check(await supa("POST", "/rest/v1/family", { token,
      body: { email, name: String(b.name || "").slice(0, 80), role },
      headers: { Prefer: "resolution=merge-duplicates,return=representation" } }), "Couldn't add - only admins can change the family list.");
    if (!(await r.json()).length) throw new ApiError(403, "Only admins can change the family list.");
    return json({ ok: true });
  }
  if ((mm = path.match(/^\/family\/(.+)$/)) && m === "DELETE") {
    const email = decodeURIComponent(mm[1]).trim().toLowerCase();
    if (email === st.sess.email) throw new ApiError(400, "You can't remove yourself.");
    const r = await check(await supa("DELETE", `/rest/v1/family?email=eq.${encodeURIComponent(email)}`, { token,
      headers: { Prefer: "return=representation" } }), "Couldn't remove.");
    if (!(await r.json()).length) throw new ApiError(403, "Only admins can change the family list.");
    return json({ ok: true });
  }

  if (path === "/receipts" && m === "POST") {
    const trip = url.searchParams.get("trip") || "";
    let form; try { form = await req.formData(); } catch { throw new ApiError(400, "Missing file."); }
    const f = form.get("file");
    if (!ID_RE.test(trip) || !f || typeof f === "string") throw new ApiError(400, "Missing file.");
    const type = String(f.type || "").toLowerCase();
    if (!TYPE_RE.test(type)) throw new ApiError(400, "Receipts must be a photo or a PDF.");
    if (f.size > MAX_RECEIPT_BYTES) throw new ApiError(413, "Receipts can be up to 4 MB.");
    const name = (String(f.name || "receipt").replace(/[^A-Za-z0-9_.-]+/g, "_").slice(-80)) || "receipt";
    const p = `${trip}/${crypto.randomBytes(5).toString("hex")}-${name}`;
    await check(await supa("POST", `/storage/v1/object/${BUCKET}/${p}`, { token, raw: true,
      body: Buffer.from(await f.arrayBuffer()), headers: { "Content-Type": type, "x-upsert": "false" } }), "Receipt upload failed.");
    return json({ id: p, contentType: type });
  }
  if (path === "/receipts" && m === "DELETE") {
    const p = String((await bodyJson(req)).path || "");
    if (!PATH_RE.test(p)) throw new ApiError(400, "Bad path.");
    await supa("DELETE", `/storage/v1/object/${BUCKET}`, { token, body: { prefixes: [p] } });
    return json({ ok: true });
  }
  if ((mm = path.match(/^\/receipts\/(.+)$/)) && m === "GET") {
    const p = mm[1].split("/").map(decodeURIComponent).join("/");
    if (!PATH_RE.test(p)) throw new ApiError(404, "Not found.");
    const r = await supa("GET", `/storage/v1/object/authenticated/${BUCKET}/${p}`, { token });
    if (r.status !== 200) throw new ApiError(404, "Not found.");
    let type = (r.headers.get("content-type") || "").split(";")[0].trim();
    if (!TYPE_RE.test(type)) type = "application/octet-stream";
    return new Response(r.body, { headers: { "Content-Type": type, "Content-Disposition": "inline", "Cache-Control": "private, max-age=600" } });
  }

  throw new ApiError(404, "Not found.");
}

export default async (req, context) => {
  if (!SUPABASE_URL || !ANON || !SECRET)
    return json({ error: "The portal isn't configured yet: set SUPABASE_URL, SUPABASE_ANON_KEY and SECRET_KEY in Netlify, then deploy again." }, 500);
  const st = { sess: readCookie(req), changed: false };
  let res;
  try { res = await route(req, context, st); }
  catch (err) {
    if (!(err instanceof ApiError)) console.error(err);
    res = json({ error: err instanceof ApiError ? err.message : "Something went wrong - please try again." }, err.status || 500);
  }
  if (st.changed) {
    const h = new Headers(res.headers);
    h.append("Set-Cookie", st.sess ? cookieHeader(seal(st.sess), MAX_AGE) : cookieHeader("", 0));
    res = new Response(res.body, { status: res.status, headers: h });
  }
  return res;
};

export const config = { path: "/api/*" };
