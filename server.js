const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");

// HOST defaults to loopback (secure). Set HOST=0.0.0.0 only when hosting
// publicly behind a protected network/firewall (e.g. on a cloud host).
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "127.0.0.1";
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, "public");

/* ------------------------------------------------------------------ */
/* Database                                                           */
/* ------------------------------------------------------------------ */
const db = new DatabaseSync(path.join(ROOT, "vault.db"));
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    pass_hash TEXT NOT NULL,
    pass_salt TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Migration: add lockout columns to pre-existing users tables.
try {
  db.exec(`ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0`);
} catch (e) { /* already exists */ }
try {
  db.exec(`ALTER TABLE users ADD COLUMN locked_until TEXT`);
} catch (e) { /* already exists */ }

/* ------------------------------------------------------------------ */
/* Helpers                                                           */
/* ------------------------------------------------------------------ */
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function makeSalt() {
  return crypto.randomBytes(16).toString("hex");
}

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days

/* Security: rate limiting (per IP) and account lockout            */
const RATE_LIMIT = {
  login: { windowMs: 60_000, max: 5 },
  register: { windowMs: 60_000, max: 3 },
  password: { windowMs: 60_000, max: 3 },
};
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MS = 10 * 60 * 1000; // 10 minutes

const rateBuckets = new Map(); // key -> { windowStart, count }

function rateLimitKey(action, req) {
  const fwd = req.headers["x-forwarded-for"];
  const ip = (fwd ? String(fwd).split(",")[0].trim() : req.socket.remoteAddress) || "unknown";
  return action + ":" + ip;
}

function isRateLimited(action, req) {
  const key = rateLimitKey(action, req);
  const cfg = RATE_LIMIT[action];
  const now = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.windowStart > cfg.windowMs) {
    rateBuckets.set(key, { windowStart: now, count: 1 });
    return false;
  }
  bucket.count += 1;
  if (bucket.count > cfg.max) {
    // shake off stale entries periodically
    if (rateBuckets.size > 5000) {
      for (const [k, b] of rateBuckets) {
        if (now - b.windowStart > cfg.windowMs) rateBuckets.delete(k);
      }
    }
    return true;
  }
  return false;
}

function isLocked(row) {
  if (!row.locked_until) return false;
  const lockTime = new Date(row.locked_until).getTime();
  return Date.now() < lockTime;
}

function lockUser(id) {
  db.prepare(
    "UPDATE users SET locked_until = ?, failed_attempts = 0 WHERE id = ?"
  ).run(new Date(Date.now() + LOCK_DURATION_MS).toISOString(), id);
}

function recordFailedAttempt(id) {
  db.prepare("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?").run(id);
  const row = db.prepare("SELECT failed_attempts FROM users WHERE id = ?").get(id);
  if (row && row.failed_attempts >= MAX_FAILED_ATTEMPTS) lockUser(id);
}

function resetFailedAttempts(id) {
  db.prepare(
    "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?"
  ).run(id);
}

function remainingLockTime(row) {
  const t = new Date(row.locked_until).getTime();
  return Math.max(0, Math.ceil((t - Date.now()) / 1000));
}

function readBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error("payload too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(new Error("invalid json"));
      }
    });
    req.on("error", reject);
  });
}

function send(res, status, data) {
  const body = JSON.stringify(data);
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
  };
  if (status === 429) headers["Retry-After"] = "60";
  res.writeHead(status, headers);
  res.end(body);
}

// Security headers for every response.
const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
};

function applySecurityHeaders(res) {
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
    res.setHeader(k, v);
  }
}

function hashString(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

/* Session helpers */
function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(
      part.slice(idx + 1).trim()
    );
  }
  return out;
}

function getSessionUser(req) {
  const token = parseCookies(req).vault_session;
  if (!token) return null;
  const row = db
    .prepare(
      `SELECT u.id, u.username FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token = ? AND s.expires_at > datetime('now')`
    )
    .get(token);
  return row || null;
}

function createSession(res, userId) {
  const token = makeToken();
  const expires = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  db.prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)")
    .run(token, userId, expires);
  res.setHeader(
    "Set-Cookie",
    `vault_session=${token}; HttpOnly; Path=/; Max-Age=${SESSION_TTL_MS / 1000}; SameSite=Lax`
  );
}

function clearSession(req, res) {
  const token = parseCookies(req).vault_session;
  if (token) db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
  res.setHeader(
    "Set-Cookie",
    "vault_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax"
  );
}

/* ------------------------------------------------------------------ */
/* Static file serving                                               */
/* ------------------------------------------------------------------ */
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

function serveStatic(req, res, urlPath) {
  let filePath;
  if (urlPath === "/") filePath = path.join(PUBLIC, "index.html");
  else filePath = path.normalize(path.join(PUBLIC, urlPath));

  if (!filePath.startsWith(PUBLIC)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    // graceful fallbacks
    if (urlPath === "/login") filePath = path.join(PUBLIC, "login.html");
    else if (urlPath === "/register")
      filePath = path.join(PUBLIC, "register.html");
    else if (urlPath.indexOf(".") === -1)
      filePath = path.join(PUBLIC, "index.html");
    else {
      res.writeHead(404);
      res.end("Not Found");
      return;
    }
  }

  const ext = path.extname(filePath).toLowerCase();
  const headers = {
    "Content-Type": MIME[ext] || "application/octet-stream",
    "Cache-Control": "no-cache",
  };
  applySecurityHeaders(res);
  res.writeHead(200, headers);
  fs.createReadStream(filePath).pipe(res);
}

/* ------------------------------------------------------------------ */
/* API routes                                                        */
/* ------------------------------------------------------------------ */
async function handleApi(req, res, urlPath) {
  const method = req.method;
  const clean = urlPath.replace(/\/+$/, ""); // strip trailing slash

  /* ---- AUTH ---- */
  if (method === "POST" && clean === "/api/register") {
    if (isRateLimited("register", req))
      return send(res, 429, { error: "Too many registration attempts. Wait a minute." });

    const body = await readBody(req);
    const username = String(body.username || "").trim();
    const password = String(body.password || "");

    if (username.length < 3 || username.length > 24)
      return send(res, 400, { error: "Username must be 3-24 characters." });
    if (!/^[a-zA-Z0-9_.-]+$/.test(username))
      return send(res, 400, { error: "Username may only contain letters, numbers, dots, dashes, underscores." });
    if (password.length < 6)
      return send(res, 400, { error: "Password must be at least 6 characters." });
    if (password.length > 128)
      return send(res, 400, { error: "Password must be 128 characters or fewer." });

    const exists = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
    if (exists) return send(res, 409, { error: "Username already taken." });

    const salt = makeSalt();
    const pass_hash = hashPassword(password, salt);
    const info = db
      .prepare("INSERT INTO users (username, pass_hash, pass_salt) VALUES (?, ?, ?)")
      .run(username, pass_hash, salt);
    createSession(res, Number(info.lastInsertRowid));
    return send(res, 201, { user: { username } });
  }

  if (method === "POST" && clean === "/api/login") {
    if (isRateLimited("login", req))
      return send(res, 429, { error: "Too many login attempts. Wait a minute." });

    const body = await readBody(req);
    const username = String(body.username || "").trim();
    const password = String(body.password || "");

    const row = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (!row)
      return send(res, 401, { error: "No account found with that username." });

    if (isLocked(row)) {
      return send(res, 423, {
        error: `Account temporarily locked. Try again in ${Math.ceil(remainingLockTime(row) / 60)} min.`,
      });
    }

    const hash = hashPassword(password, row.pass_salt);
    const ok = crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(row.pass_hash, "hex")
    );
    if (!ok) {
      recordFailedAttempt(Number(row.id));
      return send(res, 401, { error: "Incorrect password." });
    }

    resetFailedAttempts(Number(row.id));
    createSession(res, Number(row.id));
    return send(res, 200, { user: { username: row.username } });
  }

  if (method === "POST" && clean === "/api/password") {
    if (isRateLimited("password", req))
      return send(res, 429, { error: "Too many attempts. Wait a minute." });

    const user = getSessionUser(req);
    if (!user) return send(res, 401, { error: "Not logged in." });

    const body = await readBody(req);
    const current = String(body.current || "");
    const next = String(body.next || "");

    if (next.length < 6 || next.length > 128)
      return send(res, 400, { error: "New password must be 6-128 characters." });

    const row = db.prepare("SELECT * FROM users WHERE id = ?").get(user.id);
    const hash = hashPassword(current, row.pass_salt);
    const ok = crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(row.pass_hash, "hex")
    );
    if (!ok) return send(res, 401, { error: "Current password is incorrect." });

    const salt = makeSalt();
    const nextHash = hashPassword(next, salt);
    db.prepare("UPDATE users SET pass_hash = ?, pass_salt = ? WHERE id = ?")
      .run(nextHash, salt, user.id);

    // Invalidate all other sessions after a password change.
    const token = parseCookies(req).vault_session;
    db.prepare("DELETE FROM sessions WHERE user_id = ? AND token != ?").run(user.id, token);

    return send(res, 200, { ok: true });
  }

  if (method === "POST" && clean === "/api/logout") {
    clearSession(req, res);
    return send(res, 200, { ok: true });
  }

  if (method === "GET" && clean === "/api/me") {
    const user = getSessionUser(req);
    if (!user) return send(res, 401, { error: "Not logged in." });
    return send(res, 200, { user: { username: user.username } });
  }

  /* ---- NOTES (protected) ---- */
  const user = getSessionUser(req);
  if (!user) return send(res, 401, { error: "Not logged in." });

  const noteMatch = clean.match(/^\/api\/notes\/(\d+)$/);

  if (method === "GET" && clean === "/api/notes") {
    const rows = db
      .prepare(
        `SELECT id, title, content, created_at, updated_at
         FROM notes WHERE user_id = ? ORDER BY updated_at DESC, id DESC`
      )
      .all(user.id);
    return send(res, 200, { notes: rows });
  }

  if (method === "POST" && clean === "/api/notes") {
    const body = await readBody(req);
    const title = String(body.title || "").trim().slice(0, 120);
    const content = String(body.content || "").trim().slice(0, 20000);
    if (!title) return send(res, 400, { error: "Note title is required." });
    const info = db
      .prepare(
        `INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)`
      )
      .run(user.id, title, content);
    const row = db
      .prepare("SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ?")
      .get(Number(info.lastInsertRowid));
    return send(res, 201, { note: row });
  }

  if (method === "PATCH" && noteMatch) {
    const id = Number(noteMatch[1]);
    const body = await readBody(req);
    const own = db
      .prepare("SELECT id FROM notes WHERE id = ? AND user_id = ?")
      .get(id, user.id);
    if (!own) return send(res, 404, { error: "Note not found." });

    const title = body.title !== undefined ? String(body.title).trim().slice(0, 120) : undefined;
    const content = body.content !== undefined ? String(body.content).trim().slice(0, 20000) : undefined;

    if (title !== undefined || content !== undefined) {
      const t = title !== undefined ? title : db.prepare("SELECT title FROM notes WHERE id = ?").get(id).title;
      const c = content !== undefined ? content : db.prepare("SELECT content FROM notes WHERE id = ?").get(id).content;
      db.prepare(
        "UPDATE notes SET title = ?, content = ?, updated_at = datetime('now') WHERE id = ?"
      ).run(t, c, id);
    }
    const row = db
      .prepare("SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ?")
      .get(id);
    return send(res, 200, { note: row });
  }

  if (method === "DELETE" && noteMatch) {
    const id = Number(noteMatch[1]);
    const info = db
      .prepare("DELETE FROM notes WHERE id = ? AND user_id = ?")
      .run(id, user.id);
    if (info.changes === 0) return send(res, 404, { error: "Note not found." });
    return send(res, 200, { ok: true });
  }

  return send(res, 404, { error: "Not found." });
}

/* ------------------------------------------------------------------ */
/* Server                                                            */
/* ------------------------------------------------------------------ */
const server = http.createServer(async (req, res) => {
  applySecurityHeaders(res);
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const urlPath = url.pathname;

  try {
    if (urlPath.startsWith("/api")) {
      await handleApi(req, res, urlPath);
    } else {
      serveStatic(req, res, urlPath);
    }
  } catch (err) {
    send(res, 500, { error: err.message || "Server error." });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Vault running at http://localhost:${PORT}`);
});