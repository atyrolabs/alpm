require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const axios = require("axios");
const https = require("https");
const http = require("http");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const { Server } = require("socket.io");
const readline = require("readline");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  },
  transports: ["websocket", "polling"]
});
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const DB_PATH = path.resolve(process.env.DB_PATH || "./data/atyro.sqlite");
const SESSION_SECRET = process.env.SESSION_SECRET;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error("SESSION_SECRET must be set and at least 32 characters long.");
  process.exit(1);
}
if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length < 32) {
  console.error("ENCRYPTION_KEY must be set and at least 32 characters long.");
  process.exit(1);
}

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin','user')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 8006,
  token_id TEXT NOT NULL,
  token_secret_enc TEXT NOT NULL,
  tls_verify INTEGER NOT NULL DEFAULT 1,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS servers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
  vmid INTEGER NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('qemu','lxc')),
  pve_node TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(node_id, vmid)
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  detail TEXT,
  ip TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
  sid TEXT PRIMARY KEY,
  sess TEXT NOT NULL,
  expire INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_servers_user ON servers(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
`);

const UPLOADS_DIR = path.resolve("./data/uploads");
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Lightweight schema migration for installations created before pve_node was added.
try { db.exec("ALTER TABLE servers ADD COLUMN pve_node TEXT NOT NULL DEFAULT ''"); } catch (e) { if (!String(e.message).includes("duplicate column name")) throw e; }

const encryptionKey = crypto.createHash("sha256").update(ENCRYPTION_KEY).digest();
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey, iv);
  const data = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  return [iv.toString("hex"), cipher.getAuthTag().toString("hex"), data.toString("hex")].join(":");
}
function decrypt(payload) {
  const [ivHex, tagHex, dataHex] = payload.split(":");
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey, Buffer.from(ivHex, "hex"));
  decipher.setAuthTag(Buffer.from(tagHex, "hex"));
  return Buffer.concat([decipher.update(Buffer.from(dataHex, "hex")), decipher.final()]).toString("utf8");
}

app.disable("x-powered-by");
app.set("trust proxy", Number(process.env.TRUST_PROXY || 0));
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:", "http:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: false, limit: "15mb" }));
app.use("/uploads", express.static(UPLOADS_DIR));

const sessionMiddleware = session({
  name: "atyro.sid",
  secret: SESSION_SECRET,
  store: new SQLiteStoreFactory({ db: "sessions.sqlite", dir: path.dirname(DB_PATH), table: "sessions" }),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.COOKIE_SECURE === "true",
    maxAge: 1000 * 60 * 60 * 8
  }
});
app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: "draft-7", legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 180, standardHeaders: "draft-7", legacyHeaders: false });
app.use("/api", apiLimiter);

function audit(userId, action, detail, req) {
  db.prepare("INSERT INTO audit_logs(user_id,action,detail,ip) VALUES(?,?,?,?)")
    .run(userId || null, action, detail ? String(detail).slice(0, 500) : null, req.ip);
}
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Authentication required." });
  const current = db.prepare("SELECT id,username,email,role,active FROM users WHERE id=?").get(req.session.user.id);
  if (!current || !current.active) {
    req.session.destroy(() => {});
    return res.status(401).json({ error: "Account unavailable." });
  }
  req.user = current;
  next();
}
function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Administrator permission required." });
  next();
}
function csrf(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const supplied = req.get("x-csrf-token");
  if (!req.session.csrf || !supplied || supplied.length !== req.session.csrf.length || !crypto.timingSafeEqual(Buffer.from(req.session.csrf), Buffer.from(supplied))) {
    return res.status(403).json({ error: "Invalid CSRF token. Refresh and try again." });
  }
  next();
}
app.use("/api", (req, res, next) => {
  if (req.path === "/auth/login" || req.path === "/health" || req.path === "/settings" || req.path.startsWith("/setup")) return next();
  return requireAuth(req, res, () => csrf(req, res, next));
});

function safeUser(row) {
  return { id: row.id, username: row.username, email: row.email, role: row.role, active: !!row.active, created_at: row.created_at };
}
function validateString(value, label, max = 100) {
  if (typeof value !== "string" || !value.trim() || value.length > max) {
    const e = new Error(`${label} is required and must be at most ${max} characters.`);
    e.status = 400;
    throw e;
  }
  return value.trim();
}
function buildIpConfig(ip4Type, rawIp4, rawGw4, ip6Type, rawIp6, rawGw6) {
  let ip4 = "";
  let gw4 = "";
  let cleanIp4Type = ip4Type === "static" ? "static" : "dhcp";

  if (rawIp4 && typeof rawIp4 === "string" && rawIp4.trim()) {
    let s4 = rawIp4.trim();
    if (!s4.includes(":")) {
      if (!s4.includes("/")) s4 += "/24";
      ip4 = s4;
      cleanIp4Type = "static";
      if (rawGw4 && typeof rawGw4 === "string" && rawGw4.trim()) {
        const g4 = rawGw4.trim().split("/")[0];
        if (!g4.includes(":")) gw4 = g4;
      }
    }
  }

  let ip6 = "";
  let gw6 = "";
  let cleanIp6Type = ["static", "dhcp", "auto", "disabled"].includes(ip6Type) ? ip6Type : "auto";

  if (cleanIp6Type === "static" && rawIp6 && typeof rawIp6 === "string" && rawIp6.trim()) {
    let s6 = rawIp6.trim();
    if (!s6.includes(":") && s6.includes(".")) {
      // User entered an IPv4 address into the IPv6 field! Rescue to IPv4 if empty
      if (!ip4) {
        if (!s6.includes("/")) s6 += "/24";
        ip4 = s6;
        cleanIp4Type = "static";
        if (rawGw6 && typeof rawGw6 === "string" && rawGw6.trim()) {
          const g = rawGw6.trim().split("/")[0];
          if (!g.includes(":")) gw4 = g;
        }
      }
      cleanIp6Type = "disabled";
    } else if (s6.includes(":")) {
      if (!s6.includes("/")) s6 += "/64";
      ip6 = s6;
      if (rawGw6 && typeof rawGw6 === "string" && rawGw6.trim()) {
        const g6 = rawGw6.trim().split("/")[0];
        if (g6.includes(":")) gw6 = g6;
      }
    } else {
      cleanIp6Type = "disabled";
    }
  } else if (cleanIp6Type === "dhcp") {
    ip6 = "dhcp";
  } else if (cleanIp6Type === "auto") {
    ip6 = "auto";
  }

  return { ip4, gw4, ip6, gw6, ip4Type: cleanIp4Type, ip6Type: cleanIp6Type };
}
function nodeClient(node) {
  const tokenSecret = decrypt(node.token_secret_enc);
  const baseURL = `https://${node.host}:${node.port}/api2/json`;
  return axios.create({
    baseURL,
    timeout: 15000,
    headers: { Authorization: `PVEAPIToken=${node.token_id}=${tokenSecret}`, Accept: "application/json" },
    httpsAgent: new https.Agent({ rejectUnauthorized: !!node.tls_verify })
  });
}
async function pve(node, method, endpoint, data) {
  try {
    const response = await nodeClient(node).request({ method, url: endpoint, data });
    return response.data && response.data.data !== undefined ? response.data.data : response.data;
  } catch (err) {
    const detail = err.response?.data?.errors || err.response?.data?.message || err.message;
    const e = new Error(`Proxmox API error: ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
    e.status = err.response?.status === 401 ? 502 : (err.response?.status || 502);
    throw e;
  }
}
function getNode(id) {
  const node = db.prepare("SELECT * FROM nodes WHERE id=? AND enabled=1").get(id);
  if (!node) {
    const e = new Error("Node not found or disabled.");
    e.status = 404;
    throw e;
  }
  return node;
}
function ownedServer(req, id) {
  const server = db.prepare(`
    SELECT s.*, n.name AS node_name, n.host, n.port, n.token_id, n.token_secret_enc, n.tls_verify, n.enabled
    FROM servers s JOIN nodes n ON n.id=s.node_id WHERE s.id=?
  `).get(id);
  if (!server || (req.user.role !== "admin" && server.user_id !== req.user.id)) {
    const e = new Error("Server not found.");
    e.status = 404;
    throw e;
  }
  if (!server.enabled) {
    const e = new Error("The assigned node is disabled.");
    e.status = 409;
    throw e;
  }
  return server;
}
function serverEndpoint(server, suffix = "") {
  const pveNode = server.pve_node && server.pve_node.trim() ? server.pve_node : server.node_name;
  return `/nodes/${encodeURIComponent(pveNode)}/${server.type}/${server.vmid}${suffix}`;
}

async function ensureServerPveNode(server, node) {
  if (server.pve_node && server.pve_node.trim() !== "" && server.pve_node !== server.node_name) {
    return server.pve_node;
  }
  try {
    const all = await pve(node, "GET", "/cluster/resources?type=vm");
    const found = Array.isArray(all) ? all.find(x => Number(x.vmid) === Number(server.vmid)) : null;
    if (found && found.node) {
      server.pve_node = found.node;
      db.prepare("UPDATE servers SET pve_node=? WHERE id=?").run(found.node, server.id);
      return found.node;
    }
  } catch {}

  try {
    const nodesList = await pve(node, "GET", "/nodes");
    if (Array.isArray(nodesList)) {
      for (const n of nodesList) {
        try {
          await pve(node, "GET", `/nodes/${encodeURIComponent(n.node)}/${server.type}/${server.vmid}/status/current`);
          server.pve_node = n.node;
          db.prepare("UPDATE servers SET pve_node=? WHERE id=?").run(n.node, server.id);
          return n.node;
        } catch {}
      }
    }
  } catch {}

  return server.pve_node || server.node_name;
}

const defaultSettings = {
  site_name: "Atyro Cloud",
  site_description: "Next-Generation Proxmox VE VPS Cloud Management Platform",
  site_icon: "",
  site_favicon: "",
  og_image: "",
  seo_description: "Atyro Cloud Proxmox VE Virtual Machine & Container Management Panel"
};

function getSettings() {
  try {
    const rows = db.prepare("SELECT key, value FROM settings").all();
    const res = { ...defaultSettings };
    for (const r of rows) {
      res[r.key] = r.value;
    }
    res.site_icon_url = res.site_icon || "";
    res.site_favicon_url = res.site_favicon || "";
    res.og_image_url = res.og_image || "";
    return res;
  } catch {
    const def = { ...defaultSettings };
    def.site_icon_url = def.site_icon || "";
    def.site_favicon_url = def.site_favicon || "";
    def.og_image_url = def.og_image || "";
    return def;
  }
}

function setSetting(key, value) {
  db.prepare(`
    INSERT INTO settings(key, value, updated_at)
    VALUES(?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP
  `).run(key, String(value || ""));
}

app.get("/api/settings", (req, res) => {
  res.json({ settings: getSettings() });
});

app.get("/api/health", (req, res) => res.json({ ok: true, name: "Atyro VPS Panel API" }));

function saveAdminAccount(username, email, passwordHash) {
  const existingUser1 = db.prepare("SELECT id FROM users WHERE id=1").get();
  if (existingUser1) {
    db.prepare("UPDATE users SET username=?, email=?, password_hash=?, role='admin', active=1 WHERE id=1")
      .run(username, email, passwordHash);
  } else {
    db.prepare("INSERT INTO users(id, username, email, password_hash, role, active) VALUES(1, ?, ?, ?, 'admin', 1)")
      .run(username, email, passwordHash);
  }
}

app.get("/api/setup/status", (req, res) => {
  const adminCount = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin'").get().count;
  res.json({ needSetup: adminCount === 0 });
});

app.post("/api/setup/admin", async (req, res) => {
  try {
    const adminCount = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin'").get().count;
    if (adminCount > 0) {
      return res.status(403).json({ error: "Administrator account already exists. Setup is locked." });
    }
    const username = validateString(req.body.username, "Username", 80);
    const email = validateString(req.body.email, "Email", 120);
    const password = validateString(req.body.password, "Password", 200);

    if (username.length < 3) return res.status(400).json({ error: "Username must be at least 3 characters." });
    if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." });
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ error: "Please enter a valid email address." });

    const hash = await bcrypt.hash(password, 12);
    saveAdminAccount(username, email, hash);

    console.log(`[SETUP] Initial administrator account created via Web Setup: ${username} (${email})`);
    res.json({ ok: true, message: "Administrator account created successfully! Please sign in." });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || "Failed to create administrator account." });
  }
});

app.post("/api/auth/login", loginLimiter, async (req, res, next) => {
  try {
    const username = validateString(req.body.username, "Username", 80);
    const password = validateString(req.body.password, "Password", 200);
    const row = db.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE").get(username, username);
    if (!row || !row.active || !(await bcrypt.compare(password, row.password_hash))) {
      audit(row?.id, "login_failed", "Invalid login", req);
      return res.status(401).json({ error: "Invalid username or password." });
    }
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.user = { id: row.id };
      req.session.csrf = crypto.randomBytes(32).toString("hex");
      audit(row.id, "login", "Successful login", req);
      res.json({ user: safeUser(row), csrfToken: req.session.csrf });
    });
  } catch (e) { next(e); }
});
app.get("/api/auth/me", requireAuth, (req, res) => {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString("hex");
  res.json({ user: req.user, csrfToken: req.session.csrf });
});
app.post("/api/auth/logout", requireAuth, csrf, (req, res) => {
  audit(req.user.id, "logout", "User logged out", req);
  req.session.destroy(() => res.clearCookie("atyro.sid").json({ ok: true }));
});

app.get("/api/dashboard", requireAuth, async (req, res, next) => {
  try {
    const rows = req.user.role === "admin"
      ? db.prepare("SELECT s.*,u.username,n.name AS node_name FROM servers s JOIN users u ON u.id=s.user_id JOIN nodes n ON n.id=s.node_id ORDER BY s.id DESC").all()
      : db.prepare("SELECT s.*,n.name AS node_name FROM servers s JOIN nodes n ON n.id=s.node_id WHERE s.user_id=? ORDER BY s.id DESC").all(req.user.id);
    const counts = { total: rows.length, qemu: rows.filter(x => x.type === "qemu").length, lxc: rows.filter(x => x.type === "lxc").length };

    // Fetch live status for each assigned server in parallel
    const nodeMap = new Map();
    await Promise.allSettled(rows.map(async (s) => {
      s.status = "unknown";
      s.uptime = 0;
      s.cpu = 0;
      s.mem = 0;
      s.maxmem = 0;
      try {
        let node = nodeMap.get(s.node_id);
        if (!node) {
          node = getNode(s.node_id);
          nodeMap.set(s.node_id, node);
        }
        await ensureServerPveNode(s, node);
        const st = await pve(node, "GET", serverEndpoint(s, "/status/current"));
        if (st && st.status) {
          s.status = st.status;
          s.uptime = st.uptime || 0;
          s.cpu = st.cpu || 0;
          s.mem = st.mem || 0;
          s.maxmem = st.maxmem || 0;
        }
      } catch (err) {
        s.status = "unknown";
      }
    }));

    res.json({ counts, servers: rows });
  } catch (e) { next(e); }
});

app.get("/api/servers/:id/status", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const node = getNode(s.node_id);
    await ensureServerPveNode(s, node);
    const status = await pve(node, "GET", serverEndpoint(s, "/status/current"));
    res.json({ status });
  } catch (e) { next(e); }
});
app.get("/api/servers/:id/config", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const node = getNode(s.node_id);
    await ensureServerPveNode(s, node);
    const config = await pve(node, "GET", serverEndpoint(s, "/config"));
    // Do not return cloud-init passwords or other sensitive config values.
    for (const key of Object.keys(config || {})) if (/pass|secret|token|sshkeys/i.test(key)) delete config[key];
    res.json({ config });
  } catch (e) { next(e); }
});
app.get("/api/servers/:id/rrd", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const node = getNode(s.node_id);
    await ensureServerPveNode(s, node);
    const timeframe = ["hour", "day", "week", "month", "year"].includes(req.query.timeframe) ? req.query.timeframe : "hour";
    const pveNode = s.pve_node || s.node_name;
    const rrd = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/${s.type}/${s.vmid}/rrddata?timeframe=${timeframe}`);
    res.json({ rrd: Array.isArray(rrd) ? rrd : [] });
  } catch (e) {
    res.json({ rrd: [] });
  }
});
app.post("/api/servers/:id/action", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const action = validateString(req.body.action, "Action", 30);
    const allowed = {
      start: ["POST", "/status/start"],
      stop: ["POST", "/status/stop"],
      shutdown: ["POST", "/status/shutdown"],
      reboot: ["POST", "/status/reboot"],
      reset: ["POST", "/status/reset"]
    };
    if (!allowed[action]) return res.status(400).json({ error: "Unsupported action." });
    const node = getNode(s.node_id);
    await ensureServerPveNode(s, node);
    const [method, suffix] = allowed[action];
    const task = await pve(node, method, serverEndpoint(s, suffix));
    audit(req.user.id, `server_${action}`, `${s.type}:${s.vmid}`, req);
    notifyVpsChanged(s.id, action);
    res.json({ ok: true, task });
  } catch (e) { next(e); }
});
app.post("/api/servers/:id/snapshots", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const name = validateString(req.body.name, "Snapshot name", 40).replace(/[^a-zA-Z0-9_-]/g, "-");
    const node = getNode(s.node_id);
    await ensureServerPveNode(s, node);
    const task = await pve(node, "POST", serverEndpoint(s, "/snapshot"), { snapname: name, description: "Created from Atyro Panel" });
    audit(req.user.id, "snapshot_create", `${s.type}:${s.vmid} ${name}`, req);
    notifyVpsChanged(s.id, "snapshot_create");
    res.json({ ok: true, task });
  } catch (e) { next(e); }
});
app.get("/api/servers/:id/snapshots", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const node = getNode(s.node_id);
    await ensureServerPveNode(s, node);
    const snapshots = await pve(node, "GET", serverEndpoint(s, "/snapshot"));
    res.json({ snapshots });
  } catch (e) { next(e); }
});
app.post("/api/servers/:id/snapshots/:name/rollback", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const name = validateString(req.params.name, "Snapshot name", 40);
    const node = getNode(s.node_id);
    await ensureServerPveNode(s, node);
    const task = await pve(node, "POST", serverEndpoint(s, `/snapshot/${encodeURIComponent(name)}/rollback`), {});
    audit(req.user.id, "snapshot_rollback", `${s.type}:${s.vmid} ${name}`, req);
    notifyVpsChanged(s.id, "rollback");
    res.json({ ok: true, task });
  } catch (e) { next(e); }
});

app.get("/api/servers/:id/clone/options", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const node = getNode(s.node_id);
    const pveNode = await ensureServerPveNode(s, node);

    let nextVmid = 100;
    try {
      const nid = await pve(node, "GET", "/cluster/nextid");
      if (nid) nextVmid = Number(nid);
    } catch {
      const maxRow = db.prepare("SELECT MAX(vmid) as max FROM servers WHERE node_id=?").get(node.id);
      nextVmid = (maxRow?.max || 100) + 1;
    }

    let storages = [];
    try {
      const stList = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage`);
      if (Array.isArray(stList)) {
        storages = stList.filter(x => x.active === 1).map(x => x.storage).filter(Boolean);
      }
    } catch {}
    if (!storages.length) storages = ["local-lvm", "nvme-storage", "local"];

    const users = db.prepare("SELECT id, username, email, role FROM users WHERE active=1 ORDER BY username ASC").all();

    res.json({
      server: s,
      nextVmid,
      storages,
      users,
      pveNode
    });
  } catch (e) { next(e); }
});

app.post("/api/servers/:id/clone", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const node = getNode(s.node_id);
    const pveNode = await ensureServerPveNode(s, node);

    const name = validateString(req.body.name, "Clone name", 80);
    const newVmid = Number(req.body.newVmid);
    if (!newVmid || newVmid < 100) {
      return res.status(400).json({ error: "Invalid new VMID (must be >= 100)." });
    }
    const fullClone = req.body.full !== false && req.body.full !== 0 && req.body.full !== "0";
    const targetUserId = req.body.userId ? Number(req.body.userId) : req.user.id;
    const targetStorage = req.body.storage ? String(req.body.storage).trim() : undefined;

    const dbExisting = db.prepare("SELECT id FROM servers WHERE node_id = ? AND vmid = ?").get(s.node_id, newVmid);
    if (dbExisting) {
      return res.status(409).json({ error: `VMID ${newVmid} is already registered in panel for this node.` });
    }

    let upid;
    if (s.type === "qemu") {
      const cloneParams = {
        newid: newVmid,
        name: name,
        full: fullClone ? 1 : 0
      };
      if (targetStorage) cloneParams.storage = targetStorage;
      upid = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu/${s.vmid}/clone`, cloneParams);
    } else {
      const cloneParams = {
        newid: newVmid,
        hostname: name,
        full: fullClone ? 1 : 0
      };
      if (targetStorage) cloneParams.storage = targetStorage;
      upid = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/lxc/${s.vmid}/clone`, cloneParams);
    }

    if (upid) {
      await waitForPveTask(node, pveNode, upid, 240);
    }

    const ins = db.prepare(
      "INSERT INTO servers (user_id, node_id, vmid, type, pve_node, name) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(targetUserId, s.node_id, newVmid, s.type, pveNode, name);

    audit(req.user.id, "server_clone", `Cloned ${s.type}:${s.vmid} to new ${s.type}:${newVmid} (${name})`, req);

    res.status(201).json({
      ok: true,
      id: ins.lastInsertRowid,
      vmid: newVmid,
      name,
      type: s.type,
      message: `Virtual server cloned successfully as "${name}" (VMID ${newVmid})!`
    });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) e.status = 409;
    next(e);
  }
});

app.get("/api/servers/:id/backups", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const node = getNode(s.node_id);
    const pveNode = await ensureServerPveNode(s, node);

    let storages = [];
    try {
      const stList = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage`);
      if (Array.isArray(stList)) {
        storages = stList.filter(st => {
          const content = st.content || "";
          return content.includes("backup") || st.type === "dir" || st.type === "nfs" || st.type === "pbs";
        });
        if (!storages.length) storages = stList.filter(st => st.active === 1);
      }
    } catch {}

    const backups = [];
    for (const st of storages) {
      try {
        const content = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage/${encodeURIComponent(st.storage)}/content?content=backup`);
        if (Array.isArray(content)) {
          for (const item of content) {
            const vmidMatches = item.vmid != null ? Number(item.vmid) === s.vmid : (item.volid && item.volid.includes(`-${s.vmid}-`));
            if (vmidMatches) {
              backups.push({
                volid: item.volid,
                storage: st.storage,
                format: item.format || item.volid.split(".").pop(),
                size: item.size || 0,
                ctime: item.ctime || 0,
                notes: item.notes || item.comment || "",
                vmid: s.vmid
              });
            }
          }
        }
      } catch {}
    }

    backups.sort((a, b) => (b.ctime || 0) - (a.ctime || 0));

    res.json({ backups, storages: storages.map(st => st.storage) });
  } catch (e) { next(e); }
});

app.post("/api/servers/:id/backups", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const node = getNode(s.node_id);
    const pveNode = await ensureServerPveNode(s, node);

    const mode = ["snapshot", "suspend", "stop"].includes(req.body.mode) ? req.body.mode : "snapshot";
    const compress = ["zstd", "gzip", "0"].includes(req.body.compress) ? req.body.compress : "zstd";
    const storage = req.body.storage ? String(req.body.storage).trim() : "local";

    const vzdumpParams = {
      vmid: s.vmid,
      mode: mode,
      compress: compress,
      storage: storage
    };

    const task = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/vzdump`, vzdumpParams);
    audit(req.user.id, "server_backup", `Backup started for ${s.type}:${s.vmid} on ${storage} (${mode}/${compress})`, req);
    res.json({ ok: true, task, message: `Backup task dispatched for ${s.name} (VMID ${s.vmid}).` });
  } catch (e) { next(e); }
});

app.delete("/api/servers/:id/backups", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const node = getNode(s.node_id);
    const pveNode = await ensureServerPveNode(s, node);

    const volid = String(req.body.volid || req.query.volid || "").trim();
    if (!volid) return res.status(400).json({ error: "Missing volid parameter." });

    const [storage] = volid.split(":");
    if (!storage) return res.status(400).json({ error: "Invalid volid format." });

    if (!volid.includes(`-${s.vmid}-`)) {
      return res.status(403).json({ error: "Backup volume does not belong to this server." });
    }

    await pve(node, "DELETE", `/nodes/${encodeURIComponent(pveNode)}/storage/${encodeURIComponent(storage)}/content/${encodeURIComponent(volid)}`);
    audit(req.user.id, "backup_delete", `Deleted backup ${volid} for ${s.type}:${s.vmid}`, req);
    res.json({ ok: true, message: "Backup volume deleted successfully." });
  } catch (e) { next(e); }
});

app.post("/api/servers/:id/backups/restore", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const node = getNode(s.node_id);
    const pveNode = await ensureServerPveNode(s, node);

    const volid = String(req.body.volid || "").trim();
    if (!volid) return res.status(400).json({ error: "Missing backup volid to restore." });

    if (!volid.includes(`-${s.vmid}-`)) {
      return res.status(403).json({ error: "Backup archive does not belong to this server." });
    }

    let upid;
    if (s.type === "qemu") {
      upid = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu`, {
        vmid: s.vmid,
        archive: volid,
        force: 1
      });
    } else {
      upid = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/lxc`, {
        vmid: s.vmid,
        ostemplate: volid,
        restore: 1,
        force: 1
      });
    }

    audit(req.user.id, "backup_restore", `Restored ${s.type}:${s.vmid} from ${volid}`, req);
    notifyVpsChanged(s.id, "restore");
    res.json({ ok: true, task: upid, message: `Restore task submitted for ${s.name} (VMID ${s.vmid}).` });
  } catch (e) { next(e); }
});

async function waitForPveTask(node, pveNode, upid, maxWaitSec = 90) {
  if (!upid || typeof upid !== "string" || !upid.startsWith("UPID:")) return;
  const encUpid = encodeURIComponent(upid);
  const start = Date.now();
  while ((Date.now() - start) < maxWaitSec * 1000) {
    await new Promise(r => setTimeout(r, 1500));
    try {
      const res = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/tasks/${encUpid}/status`);
      if (res && res.status === "stopped") {
        if (res.exitstatus && res.exitstatus !== "OK") {
          throw new Error(`Proxmox task failed: ${res.exitstatus}`);
        }
        return res;
      }
    } catch (err) {
      if (err.message && err.message.includes("Proxmox task failed")) throw err;
    }
  }
}

app.get("/api/servers/:id/reinstall/options", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const node = getNode(s.node_id);
    const pveNode = await ensureServerPveNode(s, node);

    let templates = [];
    let datastorePermissionRequired = false;

    try {
      const perms = await pve(node, "GET", "/access/permissions");
      const storagePerms = perms?.["/storage"] || perms?.["/"] || {};
      if (!storagePerms["Datastore.AllocateSpace"] && !storagePerms["Administrator"]) {
        datastorePermissionRequired = true;
      }
    } catch {}

    if (s.type === "qemu") {
      try {
        const allVms = await pve(node, "GET", "/cluster/resources?type=vm");
        if (Array.isArray(allVms)) {
          templates = allVms
            .filter(v => v.template === 1 && v.type === "qemu")
            .map(v => ({
              id: v.vmid,
              vmid: v.vmid,
              name: v.name || `Template ${v.vmid}`,
              type: "qemu",
              node: v.node || pveNode,
              disk: v.maxdisk || 0
            }));
        }
      } catch (err) {
        console.warn("Could not query cluster templates:", err.message);
      }
    } else if (s.type === "lxc") {
      try {
        const apl = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/aplinfo`);
        if (Array.isArray(apl)) {
          const popular = apl.filter(x => 
            /ubuntu|debian|alpine|almalinux|rocky|centos|archlinux/i.test(x.package) &&
            (x.architecture === "amd64" || !x.architecture)
          );
          templates = popular.map(x => ({
            id: x.template,
            package: x.package,
            name: x.headline || x.package,
            template: x.template,
            type: "lxc"
          }));
        }
      } catch (err) {
        console.warn("Could not query aplinfo:", err.message);
      }

      if (templates.length === 0) {
        templates = [
          { id: "ubuntu-24.04-standard_24.04-2_amd64.tar.zst", package: "ubuntu-24.04-standard", name: "Ubuntu 24.04 LTS (Standard)", type: "lxc" },
          { id: "ubuntu-22.04-standard_22.04-1_amd64.tar.zst", package: "ubuntu-22.04-standard", name: "Ubuntu 22.04 LTS (Standard)", type: "lxc" },
          { id: "debian-12-standard_12.7-1_amd64.tar.zst", package: "debian-12-standard", name: "Debian 12 Bookworm (Standard)", type: "lxc" },
          { id: "almalinux-9-default_20240911_amd64.tar.xz", package: "almalinux-9-default", name: "AlmaLinux 9 (Default)", type: "lxc" },
          { id: "alpine-3.24-default_20261105_amd64.tar.xz", package: "alpine-3.24-default", name: "Alpine Linux 3.24 (Default)", type: "lxc" }
        ];
      }
    }

    res.json({
      ok: true,
      server: {
        id: s.id,
        vmid: s.vmid,
        name: s.name,
        type: s.type,
        node_name: s.node_name,
        pve_node: pveNode
      },
      templates,
      datastorePermissionRequired
    });
  } catch (e) { next(e); }
});

app.post("/api/servers/:id/reinstall", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const password = validateString(req.body.password, "Root password", 128);
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters long." });
    }
    const sshKey = typeof req.body.sshKey === "string" ? req.body.sshKey.trim() : "";
    const hostname = typeof req.body.hostname === "string" && req.body.hostname.trim()
      ? req.body.hostname.trim().replace(/[^a-zA-Z0-9.-]/g, "")
      : s.name.replace(/[^a-zA-Z0-9.-]/g, "");

    const node = getNode(s.node_id);
    const pveNode = await ensureServerPveNode(s, node);

    // 1. Capture current config
    let currentConfig = {};
    try {
      currentConfig = await pve(node, "GET", serverEndpoint(s, "/config")) || {};
    } catch (err) {
      console.warn("Could not read current config before reinstall:", err.message);
    }

    // 2. Stop VPS if running
    try {
      const statusRes = await pve(node, "GET", serverEndpoint(s, "/status/current"));
      if (statusRes && statusRes.status === "running") {
        const stopTask = await pve(node, "POST", serverEndpoint(s, "/status/stop"));
        await waitForPveTask(node, pveNode, stopTask, 35);
      }
    } catch (err) {
      console.warn("Stop before reinstall notice:", err.message);
    }

    if (s.type === "qemu") {
      const templateId = Number(req.body.templateId);
      if (!Number.isInteger(templateId) || templateId < 100) {
        return res.status(400).json({ error: "Please select a valid QEMU template." });
      }

      // Preserve hardware specifications
      const cores = Number(currentConfig.cores || 1);
      const sockets = Number(currentConfig.sockets || 1);
      const memory = Number(currentConfig.memory || 1024);
      const net0 = currentConfig.net0 || "virtio,bridge=vmbr0";

      // Detect storage pool and primary disk size
      let targetStorage = "local-lvm";
      let diskKey = "scsi0";
      for (const k of ["scsi0", "sata0", "virtio0", "ide0"]) {
        if (currentConfig[k]) {
          diskKey = k;
          const match = String(currentConfig[k]).match(/^([^:,]+):/);
          if (match) targetStorage = match[1];
          break;
        }
      }

      let originalDiskSize = null;
      if (currentConfig[diskKey]) {
        const sizeMatch = String(currentConfig[diskKey]).match(/size=([0-9]+[GMKT]?)/i);
        if (sizeMatch) originalDiskSize = sizeMatch[1];
      }

      // Delete existing VM
      try {
        const delTask = await pve(node, "DELETE", `/nodes/${encodeURIComponent(pveNode)}/qemu/${s.vmid}?purge=1`);
        await waitForPveTask(node, pveNode, delTask, 45);
      } catch (err) {
        if (String(err.message).includes("AllocateSpace")) {
          return res.status(403).json({
            error: "Proxmox permission required: Datastore.AllocateSpace. Please add role 'PVEDatastoreUser' or 'Administrator' to API token in Proxmox VE (Datacenter -> Permissions)."
          });
        }
        throw new Error(`Failed to remove previous VM: ${err.message}`);
      }

      // Clone template to the same VMID
      try {
        const cloneTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu/${templateId}/clone`, {
          newid: s.vmid,
          name: hostname || s.name,
          full: 1,
          storage: targetStorage
        });
        await waitForPveTask(node, pveNode, cloneTask, 120);
      } catch (err) {
        if (String(err.message).includes("AllocateSpace")) {
          return res.status(403).json({
            error: "Proxmox permission required: Datastore.AllocateSpace. Please add role 'PVEDatastoreUser' or 'Administrator' to API token in Proxmox VE (Datacenter -> Permissions)."
          });
        }
        throw new Error(`Failed to clone template: ${err.message}`);
      }

      // Restore hardware resources and set cloud-init root credentials
      const configUpdate = {
        cores,
        sockets,
        memory,
        net0,
        ciuser: "root",
        cipassword: password
      };
      if (sshKey) configUpdate.sshkeys = encodeURIComponent(sshKey);
      await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu/${s.vmid}/config`, configUpdate);

      // Resize disk to original provisioned size if needed
      if (originalDiskSize) {
        try {
          const newCfg = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/qemu/${s.vmid}/config`);
          let newDiskKey = "scsi0";
          const candidateKeys = [];
          for (let i = 0; i < 16; i++) {
            candidateKeys.push(`scsi${i}`, `virtio${i}`, `sata${i}`, `ide${i}`);
          }
          for (const k of candidateKeys) {
            const dStr = newCfg[k] || "";
            if (dStr && typeof dStr === "string" && !dStr.includes("media=cdrom") && !dStr.includes("cloudinit") && !dStr.includes("none")) {
              newDiskKey = k;
              break;
            }
          }
          const resizeRes = await pve(node, "PUT", `/nodes/${encodeURIComponent(pveNode)}/qemu/${s.vmid}/resize`, {
            disk: newDiskKey,
            size: originalDiskSize
          });
          if (typeof resizeRes === "string" && resizeRes.startsWith("UPID")) {
            await waitForPveTask(node, pveNode, resizeRes, 60);
          }
        } catch (resizeErr) {
          console.warn("Disk resize notice on reinstall:", resizeErr.message);
        }
      }

      // Start the newly reinstalled VM
      try {
        await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu/${s.vmid}/status/start`);
      } catch (startErr) {
        console.warn("Start VM notice:", startErr.message);
      }

    } else if (s.type === "lxc") {
      const templateVolid = validateString(req.body.templateId, "LXC Template", 200);

      const cores = Number(currentConfig.cores || 1);
      const memory = Number(currentConfig.memory || 512);
      const swap = Number(currentConfig.swap || 512);
      const net0 = currentConfig.net0 || "name=eth0,bridge=vmbr0,ip=dhcp";

      let targetStorage = "local-lvm";
      let rootfsSize = "8";
      if (currentConfig.rootfs) {
        const match = String(currentConfig.rootfs).match(/^([^:,]+):/);
        if (match) targetStorage = match[1];
        const sizeMatch = String(currentConfig.rootfs).match(/size=([0-9]+[GMKT]?)/i);
        if (sizeMatch) rootfsSize = sizeMatch[1].replace(/G$/i, "");
      }

      // Delete existing container
      try {
        const delTask = await pve(node, "DELETE", `/nodes/${encodeURIComponent(pveNode)}/lxc/${s.vmid}?purge=1`);
        await waitForPveTask(node, pveNode, delTask, 45);
      } catch (err) {
        if (String(err.message).includes("AllocateSpace")) {
          return res.status(403).json({
            error: "Proxmox permission required: Datastore.AllocateSpace. Please add role 'PVEDatastoreUser' or 'Administrator' to API token in Proxmox VE (Datacenter -> Permissions)."
          });
        }
        throw new Error(`Failed to remove previous container: ${err.message}`);
      }

      // Create fresh container
      const createParams = {
        vmid: s.vmid,
        ostemplate: templateVolid,
        hostname: hostname || s.name,
        cores,
        memory,
        swap,
        net0,
        rootfs: `${targetStorage}:${rootfsSize}`,
        password,
        unprivileged: 1
      };
      if (sshKey) createParams["ssh-public-keys"] = sshKey;

      try {
        const createTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/lxc`, createParams);
        await waitForPveTask(node, pveNode, createTask, 120);
      } catch (err) {
        if (String(err.message).includes("AllocateSpace")) {
          return res.status(403).json({
            error: "Proxmox permission required: Datastore.AllocateSpace. Please add role 'PVEDatastoreUser' or 'Administrator' to API token in Proxmox VE (Datacenter -> Permissions)."
          });
        }
        throw new Error(`Failed to create fresh container: ${err.message}`);
      }

      // Start the fresh container
      try {
        await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/lxc/${s.vmid}/status/start`);
      } catch (startErr) {
        console.warn("Start container notice:", startErr.message);
      }
    }

    audit(req.user.id, "server_reinstall", `${s.type}:${s.vmid} (${s.name})`, req);
    res.json({
      ok: true,
      message: `VPS "${s.name}" (VMID ${s.vmid}) reinstalled successfully! The system is now booting with the fresh operating system.`
    });
  } catch (e) {
    next(e);
  }
});

app.get("/api/servers/:id/edit/options", requireAuth, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const row = db.prepare(`
      SELECT s.*, n.name as node_name, n.host, n.port, u.username, u.email
      FROM servers s
      JOIN nodes n ON s.node_id = n.id
      JOIN users u ON s.user_id = u.id
      WHERE s.id = ?
    `).get(id);

    if (!row) return res.status(404).json({ error: "Virtual server not found." });
    if (req.user.role !== "admin" && row.user_id !== req.user.id) {
      return res.status(403).json({ error: "Access denied." });
    }

    const node = getNode(row.node_id);
    let pveNode = row.pve_node;
    if (!pveNode) {
      try {
        const nodesList = await pve(node, "GET", "/nodes");
        if (Array.isArray(nodesList)) pveNode = nodesList[0]?.node || "";
      } catch {}
      if (!pveNode) pveNode = node.name.toLowerCase().replace(/[^a-z0-9_-]/g, "");
    }

    // 1. Live Proxmox config
    let config = {};
    try {
      config = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/${row.type}/${row.vmid}/config`);
    } catch {
      config = {};
    }

    // 2. Live Proxmox status
    let status = {};
    try {
      status = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/${row.type}/${row.vmid}/status/current`);
    } catch {
      status = {};
    }

    // 3. Network bridges on node
    let bridges = [];
    try {
      const net = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/network`);
      if (Array.isArray(net)) {
        bridges = net.filter(x => x.type === "bridge" || String(x.iface).startsWith("vmbr")).map(x => x.iface);
      }
    } catch {}
    if (!bridges.length) bridges = ["vmbr0", "vmbr1"];

    // 4. Panel users (for admin re-assignment)
    let users = [];
    if (req.user.role === "admin") {
      users = db.prepare("SELECT id, username, email, role FROM users WHERE active=1 ORDER BY username ASC").all();
    }

    // 5. Detect primary disk and current disk size in GB
    let diskKey = row.type === "lxc" ? "rootfs" : "scsi0";
    let currentDiskGb = 0;
    if (row.type === "lxc") {
      const rootfsStr = config.rootfs || "";
      const m = rootfsStr.match(/size=([0-9.]+)([GMKT])/i);
      if (m) {
        const num = parseFloat(m[1]);
        const unit = m[2].toUpperCase();
        currentDiskGb = unit === "M" ? Math.round(num / 1024) : (unit === "T" ? num * 1024 : num);
      }
    } else {
      const candidateKeys = [];
      for (let i = 0; i < 16; i++) {
        candidateKeys.push(`scsi${i}`, `virtio${i}`, `sata${i}`, `ide${i}`);
      }
      for (const k of candidateKeys) {
        const dStr = config[k] || "";
        if (dStr && typeof dStr === "string" && !dStr.includes("media=cdrom") && !dStr.includes("cloudinit") && !dStr.includes("none")) {
          diskKey = k;
          const m = dStr.match(/size=([0-9.]+)([GMKT])/i);
          if (m) {
            const num = parseFloat(m[1]);
            const unit = m[2].toUpperCase();
            currentDiskGb = unit === "M" ? Math.round(num / 1024) : (unit === "T" ? num * 1024 : num);
          }
          break;
        }
      }
    }
    if (!currentDiskGb && status.maxdisk) {
      currentDiskGb = Math.round(status.maxdisk / (1024 * 1024 * 1024));
    }

    res.json({
      server: row,
      config,
      status,
      bridges,
      users,
      diskKey,
      currentDiskGb
    });
  } catch (e) {
    next(e);
  }
});

app.post("/api/servers/:id/edit", requireAuth, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const row = db.prepare(`
      SELECT s.*, n.name as node_name, n.host, n.port, u.username
      FROM servers s
      JOIN nodes n ON s.node_id = n.id
      JOIN users u ON s.user_id = u.id
      WHERE s.id = ?
    `).get(id);

    if (!row) return res.status(404).json({ error: "Virtual server not found." });
    if (req.user.role !== "admin" && row.user_id !== req.user.id) {
      return res.status(403).json({ error: "Access denied." });
    }

    const node = getNode(row.node_id);
    let pveNode = row.pve_node;
    if (!pveNode) {
      try {
        const nodesList = await pve(node, "GET", "/nodes");
        if (Array.isArray(nodesList)) pveNode = nodesList[0]?.node || "";
      } catch {}
      if (!pveNode) pveNode = node.name.toLowerCase().replace(/[^a-z0-9_-]/g, "");
    }

    const newName = req.body.name ? validateString(req.body.name, "Server name", 80) : row.name;
    const newUserId = (req.user.role === "admin" && req.body.userId) ? Number(req.body.userId) : row.user_id;

    // 1. Update Database record if name or user changed
    if (newName !== row.name || newUserId !== row.user_id) {
      db.prepare("UPDATE servers SET name=?, user_id=? WHERE id=?").run(newName, newUserId, id);
    }

    // 2. Prepare Proxmox config changes
    const configUpdate = {};

    // Name / Hostname in Proxmox
    if (row.type === "lxc") {
      configUpdate.hostname = newName;
    } else {
      configUpdate.name = newName;
    }

    const isAdmin = req.user.role === "admin";

    // CPU & Memory (admin only)
    if (isAdmin) {
      if (req.body.cores) {
        configUpdate.cores = Math.max(1, Math.min(128, Number(req.body.cores)));
      }
      if (row.type === "qemu" && req.body.sockets) {
        configUpdate.sockets = Math.max(1, Math.min(8, Number(req.body.sockets)));
      }
      if (req.body.memory) {
        configUpdate.memory = Math.max(256, Math.min(524288, Number(req.body.memory)));
      }
      if (row.type === "lxc" && req.body.swap != null) {
        configUpdate.swap = Math.max(0, Math.min(65536, Number(req.body.swap)));
      }
    }

    // Network & IP Settings (bridge/vlan restricted to admin)
    const bridge = (isAdmin && req.body.bridge) ? validateString(req.body.bridge, "Bridge", 30) : null;
    const vlan = (isAdmin && req.body.vlan) ? Number(req.body.vlan) : null;
    const mac = (isAdmin && req.body.mac) ? req.body.mac.trim() : null;
    const firewall = (isAdmin && req.body.firewall != null) ? (req.body.firewall === true || req.body.firewall === "true" || req.body.firewall === 1 || req.body.firewall === "on") : null;
    const net = buildIpConfig(req.body.ip4Type, req.body.ip4Address, req.body.ip4Gateway, req.body.ip6Type, req.body.ip6Address, req.body.ip6Gateway);

    if (bridge) {
      if (row.type === "lxc") {
        let net0Str = `name=eth0,bridge=${bridge}`;
        if (vlan) net0Str += `,tag=${vlan}`;
        if (mac) net0Str += `,hwaddr=${mac}`;
        if (firewall) net0Str += `,firewall=1`;
        if (net.ip4Type === "static" && net.ip4) {
          net0Str += `,ip=${net.ip4}`;
          if (net.gw4) net0Str += `,gw=${net.gw4}`;
        } else {
          net0Str += ",ip=dhcp";
        }
        if (net.ip6Type === "static" && net.ip6) {
          net0Str += `,ip6=${net.ip6}`;
          if (net.gw6) net0Str += `,gw6=${net.gw6}`;
        } else if (net.ip6Type === "dhcp") {
          net0Str += ",ip6=dhcp";
        } else if (net.ip6Type === "auto") {
          net0Str += ",ip6=auto";
        }
        configUpdate.net0 = net0Str;
      } else {
        // QEMU
        let net0Str = `virtio,bridge=${bridge}`;
        if (vlan) net0Str += `,tag=${vlan}`;
        if (mac) net0Str += `,macaddr=${mac}`;
        if (firewall) net0Str += `,firewall=1`;
        configUpdate.net0 = net0Str;

        let ipconfig0Str = "";
        if (net.ip4Type === "static" && net.ip4) {
          ipconfig0Str = `ip=${net.ip4}`;
          if (net.gw4) ipconfig0Str += `,gw=${net.gw4}`;
        } else {
          ipconfig0Str = "ip=dhcp";
        }
        if (net.ip6Type === "static" && net.ip6) {
          ipconfig0Str += `,ip6=${net.ip6}`;
          if (net.gw6) ipconfig0Str += `,gw6=${net.gw6}`;
        } else if (net.ip6Type === "dhcp") {
          ipconfig0Str += ",ip6=dhcp";
        } else if (net.ip6Type === "auto") {
          ipconfig0Str += ",ip6=auto";
        }
        configUpdate.ipconfig0 = ipconfig0Str;
      }
    }

    // DNS Settings
    if (req.body.searchDomain != null) {
      configUpdate.searchdomain = req.body.searchDomain.trim();
    }
    if (req.body.nameServers != null) {
      configUpdate.nameserver = req.body.nameServers.trim();
    }

    // Credentials & Keys
    if (req.body.password && req.body.password.trim().length >= 8) {
      if (row.type === "qemu") {
        configUpdate.cipassword = req.body.password.trim();
      }
    }
    if (req.body.sshKey != null) {
      const k = req.body.sshKey.trim();
      if (row.type === "qemu") {
        configUpdate.sshkeys = k ? encodeURIComponent(k) : "";
      }
    }
    if (row.type === "qemu" && req.body.ciUser) {
      configUpdate.ciuser = req.body.ciUser.trim();
    }

    // Features / Options
    if (row.type === "lxc" && req.body.nesting != null) {
      const nestingOn = req.body.nesting === true || req.body.nesting === "true" || req.body.nesting === "on";
      configUpdate.features = nestingOn ? "nesting=1" : "";
    }
    if (row.type === "qemu" && req.body.qemuAgent != null) {
      const agentOn = req.body.qemuAgent === true || req.body.qemuAgent === "true" || req.body.qemuAgent === "on";
      configUpdate.agent = agentOn ? 1 : 0;
    }

    // Boot & Autostart options
    if (req.body.onboot != null) {
      configUpdate.onboot = (req.body.onboot === true || req.body.onboot === "true" || req.body.onboot === 1 || req.body.onboot === "1" || req.body.onboot === "on") ? 1 : 0;
    }
    if (req.body.startup != null && String(req.body.startup).trim()) {
      configUpdate.startup = String(req.body.startup).trim();
    }
    if (row.type === "qemu" && req.body.boot != null && String(req.body.boot).trim()) {
      configUpdate.boot = String(req.body.boot).trim();
    }

    // Apply config update to Proxmox (LXC requires PUT, QEMU accepts POST or PUT)
    if (Object.keys(configUpdate).length > 0) {
      const configMethod = row.type === "lxc" ? "PUT" : "POST";
      await pve(node, configMethod, `/nodes/${encodeURIComponent(pveNode)}/${row.type}/${row.vmid}/config`, configUpdate);
    }

    // 3. Disk Expansion (admin only)
    let diskMessage = "";
    if (isAdmin) {
      const addDiskGb = Number(req.body.addDiskGb || 0);
      const newTotalDiskGb = Number(req.body.newTotalDiskGb || req.body.totalDiskGb || 0);
      const currentDiskGb = Number(req.body.currentDiskGb || 0);

      let resizeSizeStr = "";
      if (addDiskGb > 0) {
        resizeSizeStr = `+${addDiskGb}G`;
      } else if (newTotalDiskGb > 0) {
        if (currentDiskGb > 0 && newTotalDiskGb <= currentDiskGb) {
          return res.status(400).json({
            error: `New disk size (${newTotalDiskGb} GB) must be greater than current size (${currentDiskGb} GB). Proxmox does not support shrinking virtual disks.`
          });
        }
        resizeSizeStr = `${newTotalDiskGb}G`;
      }

      if (resizeSizeStr) {
        try {
          let targetDiskKey = row.type === "lxc" ? "rootfs" : (req.body.diskKey || "scsi0");
          if (row.type === "qemu") {
            const cfg = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/qemu/${row.vmid}/config`);
            const candidateKeys = [];
            for (let i = 0; i < 16; i++) {
              candidateKeys.push(`scsi${i}`, `virtio${i}`, `sata${i}`, `ide${i}`);
            }
            for (const k of candidateKeys) {
              const dStr = cfg[k] || "";
              if (dStr && typeof dStr === "string" && !dStr.includes("media=cdrom") && !dStr.includes("cloudinit") && !dStr.includes("none")) {
                targetDiskKey = k;
                break;
              }
            }
          }
          const resizeRes = await pve(node, "PUT", `/nodes/${encodeURIComponent(pveNode)}/${row.type}/${row.vmid}/resize`, {
            disk: targetDiskKey,
            size: resizeSizeStr
          });
          if (typeof resizeRes === "string" && resizeRes.startsWith("UPID")) {
            await waitForPveTask(node, pveNode, resizeRes, 60);
          }
          diskMessage = ` Disk expanded by ${resizeSizeStr}.`;
        } catch (err) {
          console.error("Disk resize error on edit:", err.message);
          throw new Error(`Failed to expand disk in Proxmox: ${err.message}`);
        }
      }
    }

    audit(req.user.id, "server_edit", `${row.type}:${row.vmid} (${newName}) configuration edited`, req);

    res.json({
      ok: true,
      name: newName,
      message: `VPS configuration updated successfully!${diskMessage}`
    });
  } catch (e) {
    next(e);
  }
});

app.get("/api/admin/settings", requireAuth, requireAdmin, (req, res) => {
  res.json({ settings: getSettings() });
});

app.patch("/api/admin/settings", requireAuth, requireAdmin, (req, res) => {
  const { site_name, site_description, seo_description } = req.body;
  const site_icon = req.body.site_icon !== undefined ? req.body.site_icon : req.body.site_icon_url;
  const site_favicon = req.body.site_favicon !== undefined ? req.body.site_favicon : req.body.site_favicon_url;
  const og_image = req.body.og_image !== undefined ? req.body.og_image : req.body.og_image_url;

  if (site_name !== undefined) setSetting("site_name", String(site_name).trim().slice(0, 100));
  if (site_description !== undefined) setSetting("site_description", String(site_description).trim().slice(0, 500));
  if (site_icon !== undefined) setSetting("site_icon", String(site_icon).trim().slice(0, 2000));
  if (site_favicon !== undefined) setSetting("site_favicon", String(site_favicon).trim().slice(0, 2000));
  if (og_image !== undefined) setSetting("og_image", String(og_image).trim().slice(0, 2000));
  if (seo_description !== undefined) setSetting("seo_description", String(seo_description).trim().slice(0, 1000));

  audit(req.user.id, "settings_update", "Updated site branding & SEO settings", req);
  const updated = getSettings();
  if (io) io.emit("settings:updated", { settings: updated });
  res.json({ ok: true, settings: updated, message: "Settings saved successfully." });
});

app.post("/api/admin/settings/upload", requireAuth, requireAdmin, (req, res) => {
  try {
    const rawData = req.body.data || req.body.fileData;
    const type = req.body.type || req.body.assetType || "asset";
    const filename = req.body.filename || req.body.fileName;
    if (!rawData || typeof rawData !== "string" || !rawData.startsWith("data:image/")) {
      return res.status(400).json({ error: "Invalid image data format. Please upload a valid image file." });
    }

    const matches = rawData.match(/^data:image\/([a-zA-Z0-9+.-]+);base64,(.+)$/);
    if (!matches) {
      return res.status(400).json({ error: "Invalid base64 image data." });
    }

    let ext = matches[1].toLowerCase();
    if (ext === "svg+xml") ext = "svg";
    if (ext === "x-icon" || ext === "vnd.microsoft.icon") ext = "ico";
    if (ext === "jpeg") ext = "jpg";

    const allowed = ["png", "jpg", "jpeg", "webp", "svg", "ico", "gif"];
    if (!allowed.includes(ext)) {
      return res.status(400).json({ error: `Unsupported image format (${ext}). Allowed: PNG, JPG, WEBP, SVG, ICO, GIF.` });
    }

    const buffer = Buffer.from(matches[2], "base64");
    if (buffer.length > 8 * 1024 * 1024) {
      return res.status(400).json({ error: "Image file exceeds maximum allowed size of 8 MB." });
    }

    const safeType = ["icon", "favicon", "og_image"].includes(type) ? type : "asset";
    const outFilename = `${safeType}-${Date.now()}-${crypto.randomBytes(4).toString("hex")}.${ext}`;
    const filePath = path.join(UPLOADS_DIR, outFilename);
    fs.writeFileSync(filePath, buffer);

    const publicUrl = `/uploads/${outFilename}`;
    audit(req.user.id, "settings_upload", `Uploaded ${safeType} image (${outFilename})`, req);
    res.json({ ok: true, url: publicUrl, filename: outFilename });
  } catch (err) {
    res.status(500).json({ error: `Failed to process image upload: ${err.message}` });
  }
});

app.get("/api/admin/overview", requireAuth, requireAdmin, async (req, res) => {
  res.json({
    users: db.prepare("SELECT COUNT(*) AS count FROM users").get().count,
    nodes: db.prepare("SELECT COUNT(*) AS count FROM nodes").get().count,
    servers: db.prepare("SELECT COUNT(*) AS count FROM servers").get().count,
    enabledNodes: db.prepare("SELECT COUNT(*) AS count FROM nodes WHERE enabled=1").get().count,
    recentLogs: db.prepare("SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 30").all()
  });
});
app.get("/api/admin/users", requireAuth, requireAdmin, (req, res) => {
  res.json({ users: db.prepare("SELECT id,username,email,role,active,created_at FROM users ORDER BY id DESC").all().map(safeUser) });
});
app.post("/api/admin/users", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const username = validateString(req.body.username, "Username", 32);
    const email = validateString(req.body.email, "Email", 120).toLowerCase();
    const password = validateString(req.body.password, "Password", 200);
    const role = req.body.role === "admin" ? "admin" : "user";
    if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) return res.status(400).json({ error: "Username must be 3–32 characters (letters, numbers, . _ -)." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
    if (password.length < 12) return res.status(400).json({ error: "Password must be at least 12 characters." });
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,?)").run(username,email,hash,role);
    audit(req.user.id, "user_create", `${username} (${role})`, req);
    res.status(201).json({ user: safeUser(db.prepare("SELECT * FROM users WHERE id=?").get(result.lastInsertRowid)) });
  } catch (e) { if (String(e.message).includes("UNIQUE")) e.status = 409; next(e); }
});
app.patch("/api/admin/users/:id", requireAuth, requireAdmin, (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (id === req.user.id && req.body.active === false) return res.status(400).json({ error: "You cannot disable your own account." });
    const target = db.prepare("SELECT * FROM users WHERE id=?").get(id);
    if (!target) return res.status(404).json({ error: "User not found." });
    if (req.body.role && !["admin","user"].includes(req.body.role)) return res.status(400).json({ error: "Invalid role." });
    db.prepare("UPDATE users SET active=COALESCE(?,active), role=COALESCE(?,role) WHERE id=?")
      .run(typeof req.body.active === "boolean" ? (req.body.active ? 1 : 0) : null, req.body.role || null, id);
    audit(req.user.id, "user_update", `User ${id}`, req);
    res.json({ ok: true });
  } catch (e) { next(e); }
});
app.delete("/api/admin/users/:id", requireAuth, requireAdmin, (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (id === req.user.id) return res.status(400).json({ error: "You cannot delete your own account." });
    db.prepare("DELETE FROM users WHERE id=?").run(id);
    audit(req.user.id, "user_delete", `User ${id}`, req);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.get("/api/admin/nodes", requireAuth, requireAdmin, (req, res) => {
  const nodes = db.prepare("SELECT id,name,host,port,token_id,tls_verify,enabled,created_at FROM nodes ORDER BY id DESC").all();
  res.json({ nodes });
});
app.post("/api/admin/nodes", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const name = validateString(req.body.name, "Node name", 60);
    const host = validateString(req.body.host, "Node host", 253);
    const tokenId = validateString(req.body.tokenId, "API token ID", 180);
    const tokenSecret = validateString(req.body.tokenSecret, "API token secret", 300);
    const port = Number(req.body.port || 8006);
    if (!/^[a-zA-Z0-9.-]+$/.test(host) || !Number.isInteger(port) || port < 1 || port > 65535) {
      return res.status(400).json({ error: "Invalid host or port." });
    }
    const result = db.prepare("INSERT INTO nodes(name,host,port,token_id,token_secret_enc,tls_verify) VALUES(?,?,?,?,?,?)")
      .run(name,host,port,tokenId,encrypt(tokenSecret),req.body.tlsVerify === false ? 0 : 1);
    const node = db.prepare("SELECT * FROM nodes WHERE id=?").get(result.lastInsertRowid);
    await pve(node, "GET", "/version");

    let warning = null;
    try {
      const perms = await pve(node, "GET", "/access/permissions");
      if (!perms || Object.keys(perms).length === 0) {
        warning = "API token has no permissions assigned in Proxmox VE. Please assign an ACL permission (e.g. 'PVEVMAdmin' or 'Administrator' on '/') in Proxmox VE under Datacenter -> Permissions.";
      }
    } catch {}

    audit(req.user.id, "node_create", name, req);
    res.status(201).json({ ok: true, id: result.lastInsertRowid, message: warning ? `Node connected. Warning: ${warning}` : "Node connected and saved.", warning });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) e.status = 409;
    next(e);
  }
});
app.post("/api/admin/nodes/:id/test", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const node = db.prepare("SELECT * FROM nodes WHERE id=?").get(Number(req.params.id));
    if (!node) return res.status(404).json({ error: "Node not found." });
    const version = await pve(node, "GET", "/version");

    let warning = null;
    try {
      const perms = await pve(node, "GET", "/access/permissions");
      if (!perms || Object.keys(perms).length === 0) {
        warning = "API token has no permissions assigned in Proxmox VE. In Proxmox (Datacenter -> Permissions), add an API Token Permission for this token with Path '/' and Role 'PVEVMAdmin' (or uncheck Privilege Separation).";
      }
    } catch {}

    let pveNodes = [];
    try {
      const nodesList = await pve(node, "GET", "/nodes");
      if (Array.isArray(nodesList)) pveNodes = nodesList.map(n => n.node).filter(Boolean);
    } catch {}

    res.json({ ok: true, version, warning, pveNodes });
  } catch (e) { next(e); }
});
async function updateNodeHandler(req, res, next) {
  try {
    const id = Number(req.params.id);
    const node = db.prepare("SELECT * FROM nodes WHERE id=?").get(id);
    if (!node) return res.status(404).json({ error: "Node not found." });

    // If only toggling enabled:
    const bodyKeys = Object.keys(req.body);
    if (bodyKeys.length === 1 && typeof req.body.enabled !== "undefined") {
      const enabledVal = req.body.enabled === true || req.body.enabled === 1 ? 1 : 0;
      db.prepare("UPDATE nodes SET enabled=? WHERE id=?").run(enabledVal, id);
      audit(req.user.id, "node_toggle", `Node ${id} (${node.name}) enabled=${enabledVal}`, req);
      return res.json({ ok: true, message: `Node ${enabledVal ? "enabled" : "disabled"}.` });
    }

    // Full node update:
    const name = validateString(req.body.name || node.name, "Node name", 60);
    const host = validateString(req.body.host || node.host, "Node host", 253);
    const port = Number(req.body.port || node.port || 8006);
    const tokenId = validateString(req.body.tokenId || node.token_id, "API token ID", 180);
    const tlsVerify = typeof req.body.tlsVerify !== "undefined" ? (req.body.tlsVerify === true || req.body.tlsVerify === 1 ? 1 : 0) : node.tls_verify;
    const enabled = typeof req.body.enabled !== "undefined" ? (req.body.enabled === true || req.body.enabled === 1 ? 1 : 0) : node.enabled;

    if (!/^[a-zA-Z0-9.-]+$/.test(host) || !Number.isInteger(port) || port < 1 || port > 65535) {
      return res.status(400).json({ error: "Invalid host or port." });
    }

    let tokenSecretEnc = node.token_secret_enc;
    if (req.body.tokenSecret && typeof req.body.tokenSecret === "string" && req.body.tokenSecret.trim()) {
      tokenSecretEnc = encrypt(req.body.tokenSecret.trim());
    }

    // Verify Proxmox connection with updated credentials
    const updatedNode = { ...node, name, host, port, token_id: tokenId, token_secret_enc: tokenSecretEnc, tls_verify: tlsVerify };
    await pve(updatedNode, "GET", "/version");

    let warning = null;
    try {
      const perms = await pve(updatedNode, "GET", "/access/permissions");
      if (!perms || Object.keys(perms).length === 0) {
        warning = "API token has no permissions assigned in Proxmox VE. Please assign an ACL permission (e.g. 'PVEVMAdmin' or 'Administrator' on '/') in Proxmox VE under Datacenter -> Permissions.";
      }
    } catch {}

    db.prepare(`
      UPDATE nodes 
      SET name=?, host=?, port=?, token_id=?, token_secret_enc=?, tls_verify=?, enabled=?
      WHERE id=?
    `).run(name, host, port, tokenId, tokenSecretEnc, tlsVerify, enabled, id);

    audit(req.user.id, "node_update", `Node ${id} (${name})`, req);
    res.json({ ok: true, message: warning ? `Node updated. Warning: ${warning}` : "Node updated and verified successfully.", warning });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) e.status = 409;
    next(e);
  }
}

app.patch("/api/admin/nodes/:id", requireAuth, requireAdmin, updateNodeHandler);
app.put("/api/admin/nodes/:id", requireAuth, requireAdmin, updateNodeHandler);

app.delete("/api/admin/nodes/:id", requireAuth, requireAdmin, (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const node = db.prepare("SELECT * FROM nodes WHERE id=?").get(id);
    if (!node) return res.status(404).json({ error: "Node not found." });
    const count = db.prepare("SELECT COUNT(*) AS c FROM servers WHERE node_id=?").get(id).c;
    if (count > 0) {
      return res.status(409).json({ error: `Cannot delete node: ${count} assigned VPS record(s) are linked to this node. Please delete or reassign them first.` });
    }
    db.prepare("DELETE FROM nodes WHERE id=?").run(id);
    audit(req.user.id, "node_delete", `Node ${id} (${node.name})`, req);
    res.json({ ok: true, message: `Node "${node.name}" deleted successfully.` });
  } catch (e) { next(e); }
});

app.get("/api/admin/nodes/:id/details", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const node = db.prepare("SELECT id, name, host, port, token_id, tls_verify, enabled, created_at, token_secret_enc FROM nodes WHERE id=?").get(id);
    if (!node) return res.status(404).json({ error: "Node not found." });

    // 1. Resolve internal PVE node name
    let pveNode = "";
    let pveNodesList = [];
    try {
      const nodesData = await pve(node, "GET", "/nodes");
      if (Array.isArray(nodesData)) {
        pveNodesList = nodesData;
        pveNode = nodesData[0]?.node || "";
      }
    } catch (err) {
      console.warn("Could not query /nodes:", err.message);
    }
    if (!pveNode) {
      pveNode = node.name.toLowerCase().replace(/[^a-z0-9_-]/g, "");
    }

    // 2. Query node status, version, network, storage, VMs, and rrd in parallel
    const [verResult, statusResult, netResult, storageResult, vmResult, rrdResult] = await Promise.allSettled([
      pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/version`).catch(() => pve(node, "GET", "/version")),
      pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/status`),
      pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/network`),
      pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage`).catch(() => pve(node, "GET", "/storage")),
      pve(node, "GET", "/cluster/resources?type=vm"),
      pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/rrddata?timeframe=hour`)
    ]);

    const version = verResult.status === "fulfilled" ? verResult.value : null;
    const status = statusResult.status === "fulfilled" ? statusResult.value : null;
    const statusSysAuditRequired = statusResult.status === "rejected" && String(statusResult.reason?.message || "").includes("Sys.Audit");
    const network = netResult.status === "fulfilled" && Array.isArray(netResult.value) ? netResult.value : [];
    const storage = storageResult.status === "fulfilled" && Array.isArray(storageResult.value) ? storageResult.value : [];
    const allVms = vmResult.status === "fulfilled" && Array.isArray(vmResult.value) ? vmResult.value : [];
    const rrd = rrdResult.status === "fulfilled" && Array.isArray(rrdResult.value) ? rrdResult.value : [];

    // Filter VMs for this specific node (or fallback to probing if cluster/resources was restricted)
    let nodeVms = allVms.filter(v => !v.node || v.node === pveNode);
    if (nodeVms.length === 0) {
      try {
        const qemu = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/qemu`);
        if (Array.isArray(qemu)) nodeVms.push(...qemu.map(x => ({ ...x, type: "qemu", node: pveNode })));
      } catch {}
      try {
        const lxc = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/lxc`);
        if (Array.isArray(lxc)) nodeVms.push(...lxc.map(x => ({ ...x, type: "lxc", node: pveNode })));
      } catch {}
    }

    // Map panel servers to see which VMs are assigned
    const assignedServers = db.prepare("SELECT id, vmid, name, user_id FROM servers WHERE node_id=?").all(id);
    const assignedMap = new Map();
    for (const s of assignedServers) assignedMap.set(Number(s.vmid), s.id);

    let allocatedCpu = 0;
    let allocatedMem = 0;
    let allocatedDisk = 0;
    let runningCount = 0;
    let stoppedCount = 0;

    for (const v of nodeVms) {
      if (v.status === "running") runningCount++;
      else stoppedCount++;
      allocatedCpu += Number(v.maxcpu || v.cpus || 0);
      allocatedMem += Number(v.maxmem || 0);
      allocatedDisk += Number(v.maxdisk || 0);
      v.assignedServerId = assignedMap.get(Number(v.vmid)) || null;
    }

    const nodeClusterInfo = pveNodesList.find(n => n.node === pveNode) || pveNodesList[0] || null;

    res.json({
      ok: true,
      node: {
        id: node.id,
        name: node.name,
        host: node.host,
        port: node.port,
        token_id: node.token_id,
        tls_verify: node.tls_verify,
        enabled: node.enabled,
        created_at: node.created_at
      },
      pveNode,
      clusterInfo: nodeClusterInfo,
      version,
      status,
      statusSysAuditRequired,
      network,
      storage,
      rrd,
      vmSummary: {
        total: nodeVms.length,
        running: runningCount,
        stopped: stoppedCount,
        allocatedCpu,
        allocatedMem,
        allocatedDisk
      },
      vms: nodeVms.map(v => ({
        vmid: v.vmid,
        name: v.name || `VM ${v.vmid}`,
        type: v.type,
        status: v.status,
        cpu: v.cpu || 0,
        maxcpu: v.maxcpu || 0,
        mem: v.mem || 0,
        maxmem: v.maxmem || 0,
        disk: v.disk || 0,
        maxdisk: v.maxdisk || 0,
        uptime: v.uptime || 0,
        netin: v.netin || 0,
        netout: v.netout || 0,
        diskread: v.diskread || 0,
        diskwrite: v.diskwrite || 0,
        assignedServerId: v.assignedServerId
      }))
    });
  } catch (e) {
    next(e);
  }
});

app.get("/api/admin/proxmox/nodes/:nodeId/resources", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const node = getNode(Number(req.params.nodeId));
    let resources = [];
    try {
      const clusterRes = await pve(node, "GET", "/cluster/resources?type=vm");
      if (Array.isArray(clusterRes)) resources = clusterRes;
    } catch {}

    if (resources.length === 0) {
      try {
        const nodesList = await pve(node, "GET", "/nodes");
        if (Array.isArray(nodesList)) {
          for (const n of nodesList) {
            try {
              const qemu = await pve(node, "GET", `/nodes/${encodeURIComponent(n.node)}/qemu`);
              if (Array.isArray(qemu)) {
                resources.push(...qemu.map(x => ({ ...x, type: "qemu", node: n.node })));
              }
            } catch {}
            try {
              const lxc = await pve(node, "GET", `/nodes/${encodeURIComponent(n.node)}/lxc`);
              if (Array.isArray(lxc)) {
                resources.push(...lxc.map(x => ({ ...x, type: "lxc", node: n.node })));
              }
            } catch {}
          }
        }
      } catch {}
    }
    res.json({ resources });
  } catch (e) { next(e); }
});

app.get("/api/admin/servers/create/options", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const nodes = db.prepare("SELECT id, name, host, port FROM nodes WHERE enabled=1 ORDER BY id DESC").all();
    const users = db.prepare("SELECT id, username, email FROM users WHERE active=1 ORDER BY username ASC").all();

    if (nodes.length === 0) {
      return res.json({ ok: true, nodes: [], users, error: "No enabled Proxmox nodes found." });
    }

    const requestedNodeId = req.query.nodeId ? Number(req.query.nodeId) : nodes[0].id;
    const node = getNode(requestedNodeId);

    // Resolve internal node name
    let pveNode = "";
    try {
      const nodesList = await pve(node, "GET", "/nodes");
      if (Array.isArray(nodesList)) pveNode = nodesList[0]?.node || "";
    } catch {}
    if (!pveNode) pveNode = node.name.toLowerCase().replace(/[^a-z0-9_-]/g, "");

    // 1. Next free VMID
    let nextVmid = 100;
    try {
      const nid = await pve(node, "GET", "/cluster/nextid");
      if (nid) nextVmid = Number(nid);
    } catch {
      const maxRow = db.prepare("SELECT MAX(vmid) as max FROM servers WHERE node_id=?").get(node.id);
      nextVmid = (maxRow?.max || 100) + 1;
    }

    // 2. QEMU Templates
    let qemuTemplates = [];
    try {
      const allVms = await pve(node, "GET", "/cluster/resources?type=vm");
      if (Array.isArray(allVms)) {
        qemuTemplates = allVms
          .filter(v => v.template === 1 && v.type === "qemu")
          .map(v => ({
            id: v.vmid,
            vmid: v.vmid,
            name: v.name || `Template ${v.vmid}`,
            type: "qemu",
            node: v.node || pveNode,
            disk: v.maxdisk || 0
          }));
      }
    } catch {}
    if (qemuTemplates.length === 0) {
      qemuTemplates = [
        { id: 1003, vmid: 1003, name: "Ubuntu-24.04", type: "qemu" },
        { id: 4001, vmid: 4001, name: "Debian-12", type: "qemu" }
      ];
    }

    // 3. LXC Templates
    let lxcTemplates = [];
    try {
      const apl = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/aplinfo`);
      if (Array.isArray(apl)) {
        const popular = apl.filter(x => 
          /ubuntu|debian|alpine|almalinux|rocky|centos|archlinux/i.test(x.package) &&
          (x.architecture === "amd64" || !x.architecture)
        );
        lxcTemplates = popular.map(x => ({
          id: x.template,
          package: x.package,
          name: x.headline || x.package,
          template: x.template,
          type: "lxc"
        }));
      }
    } catch {}
    if (lxcTemplates.length === 0) {
      lxcTemplates = [
        { id: "ubuntu-24.04-standard_24.04-2_amd64.tar.zst", package: "ubuntu-24.04-standard", name: "Ubuntu 24.04 LTS (Standard)", type: "lxc" },
        { id: "ubuntu-22.04-standard_22.04-1_amd64.tar.zst", package: "ubuntu-22.04-standard", name: "Ubuntu 22.04 LTS (Standard)", type: "lxc" },
        { id: "debian-12-standard_12.7-1_amd64.tar.zst", package: "debian-12-standard", name: "Debian 12 Bookworm (Standard)", type: "lxc" },
        { id: "almalinux-9-default_20240911_amd64.tar.xz", package: "almalinux-9-default", name: "AlmaLinux 9 (Default)", type: "lxc" },
        { id: "alpine-3.24-default_20261105_amd64.tar.xz", package: "alpine-3.24-default", name: "Alpine Linux 3.24 (Default)", type: "lxc" }
      ];
    }

    // 4. ISOs
    let isoList = [];
    try {
      const storages = ["local", "nvme-storage", "ISO", "iso"];
      for (const st of storages) {
        try {
          const res = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage/${st}/content?content=iso`);
          if (Array.isArray(res)) {
            for (const item of res) {
              if (item.volid) isoList.push({ volid: item.volid, name: item.volid.split("/").pop() || item.volid, size: item.size });
            }
          }
        } catch {}
      }
    } catch {}
    if (isoList.length === 0) {
      isoList = [
        { volid: "local:iso/ubuntu-24.04-live-server-amd64.iso", name: "Ubuntu 24.04 Live Server (local)" },
        { volid: "local:iso/debian-12.7.0-amd64-netinst.iso", name: "Debian 12.7 Netinst (local)" },
        { volid: "local:iso/Windows_Server_2022.iso", name: "Windows Server 2022 (local)" }
      ];
    }

    // 5. Storages
    let storages = [];
    try {
      const stList = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage`);
      if (Array.isArray(stList)) {
        storages = stList.map(s => s.storage).filter(Boolean);
      }
    } catch {}
    if (storages.length === 0) {
      storages = ["local-lvm", "nvme-storage", "local"];
    }

    // 6. Network Bridges
    let bridges = [];
    try {
      const net = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/network`);
      if (Array.isArray(net)) {
        bridges = net.filter(x => x.type === "bridge" || String(x.iface).startsWith("vmbr")).map(x => x.iface);
      }
    } catch {}
    if (bridges.length === 0) {
      bridges = ["vmbr0", "vmbr1"];
    }

    // 7. Check Datastore.AllocateSpace permission
    let datastorePermissionRequired = false;
    try {
      const perms = await pve(node, "GET", "/access/permissions");
      const storagePerms = perms?.["/storage"] || perms?.["/"] || {};
      if (!storagePerms["Datastore.AllocateSpace"] && !storagePerms["Administrator"]) {
        datastorePermissionRequired = true;
      }
    } catch {}

    res.json({
      ok: true,
      selectedNodeId: node.id,
      pveNode,
      nodes,
      users,
      nextVmid,
      qemuTemplates,
      lxcTemplates,
      isoList,
      storages,
      bridges,
      datastorePermissionRequired
    });
  } catch (e) {
    next(e);
  }
});

app.post("/api/admin/servers/create", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const userId = Number(req.body.userId);
    const nodeId = Number(req.body.nodeId);
    const vmid = Number(req.body.vmid);
    const name = validateString(req.body.name, "Server name", 80);
    const type = req.body.type === "lxc" ? "lxc" : "qemu";
    const provisionMethod = (req.body.provisionMethod === "iso" || req.body.source === "iso") ? "iso" : "template";

    if (!Number.isInteger(userId) || !Number.isInteger(nodeId) || !Number.isInteger(vmid) || vmid < 100) {
      return res.status(400).json({ error: "Invalid user, node, or VMID (must be >= 100)." });
    }
    const user = db.prepare("SELECT id, username FROM users WHERE id=? AND active=1").get(userId);
    if (!user) return res.status(404).json({ error: "Active user not found." });

    const node = getNode(nodeId);

    // Resolve internal node name
    let pveNode = "";
    try {
      const nodesList = await pve(node, "GET", "/nodes");
      if (Array.isArray(nodesList)) pveNode = nodesList[0]?.node || "";
    } catch {}
    if (!pveNode) pveNode = node.name.toLowerCase().replace(/[^a-z0-9_-]/g, "");

    // Check if VMID is already taken in the database
    const existingInDb = db.prepare("SELECT id FROM servers WHERE node_id=? AND vmid=?").get(nodeId, vmid);
    if (existingInDb) {
      return res.status(409).json({ error: `A VPS with VMID ${vmid} already exists in the panel database.` });
    }

    // Hardware specifications
    const cores = Math.max(1, Math.min(128, Number(req.body.cores || 2)));
    const sockets = Math.max(1, Math.min(8, Number(req.body.sockets || 1)));
    const memory = Math.max(256, Math.min(524288, Number(req.body.memory || 2048)));
    const swap = Math.max(0, Math.min(65536, Number(req.body.swap != null ? req.body.swap : 512)));
    const diskSize = Math.max(1, Math.min(10000, Number(req.body.disk || req.body.diskSize || req.body.disk_size || 20)));
    const storage = validateString(req.body.storage || "local-lvm", "Storage", 50);
    const bridge = validateString(req.body.bridge || "vmbr0", "Bridge", 30);
    const startAfterCreate = req.body.start !== false && req.body.startAfterCreate !== false && req.body.start !== "false" && req.body.startAfterCreate !== "false";

    // Credentials & Keys
    const password = req.body.password && typeof req.body.password === "string" ? req.body.password.trim() : "";
    const sshKey = req.body.sshKey && typeof req.body.sshKey === "string" ? req.body.sshKey.trim() : "";
    const ciUser = req.body.ciUser && typeof req.body.ciUser === "string" && req.body.ciUser.trim() ? req.body.ciUser.trim() : "root";

    // Network & IP Settings
    const vlan = req.body.vlan ? Number(req.body.vlan) : null;
    const mac = req.body.mac && typeof req.body.mac === "string" ? req.body.mac.trim() : null;
    const firewall = req.body.firewall !== false && req.body.firewall !== "false" && req.body.firewall !== 0 && req.body.firewall !== "0";

    const net = buildIpConfig(req.body.ip4Type, req.body.ip4Address, req.body.ip4Gateway, req.body.ip6Type, req.body.ip6Address, req.body.ip6Gateway);

    // DNS Settings
    const searchDomain = req.body.searchDomain && typeof req.body.searchDomain === "string" ? req.body.searchDomain.trim() : "";
    const nameServers = req.body.nameServers && typeof req.body.nameServers === "string" ? req.body.nameServers.trim() : "";

    // Container / QEMU Options
    const unprivileged = req.body.unprivileged !== false && req.body.unprivileged !== "false";
    const nesting = req.body.nesting !== false && req.body.nesting !== "false";
    const ciUpgrade = req.body.ciUpgrade === true || req.body.ciUpgrade === "true" || req.body.ciUpgrade === 1 || req.body.ciUpgrade === "1";
    const qemuAgent = req.body.qemuAgent !== false && req.body.qemuAgent !== "false";

    if (provisionMethod === "template" && password.length < 8) {
      return res.status(400).json({ error: "Root password must be at least 8 characters long for template installations." });
    }

    // Execution
    if (type === "qemu") {
      if (provisionMethod === "template") {
        const templateId = Number(req.body.templateId);
        if (!Number.isInteger(templateId) || templateId < 100) {
          return res.status(400).json({ error: "Please select a valid QEMU template." });
        }

        // Clone template
        try {
          const cloneTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu/${templateId}/clone`, {
            newid: vmid,
            name,
            full: 1,
            storage
          });
          await waitForPveTask(node, pveNode, cloneTask, 120);
        } catch (err) {
          if (String(err.message).includes("AllocateSpace")) {
            return res.status(403).json({
              error: "Proxmox permission required: Datastore.AllocateSpace. Please add role 'PVEDatastoreUser' or 'Administrator' to API token in Proxmox VE (Datacenter -> Permissions)."
            });
          }
          throw new Error(`Failed to clone VM template: ${err.message}`);
        }

        // Build net0 string
        let net0Str = `virtio,bridge=${bridge}`;
        if (vlan) net0Str += `,tag=${vlan}`;
        if (mac) net0Str += `,macaddr=${mac}`;
        if (firewall) net0Str += `,firewall=1`;

        // Build Cloud-Init ipconfig0 string
        let ipconfig0Str = "";
        if (net.ip4Type === "static" && net.ip4) {
          ipconfig0Str = `ip=${net.ip4}`;
          if (net.gw4) ipconfig0Str += `,gw=${net.gw4}`;
        } else {
          ipconfig0Str = "ip=dhcp";
        }
        if (net.ip6Type === "static" && net.ip6) {
          ipconfig0Str += `,ip6=${net.ip6}`;
          if (net.gw6) ipconfig0Str += `,gw6=${net.gw6}`;
        } else if (net.ip6Type === "dhcp") {
          ipconfig0Str += ",ip6=dhcp";
        } else if (net.ip6Type === "auto") {
          ipconfig0Str += ",ip6=auto";
        }

        // Update hardware specifications and Cloud-Init config
        const configUpdate = {
          cores,
          sockets,
          memory,
          net0: net0Str,
          ipconfig0: ipconfig0Str,
          ciuser: ciUser,
          cipassword: password
        };
        if (sshKey) configUpdate.sshkeys = encodeURIComponent(sshKey);
        if (searchDomain) configUpdate.searchdomain = searchDomain;
        if (nameServers) configUpdate.nameserver = nameServers;
        if (ciUpgrade) configUpdate.ciupgrade = 1;
        if (qemuAgent) configUpdate.agent = 1;

        await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu/${vmid}/config`, configUpdate);

        // Resize disk to target size
        try {
          const newCfg = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/qemu/${vmid}/config`);
          let newDiskKey = "scsi0";
          let templateDiskGb = 0;
          const candidateKeys = [];
          for (let i = 0; i < 16; i++) {
            candidateKeys.push(`scsi${i}`, `virtio${i}`, `sata${i}`, `ide${i}`);
          }
          for (const k of candidateKeys) {
            const dStr = newCfg[k] || "";
            if (dStr && typeof dStr === "string" && !dStr.includes("media=cdrom") && !dStr.includes("cloudinit") && !dStr.includes("none")) {
              newDiskKey = k;
              const m = dStr.match(/size=([0-9.]+)([GMKT])/i);
              if (m) {
                const num = parseFloat(m[1]);
                const unit = m[2].toUpperCase();
                templateDiskGb = unit === "M" ? Math.round(num / 1024) : (unit === "T" ? num * 1024 : num);
              }
              break;
            }
          }

          if (diskSize > templateDiskGb) {
            const resizeRes = await pve(node, "PUT", `/nodes/${encodeURIComponent(pveNode)}/qemu/${vmid}/resize`, {
              disk: newDiskKey,
              size: `${diskSize}G`
            });
            if (typeof resizeRes === "string" && resizeRes.startsWith("UPID")) {
              await waitForPveTask(node, pveNode, resizeRes, 60);
            }
          }
        } catch (resizeErr) {
          console.error("Disk resize notice on create:", resizeErr.message);
        }

        if (startAfterCreate) {
          try {
            await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu/${vmid}/status/start`);
          } catch {}
        }

      } else {
        // Provision from ISO
        const isoVolid = validateString(req.body.iso || req.body.isoVolid, "ISO image", 250);
        const osType = req.body.osType && ["l26", "win11", "win10", "other"].includes(req.body.osType) ? req.body.osType : "l26";

        let net0Qemu = `virtio,bridge=${bridge}`;
        if (vlan) net0Qemu += `,tag=${vlan}`;
        if (mac) net0Qemu += `,macaddr=${mac}`;
        if (firewall) net0Qemu += `,firewall=1`;

        const createParams = {
          vmid,
          name,
          memory,
          cores,
          sockets,
          cpu: "host",
          ostype: osType,
          scsihw: "virtio-scsi-single",
          boot: "order=ide2;scsi0",
          ide2: `${isoVolid},media=cdrom`,
          scsi0: `${storage}:${diskSize},discard=on,ssd=1`,
          net0: net0Qemu,
          agent: qemuAgent ? 1 : 0
        };

        try {
          const createTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu`, createParams);
          await waitForPveTask(node, pveNode, createTask, 60);
        } catch (err) {
          if (String(err.message).includes("AllocateSpace")) {
            return res.status(403).json({
              error: "Proxmox permission required: Datastore.AllocateSpace. Please add role 'PVEDatastoreUser' or 'Administrator' to API token in Proxmox VE (Datacenter -> Permissions)."
            });
          }
          throw new Error(`Failed to create VM from ISO: ${err.message}`);
        }

        if (startAfterCreate) {
          try {
            await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu/${vmid}/status/start`);
          } catch {}
        }
      }

    } else if (type === "lxc") {
      const templateVolid = validateString(req.body.templateId, "LXC Template", 250);

      // Build net0 for LXC
      let net0Lxc = `name=eth0,bridge=${bridge}`;
      if (vlan) net0Lxc += `,tag=${vlan}`;
      if (mac) net0Lxc += `,hwaddr=${mac}`;
      if (firewall) net0Lxc += `,firewall=1`;

      if (net.ip4Type === "static" && net.ip4) {
        net0Lxc += `,ip=${net.ip4}`;
        if (net.gw4) net0Lxc += `,gw=${net.gw4}`;
      } else {
        net0Lxc += ",ip=dhcp";
      }

      if (net.ip6Type === "static" && net.ip6) {
        net0Lxc += `,ip6=${net.ip6}`;
        if (net.gw6) net0Lxc += `,gw6=${net.gw6}`;
      } else if (net.ip6Type === "dhcp") {
        net0Lxc += ",ip6=dhcp";
      } else if (net.ip6Type === "auto") {
        net0Lxc += ",ip6=auto";
      }

      let ostemplate = templateVolid;
      if (!ostemplate.includes(":")) {
        ostemplate = `local:vztmpl/${ostemplate}`;
      }

      const createParams = {
        vmid,
        hostname: name,
        ostemplate,
        cores,
        memory,
        swap,
        net0: net0Lxc,
        rootfs: `${storage}:${diskSize}`,
        password,
        unprivileged: unprivileged ? 1 : 0
      };
      if (nesting) createParams.features = "nesting=1";
      if (sshKey) createParams["ssh-public-keys"] = encodeURIComponent(sshKey);
      if (searchDomain) createParams.searchdomain = searchDomain;
      if (nameServers) createParams.nameserver = nameServers;

      try {
        const createTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/lxc`, createParams);
        await waitForPveTask(node, pveNode, createTask, 120);
      } catch (err) {
        const errMsg = String(err.message).toLowerCase();
        if (errMsg.includes("does not exist") || errMsg.includes("no such file")) {
          const bareTemplate = templateVolid.split("/").pop();
          try {
            const dlTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/aplinfo`, {
              template: bareTemplate,
              storage: "local"
            });
            await waitForPveTask(node, pveNode, dlTask, 180);
            const createTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/lxc`, createParams);
            await waitForPveTask(node, pveNode, createTask, 120);
          } catch (dlErr) {
            throw new Error(`Failed to download template & create container: ${dlErr.message}`);
          }
        } else if (String(err.message).includes("AllocateSpace")) {
          return res.status(403).json({
            error: "Proxmox permission required: Datastore.AllocateSpace. Please add role 'PVEDatastoreUser' or 'Administrator' to API token in Proxmox VE (Datacenter -> Permissions)."
          });
        } else {
          throw new Error(`Failed to create LXC container: ${err.message}`);
        }
      }

      if (startAfterCreate) {
        try {
          await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/lxc/${vmid}/status/start`);
        } catch {}
      }
    }

    // Insert newly created server into panel SQLite database
    const result = db.prepare(`
      INSERT INTO servers(user_id, node_id, vmid, type, pve_node, name)
      VALUES(?, ?, ?, ?, ?, ?)
    `).run(userId, nodeId, vmid, type, pveNode, name);

    audit(req.user.id, "server_create", `${type}:${vmid} (${name}) created for user ${user.username}`, req);
    io.emit("vps:list_changed");
    setTimeout(pollLiveMetrics, 300);

    res.status(201).json({
      ok: true,
      id: result.lastInsertRowid,
      vmid,
      name,
      type,
      message: `${type.toUpperCase()} instance "${name}" (VMID ${vmid}) created and deployed successfully!`
    });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) e.status = 409;
    next(e);
  }
});

app.post("/api/admin/servers/assign", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const userId = Number(req.body.userId), nodeId = Number(req.body.nodeId), vmid = Number(req.body.vmid);
    let type = req.body.type === "lxc" ? "lxc" : "qemu";
    const name = validateString(req.body.name, "Server name", 80);
    if (!Number.isInteger(userId) || !Number.isInteger(nodeId) || !Number.isInteger(vmid) || vmid < 100) {
      return res.status(400).json({ error: "Invalid user, node or VMID." });
    }
    if (!db.prepare("SELECT id FROM users WHERE id=? AND active=1").get(userId)) {
      return res.status(404).json({ error: "Active user not found." });
    }
    const node = getNode(nodeId);

    // 1. Try to find the VM in Proxmox cluster resources
    let resource = null;
    let allResources = [];
    try {
      const res = await pve(node, "GET", "/cluster/resources?type=vm");
      if (Array.isArray(res)) allResources = res;
    } catch (err) {
      console.warn("Could not query /cluster/resources:", err.message);
    }

    if (allResources.length > 0) {
      resource = allResources.find(x => Number(x.vmid) === vmid && x.type === type);
      if (!resource) {
        resource = allResources.find(x => Number(x.vmid) === vmid);
        if (resource) type = resource.type;
      }
    }

    // 2. If not found in cluster resources (e.g. restricted API token permissions or standalone node), probe nodes directly
    if (!resource) {
      let pveNodes = [];
      try {
        const nodesList = await pve(node, "GET", "/nodes");
        if (Array.isArray(nodesList)) {
          pveNodes = nodesList.map(n => n.node).filter(Boolean);
        }
      } catch (err) {
        console.warn("Could not list /nodes:", err.message);
      }

      if (pveNodes.length === 0) {
        const cleanName = node.name.toLowerCase().replace(/[^a-z0-9_-]/g, "");
        if (cleanName) pveNodes.push(cleanName);
      }

      const typesToTry = [type, type === "qemu" ? "lxc" : "qemu"];
      let lastPermError = null;

      for (const pveNode of pveNodes) {
        for (const t of typesToTry) {
          try {
            await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/${t}/${vmid}/status/current`);
            resource = { vmid, node: pveNode, type: t };
            type = t;
            break;
          } catch (probeErr) {
            const detail = probeErr.response?.data?.errors || probeErr.response?.data?.message || probeErr.message;
            if (probeErr.status === 403 || String(detail).includes("Permission check failed")) {
              lastPermError = { status: 403, message: detail };
            }
          }
        }
        if (resource) break;
      }

      if (!resource) {
        if (lastPermError) {
          return res.status(403).json({
            error: `Proxmox permission denied for VM ${vmid}. The API token '${node.token_id}' does not have sufficient permissions. In Proxmox VE (Datacenter -> Permissions), grant '${node.token_id}' a role with VM permissions (e.g. 'PVEVMAdmin' or 'VM.Audit') on path '/vms' or '/', or recreate the token with 'Privilege Separation' unchecked.`
          });
        }

        let hasAnyPerms = false;
        try {
          const perms = await pve(node, "GET", "/access/permissions");
          if (perms && Object.keys(perms).length > 0) hasAnyPerms = true;
        } catch {}

        if (!hasAnyPerms && allResources.length === 0) {
          return res.status(403).json({
            error: `Proxmox API token '${node.token_id}' has no permissions assigned. In Proxmox VE (Datacenter -> Permissions), add an API Token Permission for '${node.token_id}' with Path '/' and Role 'PVEVMAdmin' (or 'Administrator'), or recreate the token without 'Privilege Separation'.`
          });
        }

        const searchedWhere = pveNodes.length > 0 ? ` on node(s): ${pveNodes.join(", ")}` : "";
        return res.status(404).json({
          error: `VM/container with VMID ${vmid} was not found${searchedWhere} on the connected Proxmox host. Please verify that VM ${vmid} exists in Proxmox VE.`
        });
      }
    }

    const pveNode = resource.node;
    const result = db.prepare("INSERT INTO servers(user_id,node_id,vmid,type,pve_node,name) VALUES(?,?,?,?,?,?)").run(userId,nodeId,vmid,type,pveNode,name);
    audit(req.user.id, "server_assign", `${type}:${vmid} (node: ${pveNode}) to user ${userId}`, req);
    io.emit("vps:list_changed");
    setTimeout(pollLiveMetrics, 300);
    res.status(201).json({ ok: true, id: result.lastInsertRowid, pve_node: pveNode, type });
  } catch (e) { if (String(e.message).includes("UNIQUE")) e.status = 409; next(e); }
});
app.delete("/api/admin/servers/:id/assignment", requireAuth, requireAdmin, (req, res, next) => {
  try {
    const sId = Number(req.params.id);
    const existing = db.prepare("SELECT s.*, u.username FROM servers s LEFT JOIN users u ON u.id = s.user_id WHERE s.id=?").get(sId);
    if (!existing) {
      return res.status(404).json({ error: "Server assignment not found." });
    }
    db.prepare("DELETE FROM servers WHERE id=?").run(sId);
    audit(req.user.id, "server_unassign", `${existing.type}:${existing.vmid} (${existing.name || 'unnamed'}) removed from user #${existing.user_id} (${existing.username || 'unknown'})`, req);
    io.emit("vps:list_changed");
    setTimeout(pollLiveMetrics, 300);
    res.json({ ok: true, name: existing.name, vmid: existing.vmid, type: existing.type, username: existing.username });
  } catch (e) { next(e); }
});

app.get("/api/admin/logs", requireAuth, requireAdmin, (req, res) => {
  const logs = db.prepare("SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200").all();
  res.json({ logs });
});

app.get("/api/admin/tasks", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const nodes = db.prepare("SELECT * FROM nodes WHERE enabled = 1").all();
    if (!nodes.length) return res.json({ tasks: [] });

    let allTasks = [];
    for (const n of nodes) {
      try {
        const list = await pve(n, "GET", "/cluster/tasks");
        if (Array.isArray(list)) {
          allTasks.push(...list.map(t => ({ ...t, node_name: n.name })));
        }
      } catch {
        try {
          const nDetails = await pve(n, "GET", "/nodes");
          if (Array.isArray(nDetails) && nDetails[0]) {
            const pveName = nDetails[0].node;
            const nTasks = await pve(n, "GET", `/nodes/${encodeURIComponent(pveName)}/tasks`);
            if (Array.isArray(nTasks)) {
              allTasks.push(...nTasks.map(t => ({ ...t, node_name: n.name })));
            }
          }
        } catch {}
      }
    }

    allTasks.sort((a, b) => (b.starttime || 0) - (a.starttime || 0));
    res.json({ tasks: allTasks.slice(0, 100) });
  } catch (e) { next(e); }
});

app.get("*", (req, res) => {
  try {
    const rawHtml = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
    const s = getSettings();
    const siteTitle = s.site_name ? `${s.site_name} — VPS Control Panel` : "Atyro Cloud — VPS Control Panel";
    const siteDesc = s.seo_description || s.site_description || "Next-Generation Proxmox VE VPS Cloud Management Platform";
    const ogImg = s.og_image || s.site_icon || "";
    const favIcon = s.site_favicon || s.site_icon || "";

    let html = rawHtml
      .replace(/<title>[\s\S]*?<\/title>/i, `<title>${siteTitle}</title>`)
      .replace(/<meta name="description"[^>]*>/i, `<meta name="description" content="${siteDesc}">`)
      .replace(/<meta property="og:title"[^>]*>/i, `<meta property="og:title" content="${siteTitle}">`)
      .replace(/<meta property="og:description"[^>]*>/i, `<meta property="og:description" content="${siteDesc}">`)
      .replace(/<meta property="og:image"[^>]*>/i, `<meta property="og:image" content="${ogImg}">`)
      .replace(/<link rel="icon"[^>]*>/i, favIcon ? `<link rel="icon" href="${favIcon}">` : '<link rel="icon" href="data:,">');

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(html);
  } catch (err) {
    res.sendFile(path.join(__dirname, "index.html"));
  }
});

app.use((err, req, res, next) => {
  const status = Number(err.status) || 500;
  if (status >= 500) console.error(`[${new Date().toISOString()}]`, err);
  res.status(status).json({ error: status >= 500 && process.env.NODE_ENV === "production" ? "Server error. Check server logs." : err.message });
});

// ==========================================
// SOCKET.IO REAL-TIME LIVE DATA & METRICS
// ==========================================

let isPollingMetrics = false;
async function pollLiveMetrics() {
  if (isPollingMetrics) return;
  if (!io || io.engine.clientsCount === 0) return;
  isPollingMetrics = true;

  try {
    const nodes = db.prepare("SELECT * FROM nodes WHERE enabled = 1").all();
    if (!nodes.length) return;

    const allServers = db.prepare(`
      SELECT s.*, u.username, n.name AS node_name, n.host, n.port, n.token_id, n.token_secret_enc, n.tls_verify, n.enabled
      FROM servers s
      JOIN users u ON u.id = s.user_id
      JOIN nodes n ON n.id = s.node_id
      WHERE n.enabled = 1
    `).all();

    if (!allServers.length) return;

    // 1. Fetch /cluster/resources?type=vm for each node in parallel
    const pveVmMap = new Map();
    await Promise.allSettled(nodes.map(async (n) => {
      try {
        const list = await pve(n, "GET", "/cluster/resources?type=vm");
        if (Array.isArray(list)) {
          for (const item of list) {
            pveVmMap.set(Number(item.vmid), item);
          }
        }
      } catch (e) {}
    }));

    // 2. Map metrics for all DB servers
    const statsList = [];
    for (const s of allServers) {
      const pveVm = pveVmMap.get(Number(s.vmid));
      let status = "unknown";
      let uptime = 0;
      let cpu = 0;
      let cpuPct = "0.0";
      let mem = 0;
      let maxmem = 1;
      let memPct = "0.0";
      let freemem = 0;
      let diskread = 0;
      let diskwrite = 0;
      let netin = 0;
      let netout = 0;
      let diskMax = 0;

      if (pveVm) {
        status = pveVm.status || "unknown";
        uptime = pveVm.uptime || 0;
        cpu = pveVm.cpu || 0;
        cpuPct = (cpu * 100).toFixed(1);
        mem = pveVm.mem || 0;
        maxmem = pveVm.maxmem || 1;
        memPct = maxmem > 0 ? ((mem / maxmem) * 100).toFixed(1) : "0.0";
        freemem = Math.max(0, maxmem - mem);
        diskread = pveVm.diskread || 0;
        diskwrite = pveVm.diskwrite || 0;
        netin = pveVm.netin || 0;
        netout = pveVm.netout || 0;
        diskMax = pveVm.maxdisk || 0;
      }

      const statItem = {
        id: s.id,
        vmid: s.vmid,
        userId: s.user_id,
        username: s.username,
        name: s.name,
        type: s.type,
        nodeName: s.pve_node || s.node_name,
        status,
        uptime,
        cpu,
        cpuPct,
        mem,
        maxmem,
        memPct,
        freemem,
        diskread,
        diskwrite,
        netin,
        netout,
        diskMax,
        timestamp: Math.floor(Date.now() / 1000)
      };

      statsList.push(statItem);

      // Check if a client has actively subscribed to this specific VPS view
      const room = io.sockets.adapter.rooms.get(`vps_${s.id}`);
      if (room && room.size > 0) {
        sendSingleVpsStats(s.id);
      }
    }

    // 3. Broadcast batch to admins
    io.to("admins").emit("vps:batch_stats", statsList);
    io.to("admins").emit("cluster:summary", {
      total: statsList.length,
      running: statsList.filter(x => x.status === "running").length,
      stopped: statsList.filter(x => x.status === "stopped").length,
      qemu: statsList.filter(x => x.type === "qemu").length,
      lxc: statsList.filter(x => x.type === "lxc").length,
      onlineNodes: nodes.length
    });

    // 4. Broadcast batch to individual users
    const byUser = new Map();
    for (const st of statsList) {
      if (!byUser.has(st.userId)) byUser.set(st.userId, []);
      byUser.get(st.userId).push(st);
    }
    for (const [uid, uList] of byUser.entries()) {
      io.to(`user_${uid}`).emit("vps:batch_stats", uList);
    }
  } catch (err) {
  } finally {
    isPollingMetrics = false;
  }
}

async function sendSingleVpsStats(id, target) {
  try {
    const s = db.prepare(`
      SELECT s.*, u.username, n.name AS node_name, n.host, n.port, n.token_id, n.token_secret_enc, n.tls_verify, n.enabled
      FROM servers s
      JOIN users u ON u.id = s.user_id
      JOIN nodes n ON n.id = s.node_id
      WHERE s.id = ? AND n.enabled = 1
    `).get(id);
    if (!s) return;

    const node = getNode(s.node_id);
    await ensureServerPveNode(s, node);
    const st = await pve(node, "GET", serverEndpoint(s, "/status/current"));
    if (!st) return;

    const cpuPct = st.cpu != null ? (st.cpu * 100).toFixed(1) : "0.0";
    const memUsed = st.mem || 0;
    const memMax = st.maxmem || 1;
    const memPct = memMax > 0 ? ((memUsed / memMax) * 100).toFixed(1) : "0.0";
    const memFree = st.freemem || Math.max(0, memMax - memUsed);

    const payload = {
      id: s.id,
      vmid: s.vmid,
      userId: s.user_id,
      name: s.name,
      type: s.type,
      nodeName: s.pve_node || s.node_name,
      status: st.status || "unknown",
      uptime: st.uptime || 0,
      cpu: st.cpu || 0,
      cpuPct,
      mem: memUsed,
      maxmem: memMax,
      memPct,
      freemem: memFree,
      diskread: st.diskread || 0,
      diskwrite: st.diskwrite || 0,
      netin: st.netin || 0,
      netout: st.netout || 0,
      diskMax: st.maxdisk || 0,
      nics: st.nics || {},
      timestamp: Math.floor(Date.now() / 1000)
    };

    if (target) {
      target.emit("vps:stats", payload);
    } else {
      io.to(`vps_${s.id}`).emit("vps:stats", payload);
    }
  } catch (err) {}
}

async function sendImmediateBatchStats(targetSocket) {
  if (!targetSocket) return;
  try {
    const nodes = db.prepare("SELECT * FROM nodes WHERE enabled = 1").all();
    if (!nodes.length) return;

    let query = `
      SELECT s.*, u.username, n.name AS node_name, n.host, n.port, n.token_id, n.token_secret_enc, n.tls_verify, n.enabled
      FROM servers s
      JOIN users u ON u.id = s.user_id
      JOIN nodes n ON n.id = s.node_id
      WHERE n.enabled = 1
    `;
    const params = [];
    if (targetSocket.userRole !== "admin" && targetSocket.userId) {
      query += " AND s.user_id = ?";
      params.push(targetSocket.userId);
    }

    const servers = db.prepare(query).all(...params);
    const pveVmMap = new Map();
    await Promise.allSettled(nodes.map(async (n) => {
      try {
        const list = await pve(n, "GET", "/cluster/resources?type=vm");
        if (Array.isArray(list)) {
          for (const item of list) pveVmMap.set(Number(item.vmid), item);
        }
      } catch (e) {}
    }));

    const stats = servers.map(s => {
      const pveVm = pveVmMap.get(Number(s.vmid)) || {};
      const status = pveVm.status || "unknown";
      const uptime = pveVm.uptime || 0;
      const cpu = pveVm.cpu || 0;
      const mem = pveVm.mem || 0;
      const maxmem = pveVm.maxmem || 1;
      return {
        id: s.id,
        vmid: s.vmid,
        userId: s.user_id,
        username: s.username,
        name: s.name,
        type: s.type,
        nodeName: s.pve_node || s.node_name,
        status,
        uptime,
        cpu,
        cpuPct: (cpu * 100).toFixed(1),
        mem,
        maxmem,
        memPct: maxmem > 0 ? ((mem / maxmem) * 100).toFixed(1) : "0.0",
        freemem: Math.max(0, maxmem - mem),
        diskread: pveVm.diskread || 0,
        diskwrite: pveVm.diskwrite || 0,
        netin: pveVm.netin || 0,
        netout: pveVm.netout || 0,
        diskMax: pveVm.maxdisk || 0,
        timestamp: Math.floor(Date.now() / 1000)
      };
    });

    targetSocket.emit("vps:batch_stats", stats);
  } catch (err) {}
}

let isPollingTasks = false;
async function pollClusterTasks() {
  if (isPollingTasks) return;
  const adminRoom = io.sockets.adapter.rooms.get("admins");
  if (!adminRoom || adminRoom.size === 0) return;
  isPollingTasks = true;
  try {
    const nodes = db.prepare("SELECT * FROM nodes WHERE enabled = 1").all();
    if (!nodes.length) return;
    let allTasks = [];
    for (const n of nodes) {
      try {
        const list = await pve(n, "GET", "/cluster/tasks");
        if (Array.isArray(list)) {
          allTasks.push(...list.map(t => ({ ...t, node_name: n.name })));
        }
      } catch (e) {}
    }
    allTasks.sort((a, b) => (b.starttime || 0) - (a.starttime || 0));
    io.to("admins").emit("tasks:update", { tasks: allTasks.slice(0, 50) });
  } catch (e) {} finally {
    isPollingTasks = false;
  }
}

function notifyVpsChanged(serverId, action = "action") {
  io.emit("vps:status_changed", { serverId, action, timestamp: Date.now() });
  setTimeout(pollLiveMetrics, 300);
  setTimeout(pollLiveMetrics, 1400);
}

function setupSocketIO() {
  io.on("connection", (socket) => {
    const req = socket.request;
    const sessionUser = req && req.session ? req.session.user : null;
    if (sessionUser && sessionUser.id) {
      socket.userId = sessionUser.id;
      socket.userRole = sessionUser.role;
      socket.join(`user_${sessionUser.id}`);
      if (sessionUser.role === "admin") socket.join("admins");
      socket.join("authenticated");
    }

    socket.on("auth:sync", (user) => {
      if (user && user.id) {
        socket.userId = user.id;
        socket.userRole = user.role;
        socket.join(`user_${user.id}`);
        if (user.role === "admin") socket.join("admins");
        socket.join("authenticated");
        sendImmediateBatchStats(socket);
      }
    });

    socket.on("subscribe_vps", ({ id }) => {
      if (id) {
        socket.join(`vps_${id}`);
        sendSingleVpsStats(Number(id), socket);
      }
    });

    socket.on("unsubscribe_vps", ({ id }) => {
      if (id) {
        socket.leave(`vps_${id}`);
      }
    });

    socket.on("request_sync", () => {
      sendImmediateBatchStats(socket);
    });
  });

  setInterval(pollLiveMetrics, 3000);
  setInterval(pollClusterTasks, 5000);
}

function askCliQuestion(rl, query) {
  return new Promise((resolve) => {
    rl.question(query, (ans) => {
      resolve(ans.trim());
    });
  });
}

async function promptAdminCli() {
  console.log("\n" + "=".repeat(62));
  console.log("       ATYRO CLOUD — INITIAL ADMINISTRATOR SETUP");
  console.log("=".repeat(62));
  console.log("No administrator account found in the database.");
  console.log("Please create the primary administrator account now:\n");

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  try {
    let username = "";
    while (!username) {
      username = await askCliQuestion(rl, "Enter Admin Username [admin]: ");
      if (!username) username = "admin";
      if (username.length < 3) {
        console.log("--> Error: Username must be at least 3 characters.");
        username = "";
      }
    }

    let email = "";
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    while (!email) {
      email = await askCliQuestion(rl, "Enter Admin Email: ");
      if (!email || !emailRegex.test(email)) {
        console.log("--> Error: Please enter a valid email address (e.g. admin@example.com).");
        email = "";
      }
    }

    let password = "";
    while (!password) {
      password = await askCliQuestion(rl, "Enter Admin Password (min 8 characters): ");
      if (!password || password.length < 8) {
        console.log("--> Error: Password must be at least 8 characters long.");
        password = "";
        continue;
      }
      const confirm = await askCliQuestion(rl, "Confirm Admin Password: ");
      if (password !== confirm) {
        console.log("--> Error: Passwords do not match. Please try again.");
        password = "";
      }
    }

    const hash = await bcrypt.hash(password, 12);
    saveAdminAccount(username, email, hash);

    console.log("\n" + "-".repeat(62));
    console.log("  Administrator account created successfully!");
    console.log(`  Username: ${username}`);
    console.log(`  Email:    ${email}`);
    console.log("-".repeat(62) + "\n");
  } finally {
    rl.close();
  }
}

function getCliArg(prefix) {
  const arg = process.argv.find(a => a.startsWith(prefix));
  return arg ? arg.split("=")[1]?.trim() : null;
}

async function bootstrapAdmin() {
  const adminCount = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin'").get().count;
  const forceSetup = process.argv.includes("--create-admin") || process.argv.includes("--reset-admin");

  if (adminCount > 0 && !forceSetup) {
    return;
  }

  // Check for CLI argument flags: --admin-user=..., --admin-email=..., --admin-pass=...
  const argUser = getCliArg("--admin-user");
  const argEmail = getCliArg("--admin-email");
  const argPass = getCliArg("--admin-pass");

  if (argUser && argEmail && argPass) {
    if (argPass.length < 8) throw new Error("Admin password must be at least 8 characters.");
    const hash = await bcrypt.hash(argPass, 12);
    saveAdminAccount(argUser, argEmail, hash);
    console.log(`Initial admin account created via CLI arguments: ${argUser} (${argEmail})`);
    return;
  }

  if (process.stdin.isTTY) {
    await promptAdminCli();
  } else {
    console.log("\n" + "!".repeat(64));
    console.log(" [SETUP REQUIRED] No administrator account found in the database!");
    console.log(` Please open http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT} in your browser to create the admin account,`);
    console.log(" or run 'node app.js' in an interactive terminal.");
    console.log("!".repeat(64) + "\n");
  }
}

setupSocketIO();

bootstrapAdmin().then(() => {
  server.listen(PORT, HOST, () => console.log(`Atyro VPS Panel listening on http://${HOST}:${PORT}`));
}).catch(err => { console.error("Bootstrap failed:", err); process.exit(1); });
