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
const WebSocket = require("ws");
const discord2fa = require("./services/discord2fa");

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
  avatar_url TEXT DEFAULT '',
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
  UNIQUE(node_id, vmid, user_id)
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

CREATE TABLE IF NOT EXISTS vm_templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('lxc','qemu')),
  description TEXT DEFAULT '',
  node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  template_source TEXT NOT NULL,
  cores INTEGER NOT NULL DEFAULT 2,
  sockets INTEGER NOT NULL DEFAULT 1,
  cpu TEXT NOT NULL DEFAULT 'host',
  numa INTEGER NOT NULL DEFAULT 0,
  memory INTEGER NOT NULL DEFAULT 2048,
  swap INTEGER NOT NULL DEFAULT 512,
  balloon INTEGER DEFAULT 0,
  disk_size INTEGER NOT NULL DEFAULT 25,
  storage TEXT NOT NULL DEFAULT 'local-lvm',
  disk_bus TEXT NOT NULL DEFAULT 'scsi',
  disk_cache TEXT NOT NULL DEFAULT 'none',
  discard INTEGER NOT NULL DEFAULT 1,
  ssd INTEGER NOT NULL DEFAULT 1,
  iothread INTEGER NOT NULL DEFAULT 1,
  bridge TEXT NOT NULL DEFAULT 'vmbr0',
  net_model TEXT NOT NULL DEFAULT 'virtio',
  netif_name TEXT NOT NULL DEFAULT 'eth0',
  vlan INTEGER DEFAULT NULL,
  firewall INTEGER NOT NULL DEFAULT 1,
  rate_limit INTEGER DEFAULT NULL,
  gateway TEXT DEFAULT '',
  cidr TEXT DEFAULT '24',
  nameservers TEXT DEFAULT '1.1.1.1 8.8.8.8',
  search_domain TEXT DEFAULT '',
  onboot INTEGER NOT NULL DEFAULT 1,
  unprivileged INTEGER NOT NULL DEFAULT 1,
  nesting INTEGER NOT NULL DEFAULT 1,
  qemu_agent INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS template_ips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  template_id INTEGER NOT NULL REFERENCES vm_templates(id) ON DELETE CASCADE,
  ip_address TEXT NOT NULL,
  cidr TEXT DEFAULT '24',
  gateway TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'available' CHECK(status IN ('available','used')),
  server_id INTEGER REFERENCES servers(id) ON DELETE SET NULL,
  assigned_vmid INTEGER,
  assigned_server_name TEXT DEFAULT '',
  assigned_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  assigned_user_name TEXT DEFAULT '',
  assigned_at TEXT,
  notes TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(template_id, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_vm_templates_type ON vm_templates(type);
CREATE INDEX IF NOT EXISTS idx_vm_templates_node ON vm_templates(node_id);
CREATE INDEX IF NOT EXISTS idx_template_ips_status ON template_ips(template_id, status);
CREATE INDEX IF NOT EXISTS idx_template_ips_server ON template_ips(server_id);

CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  key_token TEXT DEFAULT '',
  scopes TEXT NOT NULL DEFAULT '*',
  allowed_ips TEXT DEFAULT '',
  rate_limit INTEGER DEFAULT 120,
  expires_at TEXT DEFAULT NULL,
  active INTEGER DEFAULT 1,
  request_count INTEGER DEFAULT 0,
  last_used_at TEXT DEFAULT NULL,
  last_used_ip TEXT DEFAULT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_by_ip TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(active);
`);

// Dynamic column additions for api_keys
try {
  db.exec("ALTER TABLE api_keys ADD COLUMN key_token TEXT DEFAULT ''");
} catch (e) {
  if (!String(e.message).includes("duplicate column name")) console.warn("[API Key Schema Notice]:", e.message);
}

// Ensure plaintext tokens are wiped from api_keys table for security
try {
  db.prepare("UPDATE api_keys SET key_token = '' WHERE key_token IS NOT NULL AND key_token != ''").run();
} catch (e) {}

// Dynamic column additions for vm_templates if upgrading from earlier schema
const templateExtraCols = [
  "ALTER TABLE vm_templates ADD COLUMN scsihw TEXT DEFAULT 'virtio-scsi-single'",
  "ALTER TABLE vm_templates ADD COLUMN machine TEXT DEFAULT 'q35'",
  "ALTER TABLE vm_templates ADD COLUMN bios TEXT DEFAULT 'seabios'",
  "ALTER TABLE vm_templates ADD COLUMN vga TEXT DEFAULT 'std'",
  "ALTER TABLE vm_templates ADD COLUMN ci_user TEXT DEFAULT 'root'",
  "ALTER TABLE vm_templates ADD COLUMN ci_upgrade INTEGER DEFAULT 1",
  "ALTER TABLE vm_templates ADD COLUMN keyctl INTEGER DEFAULT 1",
  "ALTER TABLE vm_templates ADD COLUMN fuse INTEGER DEFAULT 0",
  "ALTER TABLE vm_templates ADD COLUMN ip6_type TEXT DEFAULT 'disabled'",
  "ALTER TABLE vm_templates ADD COLUMN ip6_gateway TEXT DEFAULT ''",
  "ALTER TABLE vm_templates ADD COLUMN start_after_create INTEGER DEFAULT 1",
  "ALTER TABLE vm_templates ADD COLUMN os_mode TEXT DEFAULT 'fixed'"
];
for (const sql of templateExtraCols) {
  try { db.exec(sql); } catch (e) { if (!String(e.message).includes("duplicate column name")) console.warn("[Template Schema Notice]:", e.message); }
}

// Dynamic column additions for servers table (Suspension & Expiry/Renew features)
const serverExtraCols = [
  "ALTER TABLE servers ADD COLUMN is_suspended INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE servers ADD COLUMN suspended_at TEXT DEFAULT NULL",
  "ALTER TABLE servers ADD COLUMN suspend_reason TEXT DEFAULT ''",
  "ALTER TABLE servers ADD COLUMN expires_at TEXT DEFAULT NULL",
  "ALTER TABLE servers ADD COLUMN duration_days INTEGER DEFAULT 0",
  "ALTER TABLE servers ADD COLUMN auto_renew INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE servers ADD COLUMN expired_at TEXT DEFAULT NULL",
  "ALTER TABLE servers ADD COLUMN last_renewed_at TEXT DEFAULT NULL"
];
for (const sql of serverExtraCols) {
  try { db.exec(sql); } catch (e) { if (!String(e.message).includes("duplicate column name")) console.warn("[Server Schema Notice]:", e.message); }
}

try { db.exec("CREATE INDEX IF NOT EXISTS idx_servers_expires ON servers(expires_at)"); } catch (e) {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_servers_suspended ON servers(is_suspended)"); } catch (e) {}

// Dynamic column additions for vm_templates (Default duration)
try {
  db.exec("ALTER TABLE vm_templates ADD COLUMN default_duration_days INTEGER DEFAULT 0");
} catch (e) {
  if (!String(e.message).includes("duplicate column name")) console.warn("[Template Duration Schema Notice]:", e.message);
}

// Centralized User Identity Mapping & Permanent ID Migrations
try {
  db.exec("ALTER TABLE users ADD COLUMN uuid TEXT");
} catch (e) {
  if (!String(e.message).includes("duplicate column name")) console.warn("[Users UUID Schema Notice]:", e.message);
}
try {
  db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid)");
} catch (e) {}

// Backfill any existing users without permanent UUID
try {
  const usersWithoutUuid = db.prepare("SELECT id FROM users WHERE uuid IS NULL OR uuid = ''").all();
  const updateUuid = db.prepare("UPDATE users SET uuid = ? WHERE id = ?");
  for (const u of usersWithoutUuid) {
    updateUuid.run("usr_" + crypto.randomUUID(), u.id);
  }
} catch (e) {
  console.warn("[Users UUID Backfill Notice]:", e.message);
}

// Two-Factor Authentication & Discord Integration Schema Migrations
const user2faCols = [
  "ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0",
  "ALTER TABLE users ADD COLUMN two_factor_backup_codes TEXT DEFAULT '[]'",
  "ALTER TABLE users ADD COLUMN discord_id TEXT DEFAULT NULL",
  "ALTER TABLE users ADD COLUMN discord_username TEXT DEFAULT NULL",
  "ALTER TABLE users ADD COLUMN discord_avatar TEXT DEFAULT NULL"
];
for (const sql of user2faCols) {
  try { db.exec(sql); } catch (e) {
    if (!String(e.message).includes("duplicate column name")) console.warn("[Users 2FA Schema Notice]:", e.message);
  }
}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_users_discord_id ON users(discord_id)"); } catch (e) {}

// Two-Factor Challenges Table for Time-limited & Single-use OTPs
db.exec(`
CREATE TABLE IF NOT EXISTS two_factor_challenges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  challenge_token TEXT UNIQUE NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL DEFAULT 'login',
  otp_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  attempts INTEGER DEFAULT 0,
  resend_available_at TEXT NOT NULL,
  metadata TEXT DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_2fa_token ON two_factor_challenges(challenge_token);
CREATE INDEX IF NOT EXISTS idx_2fa_user ON two_factor_challenges(user_id);
`);

// User Identities mapping table (Centralized Identity Mapping)
db.exec(`
CREATE TABLE IF NOT EXISTS user_identities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK(provider IN ('discord', 'github', 'google', 'custom')),
  provider_user_id TEXT NOT NULL,
  provider_username TEXT DEFAULT '',
  provider_email TEXT DEFAULT '',
  provider_avatar TEXT DEFAULT '',
  metadata TEXT DEFAULT '{}',
  linked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  linked_by_ip TEXT DEFAULT '',
  UNIQUE(provider, provider_user_id)
);
CREATE INDEX IF NOT EXISTS idx_user_identities_lookup ON user_identities(provider, provider_user_id);
CREATE INDEX IF NOT EXISTS idx_user_identities_user ON user_identities(user_id);

CREATE TABLE IF NOT EXISTS identity_link_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL DEFAULT 'discord',
  provider_user_id TEXT DEFAULT '',
  provider_username TEXT DEFAULT '',
  provider_email TEXT DEFAULT '',
  provider_avatar TEXT DEFAULT '',
  code TEXT NOT NULL UNIQUE,
  initiated_by TEXT NOT NULL DEFAULT 'panel' CHECK(initiated_by IN ('panel', 'bot')),
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_link_codes_code ON identity_link_codes(code);
CREATE INDEX IF NOT EXISTS idx_link_codes_user ON identity_link_codes(user_id);
`);

// Auto-migrate any existing discord_* placeholder usernames into user_identities if not already mapped
try {
  const discordUsers = db.prepare("SELECT id, username, email FROM users WHERE username LIKE 'discord_%'").all();
  const insertIdent = db.prepare(`
    INSERT OR IGNORE INTO user_identities (user_id, provider, provider_user_id, provider_username, metadata)
    VALUES (?, 'discord', ?, ?, ?)
  `);
  for (const du of discordUsers) {
    const rawDiscId = du.username.replace("discord_", "");
    if (/^\d{15,22}$/.test(rawDiscId)) {
      insertIdent.run(du.id, rawDiscId, `DiscordUser#${rawDiscId.slice(-4)}`, JSON.stringify({ auto_migrated: true }));
    }
  }
} catch (e) {}

// Seed default branding into settings table if not present (First-time bootstrap)
try {
  const initialDefaultSettings = [
    ["site_name", "ALPM"],
    ["site_description", "High-Performance Cloud & VPS Infrastructure Management"],
    ["site_icon", "https://i.imgur.com/G93UzrB.png"],
    ["site_favicon", "https://i.imgur.com/G93UzrB.png"],
    ["og_image", ""],
    ["seo_description", "ALPM Proxmox VE Virtual Machine & Container Management Panel"],
    ["allow_registration", "0"],
    ["site_bg_type", "none"],
    ["site_bg_url", ""],
    ["site_bg_opacity", "55"],
    ["site_bg_blur", "0"]
  ];
  const seedStmt = db.prepare("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)");
  for (const [k, v] of initialDefaultSettings) {
    seedStmt.run(k, v);
  }
} catch (e) {}

// Auto-seed starter templates if vm_templates table is empty
try {
  const count = db.prepare("SELECT COUNT(*) as c FROM vm_templates").get();
  if (count && count.c === 0) {
    const node = db.prepare("SELECT id FROM nodes WHERE enabled = 1 ORDER BY id ASC LIMIT 1").get();
    if (node) {
      const insertTmpl = db.prepare(`
        INSERT INTO vm_templates (
          name, type, description, node_id, template_source,
          cores, sockets, cpu, memory, swap, balloon, disk_size, storage,
          bridge, net_model, netif_name, gateway, cidr, nameservers,
          onboot, unprivileged, nesting, qemu_agent
        ) VALUES (
          @name, @type, @description, @node_id, @template_source,
          @cores, @sockets, @cpu, @memory, @swap, @balloon, @disk_size, @storage,
          @bridge, @net_model, @netif_name, @gateway, @cidr, @nameservers,
          @onboot, @unprivileged, @nesting, @qemu_agent
        )
      `);
      const insertIp = db.prepare(`
        INSERT OR IGNORE INTO template_ips (template_id, ip_address, cidr, gateway, status)
        VALUES (?, ?, ?, ?, 'available')
      `);

      // 1. LXC Starter Template
      const lxcTmpl = insertTmpl.run({
        name: "Ubuntu 24.04 Standard LXC",
        type: "lxc",
        description: "Optimized lightweight Linux Container with Ubuntu 24.04 LTS and dedicated IPv4 pool.",
        node_id: node.id,
        template_source: "local:vztmpl/ubuntu-24.04-standard_24.04-2_amd64.tar.zst",
        cores: 2, sockets: 1, cpu: "host", memory: 2048, swap: 512, balloon: 0,
        disk_size: 20, storage: "local-lvm", bridge: "vmbr0", net_model: "virtio", netif_name: "eth0",
        gateway: "192.168.1.1", cidr: "24", nameservers: "1.1.1.1 8.8.8.8",
        onboot: 1, unprivileged: 1, nesting: 1, qemu_agent: 1
      });
      const lxcId = lxcTmpl.lastInsertRowid;
      ["192.168.1.110", "192.168.1.111", "192.168.1.112", "192.168.1.113", "192.168.1.114"].forEach(ip => {
        insertIp.run(lxcId, ip, "24", "192.168.1.1");
      });

      // 2. QEMU Starter Template
      const qemuTmpl = insertTmpl.run({
        name: "Ubuntu 24.04 Cloud QEMU",
        type: "qemu",
        description: "High-performance full KVM virtualization with Cloud-Init auto-configuration and dedicated IPv4 pool.",
        node_id: node.id,
        template_source: "1003",
        cores: 2, sockets: 1, cpu: "host", memory: 2048, swap: 0, balloon: 1024,
        disk_size: 30, storage: "local-lvm", bridge: "vmbr0", net_model: "virtio", netif_name: "eth0",
        gateway: "192.168.1.1", cidr: "24", nameservers: "1.1.1.1 8.8.8.8",
        onboot: 1, unprivileged: 1, nesting: 1, qemu_agent: 1
      });
      const qemuId = qemuTmpl.lastInsertRowid;
      ["192.168.1.120", "192.168.1.121", "192.168.1.122", "192.168.1.123", "192.168.1.124"].forEach(ip => {
        insertIp.run(qemuId, ip, "24", "192.168.1.1");
      });
      console.log("[Templates] Seeded 2 starter VM templates with dedicated IP pools.");
    }
  }
} catch (seedErr) {
  console.warn("[Templates Seed Notice]:", seedErr.message);
}

// Migration: Allow assigning one VPS to multiple users (UNIQUE on node_id, vmid, user_id)
try {
  const tbl = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='servers'").get();
  if (tbl && tbl.sql && (tbl.sql.includes("UNIQUE(node_id, vmid)") || tbl.sql.includes("UNIQUE(node_id,vmid)") || tbl.sql.includes("UNIQUE (node_id, vmid)"))) {
    db.pragma("foreign_keys = OFF");
    db.transaction(() => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS servers_new (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
          vmid INTEGER NOT NULL,
          type TEXT NOT NULL CHECK(type IN ('qemu','lxc')),
          pve_node TEXT NOT NULL DEFAULT '',
          name TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(node_id, vmid, user_id)
        );
        INSERT INTO servers_new (id, user_id, node_id, vmid, type, pve_node, name, created_at)
          SELECT id, user_id, node_id, vmid, type, pve_node, name, created_at FROM servers;
        DROP TABLE servers;
        ALTER TABLE servers_new RENAME TO servers;
        CREATE INDEX IF NOT EXISTS idx_servers_user ON servers(user_id);
      `);
    })();
    db.pragma("foreign_keys = ON");
  }
} catch (migErr) {
  console.warn("[Migration Notice] Servers table constraint check:", migErr.message);
}

const UPLOADS_DIR = path.resolve("./data/uploads");
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Lightweight schema migration for installations created before pve_node was added.
try { db.exec("ALTER TABLE servers ADD COLUMN pve_node TEXT NOT NULL DEFAULT ''"); } catch (e) { if (!String(e.message).includes("duplicate column name")) throw e; }
try { db.exec("ALTER TABLE users ADD COLUMN avatar_url TEXT DEFAULT ''"); } catch (e) { if (!String(e.message).includes("duplicate column name")) throw e; }

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
app.set("trust proxy", process.env.TRUST_PROXY ? Number(process.env.TRUST_PROXY) : 1);

// ==========================================
// ZERO-TRUST SENSITIVE FILE & PATH SHIELD
// ==========================================
// Strictly blocks any direct request, path traversal, or download attempt for
// .env, sqlite/db databases, source files, backups, logs, archives, and internal directories.
app.use((req, res, next) => {
  let decodedPath = "";
  try {
    decodedPath = decodeURIComponent(req.path);
  } catch {
    return res.status(400).json({ error: "Malformed request URI." });
  }

  const normalized = path.normalize(decodedPath).replace(/\\/g, "/");

  // 1. Directory Traversal and Null Byte Protection
  if (req.path.includes("..") || decodedPath.includes("..") || normalized.includes("..") || req.path.includes("\0") || decodedPath.includes("\0")) {
    if (typeof audit === "function") {
      try { audit(req.session?.user?.id || null, "security.path_traversal_blocked", `Blocked directory traversal: ${req.path}`, req); } catch {}
    }
    return res.status(403).json({ error: "Access Denied: Path traversal is strictly prohibited." });
  }

  // 2. Sensitive File Extensions (raw DBs, backups, code, configs, archives)
  const forbiddenExtRegex = /\.(env|sqlite|sqlite3|db|db-shm|db-wal|sql|bak|backup|zip|tar|gz|rar|7z|log|lock|js|mjs|cjs|ts|jsx|tsx|json|yml|yaml|conf|ini|sh|bat|cmd|ps1)$/i;

  // 3. Sensitive Directory / File Names
  const forbiddenNamesRegex = /^\/(\.env|\.git|\.github|\.vscode|\.idea|data|services|scratch|node_modules|panel\.db|vps\.db|sessions\.sqlite|package\.json|package-lock\.json|app\.js|backup1\.zip|Proxmox Panel\.zip)(\/.*)?$/i;

  // Explicit allowed public static assets:
  const isXtermAsset = /^\/(xterm|xterm-addon-fit)\/(css|lib)\/[a-zA-Z0-9_\-.]+\.(css|js|map)$/i.test(normalized);
  const isAllowedUpload = /^\/uploads\/(avatars\/|backgrounds\/)?[a-zA-Z0-9_\-.]+\.(png|jpg|jpeg|gif|webp|svg|ico|mp4|webm)$/i.test(normalized);
  const isApiRoute = normalized.startsWith("/api/");
  const isFavicon = normalized === "/favicon.ico";
  const isRootOrHtml = normalized === "/" || normalized === "/index.html";

  if (!isXtermAsset && !isAllowedUpload && !isApiRoute && !isFavicon && !isRootOrHtml) {
    if (forbiddenExtRegex.test(normalized) || forbiddenNamesRegex.test(normalized) || normalized.startsWith("/.")) {
      if (typeof audit === "function") {
        try { audit(req.session?.user?.id || null, "security.sensitive_file_blocked", `Blocked request to sensitive file/dir: ${req.path}`, req); } catch {}
      }
      return res.status(403).json({ error: "Access Denied: Requested resource is strictly protected and cannot be downloaded or read." });
    }
  }

  // Strict check on /uploads/ paths: only allowed media extensions
  if (normalized.startsWith("/uploads/")) {
    const isSafeUpload = /^\/uploads\/(avatars\/|backgrounds\/)?[a-zA-Z0-9_\-.]+\.(png|jpg|jpeg|gif|webp|svg|ico|mp4|webm)$/i.test(normalized);
    if (!isSafeUpload) {
      return res.status(403).json({ error: "Access Denied: Upload resource is restricted." });
    }
  }

  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://ajax.cloudflare.com", "https://static.cloudflareinsights.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "blob:", "https:", "http:"],
      mediaSrc: ["'self'", "data:", "blob:", "https:", "http:"],
      connectSrc: ["'self'", "ws:", "wss:", "https:", "http:", "https://cloudflareinsights.com"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: false, limit: "15mb" }));
app.use("/uploads", express.static(UPLOADS_DIR, {
  dotfiles: "deny",
  index: false,
  fallthrough: false,
  setHeaders: (res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "public, max-age=86400");
  }
}));
const xtermStaticOptions = {
  setHeaders: (res) => {
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }
};
app.use("/xterm/css", express.static(path.join(__dirname, "node_modules", "xterm", "css"), xtermStaticOptions));
app.use("/xterm/lib", express.static(path.join(__dirname, "node_modules", "xterm", "lib"), xtermStaticOptions));
app.use("/xterm-addon-fit/lib", express.static(path.join(__dirname, "node_modules", "xterm-addon-fit", "lib"), xtermStaticOptions));

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

function extractApiKey(req) {
  const authHeader = req.get("authorization");
  if (authHeader && authHeader.toLowerCase().startsWith("bearer ")) {
    return authHeader.slice(7).trim();
  }
  const xApiKey = req.get("x-api-key");
  if (xApiKey) return xApiKey.trim();
  if (req.query && req.query.api_key) return String(req.query.api_key).trim();
  return null;
}

function ipInCidr(clientIp, cidr) {
  if (!cidr || !clientIp) return false;
  cidr = cidr.trim();
  clientIp = clientIp.trim();
  if (cidr === "*" || cidr === "0.0.0.0/0" || cidr === "::/0") return true;
  if (clientIp.startsWith("::ffff:")) clientIp = clientIp.replace("::ffff:", "");
  if (!cidr.includes("/")) {
    return clientIp === cidr;
  }
  const [rangeIp, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix)) return false;
  if (rangeIp.includes(".") && clientIp.includes(".")) {
    const ip2int = ip => ip.split(".").reduce((acc, oct) => ((acc << 8) + parseInt(oct, 10)) >>> 0, 0);
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return (ip2int(clientIp) & mask) === (ip2int(rangeIp) & mask);
  }
  return clientIp === rangeIp;
}

function checkIpWhitelist(clientIp, allowedIpsStr) {
  if (!allowedIpsStr || !allowedIpsStr.trim()) return true;
  const rawEntries = allowedIpsStr.split(/[\r\n,;\s]+/).map(s => s.trim()).filter(Boolean);
  if (rawEntries.length === 0 || rawEntries.includes("*")) return true;
  
  let normalizedIp = clientIp || "";
  if (normalizedIp.startsWith("::ffff:")) normalizedIp = normalizedIp.replace("::ffff:", "");
  if (normalizedIp === "::1") normalizedIp = "127.0.0.1";
  
  for (const entry of rawEntries) {
    let cleanEntry = entry;
    if (cleanEntry === "localhost" || cleanEntry === "::1") cleanEntry = "127.0.0.1";
    if (ipInCidr(normalizedIp, cleanEntry)) return true;
  }
  return false;
}

const serverLiveStatsMap = new Map();
const apiKeyRateLimits = new Map();
function checkApiKeyRateLimit(keyId, limitPerMin = 120) {
  const now = Date.now();
  let record = apiKeyRateLimits.get(keyId);
  if (!record || now >= record.resetAt) {
    record = { count: 1, resetAt: now + 60000 };
    apiKeyRateLimits.set(keyId, record);
    return { ok: true, remaining: Math.max(0, limitPerMin - 1), resetInSeconds: 60 };
  }
  record.count++;
  const remaining = Math.max(0, limitPerMin - record.count);
  const resetInSeconds = Math.ceil((record.resetAt - now) / 1000);
  if (record.count > limitPerMin) {
    return { ok: false, remaining: 0, resetInSeconds };
  }
  return { ok: true, remaining, resetInSeconds };
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of apiKeyRateLimits.entries()) {
    if (now >= v.resetAt) apiKeyRateLimits.delete(k);
  }
}, 5 * 60 * 1000);

function checkApiKeyScope(req, allowedScopesStr) {
  if (!allowedScopesStr || allowedScopesStr === "*" || allowedScopesStr.trim() === "") return true;
  const scopes = allowedScopesStr.split(",").map(s => s.trim().toLowerCase());
  if (scopes.includes("*")) return true;

  const path = (req.originalUrl || req.path || "").toLowerCase();
  const method = req.method.toUpperCase();

  // Servers / VPS actions & Application Servers API
  if (path.includes("/servers") || path.includes("/dashboard") || path.includes("/vps") || path.includes("/application/servers")) {
    if (scopes.includes("vps:*") || scopes.includes("servers:*") || scopes.includes("*")) return true;
    if (method === "GET" && (scopes.includes("vps:read") || scopes.includes("servers:read"))) return true;
    if ((path.includes("/action") || path.includes("/power")) && (scopes.includes("vps:power") || scopes.includes("vps:write") || scopes.includes("vps:*"))) return true;
    if ((path.includes("/suspend") || path.includes("/unsuspend") || path.includes("/toggle-suspend") || path.includes("/renew")) && (scopes.includes("vps:power") || scopes.includes("vps:write") || scopes.includes("vps:*"))) return true;
    if (path.includes("/reinstall") && (scopes.includes("vps:reinstall") || scopes.includes("vps:write"))) return true;
    if (["POST", "PUT", "DELETE", "PATCH"].includes(method) && scopes.includes("vps:write")) return true;
  }

  // VM Templates
  if (path.includes("/admin/templates")) {
    if (scopes.includes("templates:*")) return true;
    if (path.includes("/deploy") && (scopes.includes("templates:deploy") || scopes.includes("templates:write"))) return true;
    if (method === "GET" && (scopes.includes("templates:read") || scopes.includes("templates:*"))) return true;
    if (["POST", "PUT", "DELETE"].includes(method) && scopes.includes("templates:write")) return true;
  }

  // Nodes
  if (path.includes("/admin/nodes") || path.includes("/admin/proxmox")) {
    if (scopes.includes("nodes:*")) return true;
    if (method === "GET" && (scopes.includes("nodes:read") || scopes.includes("nodes:*"))) return true;
    if (["POST", "PUT", "DELETE"].includes(method) && scopes.includes("nodes:write")) return true;
  }

  // Users & Application Users API (Pterodactyl-compatible, Discord Bot & Billing)
  if (path.includes("/admin/users") || path.includes("/users") || path.includes("/application/users")) {
    if (scopes.includes("users:*") || scopes.includes("*")) return true;
    if (method === "GET" && (scopes.includes("users:read") || scopes.includes("users:manage") || scopes.includes("vps:read"))) return true;
    if (["POST", "PUT", "DELETE"].includes(method) && (scopes.includes("users:write") || scopes.includes("users:manage"))) return true;
  }

  // Logs & Tasks
  if (path.includes("/admin/logs") || path.includes("/admin/tasks") || path.includes("/admin/overview")) {
    if (scopes.includes("logs:*") || scopes.includes("logs:read") || scopes.includes("monitoring:read")) return true;
  }

  // Settings
  if (path.includes("/admin/settings")) {
    if (scopes.includes("settings:*")) return true;
    if (method === "GET" && scopes.includes("settings:read")) return true;
  }

  // API Keys management itself
  if (path.includes("/admin/api-keys")) {
    if (scopes.includes("keys:*") || scopes.includes("keys:manage")) return true;
  }

  // Centralized Identity Mapping scopes (Discord, Permanent ID, Linking)
  if (path.includes("/identity")) {
    if (scopes.includes("identity:*") || scopes.includes("*")) return true;
    if (method === "GET" && (scopes.includes("identity:read") || scopes.includes("users:read") || scopes.includes("users:*"))) return true;
    if (["POST", "PUT", "DELETE", "PATCH"].includes(method) && (scopes.includes("identity:write") || scopes.includes("users:manage") || scopes.includes("users:*"))) return true;
  }

  return false;
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many login attempts from this IP address. Please wait 15 minutes before retrying." }
});

const twoFactorLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 15,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many 2FA verification attempts from this IP address. Please wait 10 minutes before retrying." }
});

const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many password reset requests from this IP address. Please wait 15 minutes before retrying." }
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 180,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  skip: (req) => Boolean(extractApiKey(req))
});
app.use("/api", apiLimiter);

function audit(userId, action, detail, req) {
  let ip = (req?.ip || "").trim();
  let fullDetail = detail ? String(detail).slice(0, 500) : null;
  if (req?.apiKey) {
    fullDetail = `[API: ${req.apiKey.name}] ${fullDetail || ""}`.trim().slice(0, 500);
  }
  db.prepare("INSERT INTO audit_logs(user_id,action,detail,ip) VALUES(?,?,?,?)")
    .run(userId || null, action, fullDetail, ip);
}

function requireAuth(req, res, next) {
  if (req.apiKey && req.user) return next();
  if (!req.session || !req.session.user) return res.status(401).json({ error: "Authentication required." });
  const current = db.prepare("SELECT * FROM users WHERE id=?").get(req.session.user.id);
  if (!current || !current.active) {
    if (req.session) req.session.destroy(() => {});
    return res.status(401).json({ error: "Account unavailable." });
  }
  if (!req.session.csrf) {
    req.session.csrf = crypto.randomBytes(32).toString("hex");
  }
  req.user = current;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") return res.status(403).json({ error: "Administrator permission required." });
  next();
}

function csrf(req, res, next) {
  if (req.apiKey) return next();
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const supplied = req.get("x-csrf-token");
  if (!req.session || !req.session.csrf || !supplied || supplied.length !== req.session.csrf.length || !crypto.timingSafeEqual(Buffer.from(req.session.csrf), Buffer.from(supplied))) {
    return res.status(403).json({ error: "Invalid CSRF token. Refresh and try again." });
  }
  next();
}

app.use("/api", async (req, res, next) => {
  // Only public endpoints bypass authentication. Note: /setup/status is public, but setup creation is strictly guarded.
  const publicApiPaths = [
    "/auth/login",
    "/auth/register",
    "/health",
    "/settings",
    "/setup/status",
    "/auth/2fa/verify",
    "/auth/2fa/resend",
    "/auth/forgot-password/request",
    "/auth/forgot-password/verify-reset",
    "/auth/discord/callback"
  ];
  if (publicApiPaths.includes(req.path)) {
    return next();
  }

  const rawKey = extractApiKey(req);
  if (rawKey) {
    if (typeof rawKey !== "string" || !rawKey.startsWith("atyro_live_") || rawKey.length < 40) {
      return res.status(401).json({ error: "Invalid API key format." });
    }

    const keyHash = crypto.createHash("sha256").update(rawKey.trim()).digest("hex");
    const key = db.prepare(`
      SELECT k.*, u.username, u.email, u.role, u.active AS user_active
      FROM api_keys k
      JOIN users u ON k.user_id = u.id
      WHERE k.key_hash = ?
    `).get(keyHash);

    if (!key) {
      return res.status(401).json({ error: "Invalid API key." });
    }

    // Constant-time comparison against timing attacks
    const calcBuf = Buffer.from(keyHash, "hex");
    const dbBuf = Buffer.from(key.key_hash, "hex");
    if (calcBuf.length !== dbBuf.length || !crypto.timingSafeEqual(calcBuf, dbBuf)) {
      return res.status(401).json({ error: "Invalid API key." });
    }

    if (!key.active) {
      return res.status(403).json({ error: "API key is disabled or revoked." });
    }
    if (!key.user_active) {
      return res.status(403).json({ error: "Associated user account is disabled." });
    }
    if (key.expires_at) {
      const exp = new Date(key.expires_at).getTime();
      if (!isNaN(exp) && exp < Date.now()) {
        return res.status(403).json({ error: `API key expired on ${key.expires_at}.` });
      }
    }

    const clientIp = (req.headers["x-forwarded-for"]?.split(",")[0] || req.ip || req.socket.remoteAddress || "").trim();

    if (key.allowed_ips && !checkIpWhitelist(clientIp, key.allowed_ips)) {
      return res.status(403).json({
        error: `Access denied: IP ${clientIp} is not authorized by this API key's whitelist policy.`
      });
    }

    const rateCheck = checkApiKeyRateLimit(key.id, key.rate_limit || 120);
    res.set("X-RateLimit-Limit", String(key.rate_limit || 120));
    res.set("X-RateLimit-Remaining", String(rateCheck.remaining));
    res.set("X-RateLimit-Reset", String(rateCheck.resetInSeconds));

    if (!rateCheck.ok) {
      res.set("Retry-After", String(rateCheck.resetInSeconds));
      return res.status(429).json({
        error: `API rate limit exceeded (${key.rate_limit || 120} req/min). Try again in ${rateCheck.resetInSeconds}s.`,
        retry_after: rateCheck.resetInSeconds
      });
    }

    if (!checkApiKeyScope(req, key.scopes)) {
      return res.status(403).json({
        error: `Insufficient API key scope for ${req.method} ${req.path}. Allowed scopes: ${key.scopes}`
      });
    }

    try {
      db.prepare(`
        UPDATE api_keys
        SET last_used_at = CURRENT_TIMESTAMP,
            last_used_ip = ?,
            request_count = request_count + 1
        WHERE id = ?
      `).run(clientIp, key.id);
    } catch {}

    req.apiKey = key;
    req.user = {
      id: key.user_id,
      username: key.username,
      email: key.email,
      role: key.role,
      active: !!key.user_active
    };

    return next();
  }

  return requireAuth(req, res, () => csrf(req, res, next));
});

function safeUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    uuid: row.uuid || null,
    permanent_id: row.uuid || null,
    username: row.username,
    email: row.email,
    role: row.role,
    active: !!row.active,
    avatar_url: row.avatar_url || "",
    two_factor_enabled: Boolean(row.two_factor_enabled),
    discord_id: row.discord_id || null,
    discord_username: row.discord_username || null,
    discord_avatar: row.discord_avatar || null,
    created_at: row.created_at
  };
}
function validateString(value, label, max = 100) {
  if (typeof value !== "string" || !value.trim() || value.length > max) {
    const e = new Error(`${label} is required and must be at most ${max} characters.`);
    e.status = 400;
    throw e;
  }
  return value.trim();
}
function parseIpEntries(raw, defaultCidr = "24", defaultGateway = "") {
  if (!raw) return [];
  const entries = [];
  const seen = new Set();
  const rawItems = Array.isArray(raw) ? raw : String(raw).split(/[\r\n,;\s]+/);
  for (let item of rawItems) {
    if (!item || typeof item !== "string") continue;
    item = item.trim();
    if (!item) continue;
    
    let ip = item;
    let cidr = defaultCidr || "24";
    let gw = defaultGateway || "";
    
    if (ip.includes("/")) {
      const parts = ip.split("/");
      ip = parts[0].trim();
      cidr = parts[1].trim() || cidr;
    }
    
    const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
    const isIpv6 = ip.includes(":") && /^[0-9a-fA-F:]+$/.test(ip);
    if (!isIpv4 && !isIpv6) continue;
    
    if (seen.has(ip)) continue;
    seen.add(ip);
    
    entries.push({ ip, cidr, gateway: gw });
  }
  return entries;
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

// In-memory real-time node health tracker
const nodeHealthState = new Map(); // nodeId -> { id, name, host, status, reason, message, updatedAt }

function markNodeOffline(node, reason, message) {
  if (!node || !node.id) return;
  const now = Date.now();
  const prev = nodeHealthState.get(node.id);
  nodeHealthState.set(node.id, {
    id: node.id,
    name: node.name,
    host: node.host,
    status: "offline",
    reason,
    message,
    updatedAt: now,
    broadcastAt: prev?.broadcastAt || 0
  });

  // Broadcast via WebSocket ONLY when transitioning to offline state (not repeatedly on every poll)
  if (!prev || prev.status !== "offline") {
    nodeHealthState.get(node.id).broadcastAt = now;
    if (typeof io !== "undefined" && io) {
      io.emit("node_health_alert", {
        node_id: node.id,
        node_name: node.name,
        node_host: node.host,
        status: "offline",
        reason,
        message,
        timestamp: new Date().toISOString()
      });
    }
  }
}

function markNodeOnline(node) {
  if (!node || !node.id) return;
  const prev = nodeHealthState.get(node.id);
  if (prev && prev.status === "offline") {
    nodeHealthState.set(node.id, {
      id: node.id,
      name: node.name,
      host: node.host,
      status: "online",
      reason: null,
      message: `Proxmox Node "${node.name}" is back online.`,
      updatedAt: Date.now()
    });
    if (typeof io !== "undefined" && io) {
      io.emit("node_health_alert", {
        node_id: node.id,
        node_name: node.name,
        node_host: node.host,
        status: "online",
        message: `Proxmox Node "${node.name}" is back online.`,
        timestamp: new Date().toISOString()
      });
    }
  }
}

async function pve(node, method, endpoint, data) {
  try {
    const response = await nodeClient(node).request({ method, url: endpoint, data });
    markNodeOnline(node);
    return response.data && response.data.data !== undefined ? response.data.data : response.data;
  } catch (err) {
    const detail = err.response?.data?.errors || err.response?.data?.message || err.message;
    const detailStr = typeof detail === "string" ? detail : JSON.stringify(detail);

    const isTimeout = err.code === "ECONNABORTED" || err.code === "ETIMEDOUT" || detailStr.toLowerCase().includes("timeout");
    const isConnRefused = err.code === "ECONNREFUSED" || err.code === "EHOSTUNREACH" || err.code === "ENETUNREACH" || err.code === "ENOTFOUND" || err.code === "ECONNRESET";
    const nodeName = node?.name || node?.host || "Proxmox Node";

    if (isTimeout || isConnRefused || err.response?.status === 504) {
      const reason = isTimeout ? "timeout" : "offline";
      const niceMsg = isTimeout
        ? `Proxmox Node "${nodeName}" timed out (${node.host || 'node'} not responding within 15s).`
        : `Proxmox Node "${nodeName}" is offline or unreachable (${node.host || 'host'}).`;

      markNodeOffline(node, reason, niceMsg);

      const e = new Error(niceMsg);
      e.status = 504;
      e.isNodeDown = true;
      e.nodeName = nodeName;
      e.nodeHost = node.host;
      e.nodeId = node.id;
      e.reason = reason;
      e.originalMessage = detailStr;
      throw e;
    }

    const e = new Error(`Proxmox API error: ${detailStr}`);
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
function computeServerExpiry(durationDays, explicitExpiresAt, defaultDays = 0) {
  if (explicitExpiresAt) {
    const d = new Date(explicitExpiresAt);
    if (!isNaN(d.getTime())) {
      const days = Math.max(0, Math.round((d.getTime() - Date.now()) / 86400000));
      return { expires_at: d.toISOString(), duration_days: days };
    }
  }
  const days = durationDays !== undefined && durationDays !== null ? Number(durationDays) : Number(defaultDays);
  if (!days || isNaN(days) || days <= 0) {
    return { expires_at: null, duration_days: 0 };
  }
  const exp = new Date(Date.now() + days * 86400000);
  return { expires_at: exp.toISOString(), duration_days: days };
}

function enrichServerExpiry(server) {
  if (!server) return server;
  const now = Date.now();
  let isExpired = false;
  let daysLeft = null;
  let hoursLeft = null;
  let expiryStatus = "lifetime"; // lifetime, active, expiring_soon, expired

  if (server.expires_at) {
    const expTime = new Date(server.expires_at).getTime();
    if (!isNaN(expTime)) {
      const diffMs = expTime - now;
      daysLeft = Math.ceil(diffMs / 86400000);
      hoursLeft = Math.ceil(diffMs / 3600000);
      if (diffMs <= 0) {
        isExpired = true;
        expiryStatus = "expired";
        daysLeft = 0;
        hoursLeft = 0;
      } else if (daysLeft <= 3) {
        expiryStatus = "expiring_soon";
      } else {
        expiryStatus = "active";
      }
    }
  }

  return {
    ...server,
    is_expired: (isExpired || server.expired_at) ? 1 : 0,
    days_left: daysLeft,
    hours_left: hoursLeft,
    expiry_status: expiryStatus
  };
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

const DEFAULT_SITE_LOGO = "https://i.imgur.com/G93UzrB.png";

const defaultSettings = {
  site_name: "ALPM",
  site_description: "Next-Generation Proxmox VE VPS Cloud Management Platform",
  site_icon: DEFAULT_SITE_LOGO,
  site_favicon: DEFAULT_SITE_LOGO,
  og_image: "",
  seo_description: "ALPM Proxmox VE Virtual Machine & Container Management Panel",
  allow_registration: "0",
  site_bg_type: "none",
  site_bg_url: "",
  site_bg_opacity: "55",
  site_bg_blur: "0"
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
    res.allow_registration = res.allow_registration !== undefined ? String(res.allow_registration) : "0";
    res.site_bg_type = res.site_bg_type || "none";
    res.site_bg_url = res.site_bg_url || "";
    res.site_bg_opacity = res.site_bg_opacity !== undefined ? String(res.site_bg_opacity) : "55";
    res.site_bg_blur = res.site_bg_blur !== undefined ? String(res.site_bg_blur) : "0";
    return res;
  } catch {
    const def = { ...defaultSettings };
    def.site_icon_url = def.site_icon || "";
    def.site_favicon_url = def.site_favicon || "";
    def.og_image_url = def.og_image || "";
    def.allow_registration = def.allow_registration !== undefined ? String(def.allow_registration) : "0";
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

function getPublicSettings() {
  const all = getSettings();
  const icon = all.site_icon !== undefined ? all.site_icon : DEFAULT_SITE_LOGO;
  const fav = all.site_favicon !== undefined ? all.site_favicon : (icon || DEFAULT_SITE_LOGO);
  return {
    site_name: all.site_name || "ALPM",
    site_description: all.site_description || "",
    seo_description: all.seo_description || "",
    site_icon: icon,
    site_icon_url: all.site_icon_url || icon,
    site_favicon: fav,
    site_favicon_url: all.site_favicon_url || fav,
    og_image: all.og_image || "",
    og_image_url: all.og_image_url || "",
    allow_registration: all.allow_registration || "0",
    site_bg_type: all.site_bg_type || "none",
    site_bg_url: all.site_bg_url || "",
    site_bg_opacity: all.site_bg_opacity || "55",
    site_bg_blur: all.site_bg_blur || "0"
  };
}

app.get("/api/settings", (req, res) => {
  res.json({ settings: getPublicSettings() });
});

app.get("/api/health", (req, res) => res.json({ ok: true, name: "Atyro VPS Panel API" }));

const SETUP_LOCK_FILE = path.resolve("./data/.setup_completed");

function isSetupLocked() {
  if (fs.existsSync(SETUP_LOCK_FILE)) return true;
  try {
    const adminCount = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin'").get().count;
    if (adminCount > 0) {
      try {
        fs.writeFileSync(SETUP_LOCK_FILE, JSON.stringify({ completed_at: new Date().toISOString(), locked: true }));
      } catch {}
      return true;
    }
  } catch {}
  return false;
}

function saveAdminAccount(username, email, passwordHash) {
  if (isSetupLocked()) {
    const err = new Error("Administrator account is permanently locked. Web setup is disabled.");
    err.status = 403;
    throw err;
  }
  const existingUser1 = db.prepare("SELECT id, uuid FROM users WHERE id=1").get();
  if (existingUser1) {
    const userUuid = existingUser1.uuid || ("usr_" + crypto.randomUUID());
    db.prepare("UPDATE users SET username=?, email=?, password_hash=?, role='admin', active=1, uuid=? WHERE id=1")
      .run(username, email, passwordHash, userUuid);
  } else {
    const userUuid = "usr_" + crypto.randomUUID();
    db.prepare("INSERT INTO users(id, username, email, password_hash, role, active, uuid) VALUES(1, ?, ?, ?, 'admin', 1, ?)")
      .run(username, email, passwordHash, userUuid);
  }
  try {
    fs.writeFileSync(SETUP_LOCK_FILE, JSON.stringify({ completed_at: new Date().toISOString(), locked: true }));
  } catch {}
}

app.get("/api/setup/status", (req, res) => {
  const locked = isSetupLocked();
  res.json({
    needSetup: !locked,
    setup_completed: locked,
    admin_exists: locked
  });
});

app.post("/api/setup/admin", loginLimiter, async (req, res) => {
  try {
    if (isSetupLocked()) {
      return res.status(403).json({ error: "Access denied. Initial setup is permanently locked and cannot be re-run." });
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
    if (!row || !row.active || typeof row.password_hash !== "string" || !row.password_hash.startsWith("$2") || !(await bcrypt.compare(password, row.password_hash))) {
      audit(row?.id || null, "login_failed", `Invalid login attempt for: ${username}`, req);
      return res.status(401).json({ error: "Invalid username or password." });
    }

    // CHECK IF DISCORD TWO-FACTOR AUTHENTICATION (2FA) IS ENABLED
    const is2faActive = Boolean(row.two_factor_enabled && (row.discord_id || db.prepare("SELECT id FROM user_identities WHERE user_id=? AND provider='discord'").get(row.id)));
    if (is2faActive) {
      let discordId = row.discord_id;
      let discordUsername = row.discord_username || "";

      if (!discordId) {
        const ident = db.prepare("SELECT provider_user_id, provider_username, provider_avatar FROM user_identities WHERE user_id=? AND provider='discord'").get(row.id);
        if (ident) {
          discordId = ident.provider_user_id;
          discordUsername = ident.provider_username;
          db.prepare("UPDATE users SET discord_id=?, discord_username=?, discord_avatar=? WHERE id=?")
            .run(discordId, discordUsername, ident.provider_avatar || "", row.id);
        }
      }

      if (discordId) {
        const clientIp = (req.headers["x-forwarded-for"]?.split(",")[0] || req.ip || req.socket.remoteAddress || "").trim();
        const otpCode = discord2fa.generateOtpCode();
        const otpHash = discord2fa.hashOtpCode(otpCode);
        const challengeToken = crypto.randomUUID();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString().replace("T", " ").slice(0, 19);
        const resendAvailableAt = new Date(Date.now() + 60 * 1000).toISOString().replace("T", " ").slice(0, 19);

        // Clear any previous active login challenges for this user
        db.prepare("DELETE FROM two_factor_challenges WHERE user_id=? AND purpose='login'").run(row.id);

        db.prepare(`
          INSERT INTO two_factor_challenges (challenge_token, user_id, purpose, otp_hash, expires_at, attempts, resend_available_at, metadata)
          VALUES (?, ?, 'login', ?, ?, 0, ?, ?)
        `).run(challengeToken, row.id, otpHash, expiresAt, resendAvailableAt, JSON.stringify({ ip: clientIp, userAgent: req.get("user-agent") }));

        // Send OTP via Discord DM
        let delivery;
        try {
          delivery = await discord2fa.sendDiscordOtp(discordId, otpCode, {
            purpose: "login",
            username: row.username,
            ip: clientIp
          });
        } catch (deliveryErr) {
          console.error("[2FA] Discord OTP send failed:", deliveryErr.message);
          return res.status(502).json({
            error: deliveryErr.message || "Failed to deliver 2FA verification code to Discord.",
            discordError: true
          });
        }

        audit(row.id, "2fa.challenge_issued", `Discord 2FA challenge generated for user ${row.username} (IP: ${clientIp})`, req);

        const maskedDiscord = discordId.length > 4 ? `••••••••${discordId.slice(-4)}` : discordId;
        return res.json({
          requires2FA: true,
          challengeToken,
          maskedDiscord,
          discordUsername: discordUsername || "Discord",
          expiresIn: 300,
          resendCooldown: 60
        });
      }
    }

    // Direct Login (2FA not enabled)
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.user = { id: row.id };
      req.session.csrf = crypto.randomBytes(32).toString("hex");
      audit(row.id, "login", "Successful login", req);
      res.json({ user: safeUser(row), csrfToken: req.session.csrf });
    });
  } catch (e) { next(e); }
});

app.post("/api/auth/register", loginLimiter, async (req, res, next) => {
  try {
    const s = getSettings();
    const allowReg = s.allow_registration === "1" || s.allow_registration === true || s.allow_registration === "true";
    if (!allowReg) {
      return res.status(403).json({ error: "Public registration is currently disabled by administrator." });
    }

    const username = validateString(req.body.username, "Username", 32).trim();
    const email = validateString(req.body.email, "Email", 120).trim().toLowerCase();
    const password = validateString(req.body.password, "Password", 200);

    // Block reserved and admin-impersonating names
    const reservedNames = ["admin", "administrator", "root", "system", "moderator", "superuser", "owner"];
    if (reservedNames.includes(username.toLowerCase())) {
      return res.status(400).json({ error: "This username is reserved and cannot be registered." });
    }

    if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
      return res.status(400).json({ error: "Username must be 3–32 characters (letters, numbers, . _ -)." });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Please enter a valid email address." });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters long." });
    }

    const existingUser = db.prepare("SELECT id FROM users WHERE username=? COLLATE NOCASE").get(username);
    if (existingUser) {
      return res.status(409).json({ error: "Username is already taken. Please choose another." });
    }

    const existingEmail = db.prepare("SELECT id FROM users WHERE email=? COLLATE NOCASE").get(email);
    if (existingEmail) {
      return res.status(409).json({ error: "Email address is already in use by another account." });
    }

    const hash = await bcrypt.hash(password, 12);
    const userUuid = "usr_" + crypto.randomUUID();
    // Role is strictly hardcoded to 'user'. Any role parameter in req.body is completely ignored.
    const result = db.prepare("INSERT INTO users(username, email, password_hash, role, active, uuid) VALUES(?, ?, ?, 'user', 1, ?)").run(username, email, hash, userUuid);
    const newUser = db.prepare("SELECT * FROM users WHERE id=?").get(result.lastInsertRowid);

    audit(newUser.id, "user_register", `Public user self-registration: ${username} (${email})`, req);

    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.user = { id: newUser.id };
      req.session.csrf = crypto.randomBytes(32).toString("hex");
      res.status(201).json({ ok: true, user: safeUser(newUser), csrfToken: req.session.csrf });
    });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) e.status = 409;
    next(e);
  }
});
app.get("/api/auth/me", requireAuth, (req, res) => {
  if (req.session && !req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString("hex");
  res.json({
    user: safeUser(req.user),
    csrfToken: req.session ? req.session.csrf : null,
    auth_type: req.apiKey ? "api_key" : "session",
    api_key: req.apiKey ? {
      id: req.apiKey.id,
      name: req.apiKey.name,
      prefix: req.apiKey.key_prefix,
      scopes: req.apiKey.scopes,
      rate_limit: req.apiKey.rate_limit,
      request_count: req.apiKey.request_count
    } : null
  });
});
app.get("/api/me", requireAuth, (req, res) => {
  res.json({
    user: safeUser(req.user),
    auth_type: req.apiKey ? "api_key" : "session",
    api_key: req.apiKey ? {
      id: req.apiKey.id,
      name: req.apiKey.name,
      prefix: req.apiKey.key_prefix,
      scopes: req.apiKey.scopes,
      rate_limit: req.apiKey.rate_limit,
      request_count: req.apiKey.request_count
    } : null
  });
});
app.post("/api/auth/logout", requireAuth, csrf, (req, res) => {
  audit(req.user.id, "logout", "User logged out", req);
  req.session.destroy(() => res.clearCookie("atyro.sid").json({ ok: true }));
});

// ==========================================
// DISCORD TWO-FACTOR AUTHENTICATION (2FA) API
// ==========================================

// Verify 2FA code (OTP or single-use Backup Code) during login
app.post("/api/auth/2fa/verify", twoFactorLimiter, async (req, res, next) => {
  try {
    const challengeToken = String(req.body.challengeToken || "").trim();
    const code = String(req.body.code || "").trim();
    const isBackupCode = Boolean(req.body.isBackupCode);

    if (!challengeToken) return res.status(400).json({ error: "Missing verification challenge token." });
    if (!code) return res.status(400).json({ error: "Verification code is required." });

    const challenge = db.prepare(`
      SELECT * FROM two_factor_challenges
      WHERE challenge_token = ? AND purpose = 'login' AND expires_at > CURRENT_TIMESTAMP
    `).get(challengeToken);

    if (!challenge) {
      return res.status(400).json({ error: "Verification session has expired or is invalid. Please sign in again." });
    }

    if (challenge.attempts >= 5) {
      db.prepare("DELETE FROM two_factor_challenges WHERE id = ?").run(challenge.id);
      audit(challenge.user_id, "2fa.rate_limited", "2FA challenge locked due to excessive failed attempts", req);
      return res.status(429).json({ error: "Too many failed attempts. Verification session terminated for security. Please sign in again." });
    }

    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(challenge.user_id);
    if (!user || !user.active) {
      db.prepare("DELETE FROM two_factor_challenges WHERE id = ?").run(challenge.id);
      return res.status(401).json({ error: "User account unavailable." });
    }

    let isValid = false;
    let usedBackupCode = false;

    if (isBackupCode) {
      let storedBackupCodes = [];
      try {
        storedBackupCodes = JSON.parse(user.two_factor_backup_codes || "[]");
      } catch {}
      const backupResult = discord2fa.verifyAndConsumeBackupCode(code, storedBackupCodes, user.uuid);
      if (backupResult.valid) {
        isValid = true;
        usedBackupCode = true;
        // Update user's remaining backup codes (consumed single-use code)
        db.prepare("UPDATE users SET two_factor_backup_codes = ? WHERE id = ?")
          .run(JSON.stringify(backupResult.remainingCodes), user.id);
      }
    } else {
      isValid = discord2fa.verifyOtpCode(code, challenge.otp_hash);
    }

    if (!isValid) {
      db.prepare("UPDATE two_factor_challenges SET attempts = attempts + 1 WHERE id = ?").run(challenge.id);
      const remainingAttempts = Math.max(0, 4 - challenge.attempts);
      audit(user.id, "2fa.code_invalid", `Invalid 2FA code entered (${remainingAttempts} attempts remaining)`, req);
      return res.status(400).json({
        error: isBackupCode ? "Invalid backup recovery code." : `Invalid verification code. (${remainingAttempts} attempts remaining)`
      });
    }

    // Code is valid! Delete challenge immediately (single use!)
    db.prepare("DELETE FROM two_factor_challenges WHERE id = ?").run(challenge.id);

    if (challenge.purpose === "login") {
      req.session.regenerate((err) => {
        if (err) return next(err);
        req.session.user = { id: user.id };
        req.session.csrf = crypto.randomBytes(32).toString("hex");
        audit(user.id, usedBackupCode ? "2fa.backup_code_login" : "2fa.login_success", `Successful 2FA sign in${usedBackupCode ? ' using backup recovery code' : ''}`, req);
        res.json({
          ok: true,
          user: safeUser(user),
          csrfToken: req.session.csrf,
          usedBackupCode
        });
      });
    } else {
      res.json({ ok: true, message: "Verification successful." });
    }
  } catch (e) { next(e); }
});

// Resend 2FA OTP to Discord via Bot DM (enforces 60s cooldown)
app.post("/api/auth/2fa/resend", twoFactorLimiter, async (req, res, next) => {
  try {
    const challengeToken = String(req.body.challengeToken || "").trim();
    if (!challengeToken) return res.status(400).json({ error: "Missing challenge token." });

    const challenge = db.prepare("SELECT * FROM two_factor_challenges WHERE challenge_token = ?").get(challengeToken);
    if (!challenge) {
      return res.status(400).json({ error: "Verification session expired. Please sign in again." });
    }

    // Check resend cooldown
    const now = new Date();
    const resendAvail = new Date(challenge.resend_available_at.replace(" ", "T") + "Z");
    if (now < resendAvail) {
      const waitSec = Math.ceil((resendAvail.getTime() - now.getTime()) / 1000);
      return res.status(429).json({ error: `Please wait ${waitSec} seconds before requesting a new code.`, waitSeconds: waitSec });
    }

    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(challenge.user_id);
    if (!user || !user.active) return res.status(400).json({ error: "User account unavailable." });

    let discordId = user.discord_id;
    if (!discordId) {
      const ident = db.prepare("SELECT provider_user_id FROM user_identities WHERE user_id=? AND provider='discord'").get(user.id);
      discordId = ident?.provider_user_id;
    }
    if (!discordId) {
      return res.status(400).json({ error: "No Discord account linked to this user." });
    }

    const clientIp = (req.headers["x-forwarded-for"]?.split(",")[0] || req.ip || req.socket.remoteAddress || "").trim();
    const newOtp = discord2fa.generateOtpCode();
    const newHash = discord2fa.hashOtpCode(newOtp);
    const newExpiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString().replace("T", " ").slice(0, 19);
    const newResendAt = new Date(Date.now() + 60 * 1000).toISOString().replace("T", " ").slice(0, 19);

    db.prepare(`
      UPDATE two_factor_challenges
      SET otp_hash = ?, expires_at = ?, resend_available_at = ?, attempts = 0
      WHERE id = ?
    `).run(newHash, newExpiresAt, newResendAt, challenge.id);

    const delivery = await discord2fa.sendDiscordOtp(discordId, newOtp, {
      purpose: challenge.purpose,
      username: user.username,
      ip: clientIp
    });

    audit(user.id, "2fa.code_resent", `Resent 2FA code to Discord for ${user.username}`, req);

    res.json({
      ok: true,
      message: "A new 6-digit verification code has been delivered to your Discord DM.",
      resendCooldown: 60,
      expiresIn: 300
    });
  } catch (e) { next(e); }
});

// Start 2FA Setup: sends test verification code to user's Discord DM
app.post("/api/auth/2fa/setup/start", requireAuth, async (req, res, next) => {
  try {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    let discordId = user.discord_id;
    let discordUsername = user.discord_username || "";

    if (!discordId) {
      const ident = db.prepare("SELECT provider_user_id, provider_username, provider_avatar FROM user_identities WHERE user_id=? AND provider='discord'").get(user.id);
      if (ident) {
        discordId = ident.provider_user_id;
        discordUsername = ident.provider_username;
        db.prepare("UPDATE users SET discord_id=?, discord_username=?, discord_avatar=? WHERE id=?")
          .run(discordId, discordUsername, ident.provider_avatar || "", user.id);
      }
    }

    if (!discordId) {
      return res.status(400).json({ error: "Please link your Discord account first before setting up Two-Factor Authentication." });
    }

    const clientIp = (req.headers["x-forwarded-for"]?.split(",")[0] || req.ip || req.socket.remoteAddress || "").trim();
    const otpCode = discord2fa.generateOtpCode();
    const otpHash = discord2fa.hashOtpCode(otpCode);
    const challengeToken = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString().replace("T", " ").slice(0, 19);
    const resendAvailableAt = new Date(Date.now() + 60 * 1000).toISOString().replace("T", " ").slice(0, 19);

    db.prepare("DELETE FROM two_factor_challenges WHERE user_id=? AND purpose='setup_2fa'").run(user.id);

    db.prepare(`
      INSERT INTO two_factor_challenges (challenge_token, user_id, purpose, otp_hash, expires_at, attempts, resend_available_at, metadata)
      VALUES (?, ?, 'setup_2fa', ?, ?, 0, ?, ?)
    `).run(challengeToken, user.id, otpHash, expiresAt, resendAvailableAt, JSON.stringify({ ip: clientIp }));

    const delivery = await discord2fa.sendDiscordOtp(discordId, otpCode, {
      purpose: "setup_2fa",
      username: user.username,
      ip: clientIp
    });

    const maskedDiscord = discordId.length > 4 ? `••••••••${discordId.slice(-4)}` : discordId;
    res.json({
      ok: true,
      challengeToken,
      maskedDiscord,
      discordUsername: discordUsername || "Discord",
      expiresIn: 300
    });
  } catch (e) { next(e); }
});

// Confirm 2FA Setup: verifies test code, activates 2FA, generates 10 single-use backup recovery codes
app.post("/api/auth/2fa/setup/confirm", requireAuth, async (req, res, next) => {
  try {
    const challengeToken = String(req.body.challengeToken || "").trim();
    const code = String(req.body.code || "").trim();

    if (!challengeToken || !code) {
      return res.status(400).json({ error: "Challenge token and 6-digit code are required." });
    }

    const challenge = db.prepare(`
      SELECT * FROM two_factor_challenges
      WHERE challenge_token = ? AND user_id = ? AND purpose = 'setup_2fa' AND expires_at > CURRENT_TIMESTAMP
    `).get(challengeToken, req.user.id);

    if (!challenge) {
      return res.status(400).json({ error: "Verification code expired or invalid. Please try again." });
    }

    const isValid = discord2fa.verifyOtpCode(code, challenge.otp_hash);
    if (!isValid) {
      return res.status(400).json({ error: "Invalid verification code. Please check your Discord DM and re-enter." });
    }

    // Delete setup challenge
    db.prepare("DELETE FROM two_factor_challenges WHERE id = ?").run(challenge.id);

    // Generate 10 cryptographically random backup recovery codes
    const rawBackupCodes = discord2fa.generateBackupCodes(10);
    const hashedCodes = rawBackupCodes.map(c => discord2fa.hashBackupCode(c, req.user.uuid));

    // Enable 2FA on user account
    db.prepare(`
      UPDATE users
      SET two_factor_enabled = 1, two_factor_backup_codes = ?
      WHERE id = ?
    `).run(JSON.stringify(hashedCodes), req.user.id);

    audit(req.user.id, "2fa.enabled", "Two-Factor Authentication successfully enabled via Discord", req);

    res.json({
      ok: true,
      message: "Discord Two-Factor Authentication is now actively protecting your account!",
      backupCodes: rawBackupCodes
    });
  } catch (e) { next(e); }
});

// Disable 2FA (requires current password for security)
app.post("/api/auth/2fa/disable", requireAuth, async (req, res, next) => {
  try {
    const password = String(req.body.password || "").trim();
    if (!password) return res.status(400).json({ error: "Current password is required to disable Two-Factor Authentication." });

    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(400).json({ error: "Incorrect password. 2FA was not disabled." });
    }

    db.prepare(`
      UPDATE users
      SET two_factor_enabled = 0, two_factor_backup_codes = '[]'
      WHERE id = ?
    `).run(user.id);

    db.prepare("DELETE FROM two_factor_challenges WHERE user_id = ?").run(user.id);

    audit(user.id, "2fa.disabled", "Two-Factor Authentication disabled by user", req);

    res.json({ ok: true, message: "Two-Factor Authentication has been successfully disabled." });
  } catch (e) { next(e); }
});

// Regenerate Backup Recovery Codes (requires current password)
app.post("/api/auth/2fa/backup-codes/regenerate", requireAuth, async (req, res, next) => {
  try {
    const password = String(req.body.password || "").trim();
    if (!password) return res.status(400).json({ error: "Current password is required to regenerate backup recovery codes." });

    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(400).json({ error: "Incorrect password." });
    }

    if (!user.two_factor_enabled) {
      return res.status(400).json({ error: "Two-Factor Authentication is not enabled for this account." });
    }

    const rawBackupCodes = discord2fa.generateBackupCodes(10);
    const hashedCodes = rawBackupCodes.map(c => discord2fa.hashBackupCode(c, user.uuid));

    db.prepare("UPDATE users SET two_factor_backup_codes = ? WHERE id = ?")
      .run(JSON.stringify(hashedCodes), user.id);

    audit(user.id, "2fa.backup_codes_regenerated", "Regenerated 10 new 2FA backup recovery codes", req);

    res.json({
      ok: true,
      backupCodes: rawBackupCodes,
      message: "10 new backup recovery codes generated. All previous backup codes are now invalidated."
    });
  } catch (e) { next(e); }
});

// Request Password Reset via Discord 2FA OTP
app.post("/api/auth/forgot-password/request", passwordResetLimiter, async (req, res, next) => {
  try {
    const identifier = validateString(req.body.identifier || req.body.username || req.body.email, "Username or Email", 120);
    const user = db.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE").get(identifier, identifier);

    if (!user || !user.active) {
      // Generic response to prevent account enumeration
      return res.json({
        ok: true,
        message: "If an active account exists with linked Discord, a verification code has been sent."
      });
    }

    let discordId = user.discord_id;
    let discordUsername = user.discord_username;
    if (!discordId) {
      const ident = db.prepare("SELECT provider_user_id, provider_username FROM user_identities WHERE user_id=? AND provider='discord'").get(user.id);
      if (ident) {
        discordId = ident.provider_user_id;
        discordUsername = ident.provider_username;
        db.prepare("UPDATE users SET discord_id=?, discord_username=? WHERE id=?").run(discordId, discordUsername, user.id);
      }
    }

    if (!discordId) {
      return res.status(400).json({
        error: "This account does not have a linked Discord account for password recovery. Please contact a system administrator."
      });
    }

    const clientIp = (req.headers["x-forwarded-for"]?.split(",")[0] || req.ip || req.socket.remoteAddress || "").trim();
    const otpCode = discord2fa.generateOtpCode();
    const otpHash = discord2fa.hashOtpCode(otpCode);
    const challengeToken = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString().replace("T", " ").slice(0, 19);
    const resendAvailableAt = new Date(Date.now() + 60 * 1000).toISOString().replace("T", " ").slice(0, 19);

    db.prepare("DELETE FROM two_factor_challenges WHERE user_id=? AND purpose='forgot_password'").run(user.id);

    db.prepare(`
      INSERT INTO two_factor_challenges (challenge_token, user_id, purpose, otp_hash, expires_at, attempts, resend_available_at, metadata)
      VALUES (?, ?, 'forgot_password', ?, ?, 0, ?, ?)
    `).run(challengeToken, user.id, otpHash, expiresAt, resendAvailableAt, JSON.stringify({ ip: clientIp }));

    const delivery = await discord2fa.sendDiscordOtp(discordId, otpCode, {
      purpose: "forgot_password",
      username: user.username,
      ip: clientIp
    });

    audit(user.id, "auth.forgot_password_requested", `Password reset code sent to Discord for @${user.username} (IP: ${clientIp})`, req);

    const maskedDiscord = discordId.length > 4 ? `••••••••${discordId.slice(-4)}` : discordId;
    res.json({
      ok: true,
      requiresOtp: true,
      challengeToken,
      maskedDiscord,
      discordUsername: discordUsername || "Discord",
      expiresIn: 300,
      resendCooldown: 60
    });
  } catch (e) { next(e); }
});

// Verify Discord 2FA Reset OTP and Apply New Password
app.post("/api/auth/forgot-password/verify-reset", passwordResetLimiter, async (req, res, next) => {
  try {
    const challengeToken = String(req.body.challengeToken || "").trim();
    const code = String(req.body.code || "").trim();
    const newPassword = validateString(req.body.newPassword, "New Password", 200);

    if (!challengeToken) return res.status(400).json({ error: "Missing challenge token." });
    if (!code) return res.status(400).json({ error: "Verification code is required." });
    if (newPassword.length < 8) return res.status(400).json({ error: "New password must be at least 8 characters long." });

    const challenge = db.prepare(`
      SELECT * FROM two_factor_challenges
      WHERE challenge_token = ? AND purpose = 'forgot_password' AND expires_at > CURRENT_TIMESTAMP
    `).get(challengeToken);

    if (!challenge) {
      return res.status(400).json({ error: "Verification code expired or invalid. Please request a new reset code." });
    }

    if (challenge.attempts >= 5) {
      db.prepare("DELETE FROM two_factor_challenges WHERE id = ?").run(challenge.id);
      audit(challenge.user_id, "auth.password_reset_locked", "Password reset session locked due to excessive failed attempts", req);
      return res.status(429).json({ error: "Too many failed attempts. Please request a new password reset." });
    }

    const isValid = discord2fa.verifyOtpCode(code, challenge.otp_hash);
    if (!isValid) {
      db.prepare("UPDATE two_factor_challenges SET attempts = attempts + 1 WHERE id = ?").run(challenge.id);
      const remaining = Math.max(0, 4 - challenge.attempts);
      return res.status(400).json({ error: `Invalid verification code. (${remaining} attempts remaining)` });
    }

    // Hash new password with bcrypt
    const hash = await bcrypt.hash(newPassword, 12);
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, challenge.user_id);
    db.prepare("DELETE FROM two_factor_challenges WHERE id = ?").run(challenge.id);

    audit(challenge.user_id, "auth.password_reset_discord_2fa", "Password reset successfully via Discord 2FA verification", req);

    res.json({
      ok: true,
      message: "Your password has been successfully reset! You can now sign in with your new password."
    });
  } catch (e) { next(e); }
});

// Get Discord OAuth2 Link Authorization URL
app.get("/api/auth/discord/connect", requireAuth, (req, res, next) => {
  try {
    const rawState = crypto.randomBytes(24).toString("hex") + ":" + req.user.id;
    req.session.discordOAuthState = rawState;
    const url = discord2fa.getDiscordOAuthUrl(rawState);
    res.json({ ok: true, url });
  } catch (e) { next(e); }
});

// Discord OAuth2 Redirect Callback Handler
app.get("/api/auth/discord/callback", async (req, res, next) => {
  try {
    const code = String(req.query.code || "").trim();
    const state = String(req.query.state || "").trim();

    if (!code) {
      return res.redirect("/#profile?discord_error=missing_code");
    }

    // Strict CSRF State Validation
    const expectedState = req.session?.discordOAuthState;
    if (req.session) delete req.session.discordOAuthState;

    if (!state || !expectedState || state !== expectedState) {
      return res.redirect("/#profile?discord_error=invalid_oauth_state");
    }

    const targetUserId = req.session?.user?.id;
    if (!targetUserId) {
      return res.redirect("/#profile?discord_error=session_expired");
    }

    // Exchange OAuth2 code for Discord user profile
    const profile = await discord2fa.exchangeDiscordCode(code);

    // Prevent duplicate account linking to different panel users
    const existing = db.prepare(`
      SELECT ui.user_id, u.username
      FROM user_identities ui
      JOIN users u ON ui.user_id = u.id
      WHERE ui.provider = 'discord' AND ui.provider_user_id = ?
    `).get(profile.id);

    if (existing && existing.user_id !== targetUserId) {
      audit(targetUserId, "identity.discord_link_blocked", `Blocked duplicate linking attempt for Discord ID ${profile.id} (already owned by @${existing.username})`, req);
      return res.redirect("/#profile?discord_error=already_linked");
    }

    const clientIp = (req.headers["x-forwarded-for"]?.split(",")[0] || req.ip || req.socket.remoteAddress || "").trim();

    // Upsert into user_identities
    db.prepare("DELETE FROM user_identities WHERE user_id = ? AND provider = 'discord'").run(targetUserId);
    db.prepare(`
      INSERT INTO user_identities (user_id, provider, provider_user_id, provider_username, provider_email, provider_avatar, metadata, linked_by_ip)
      VALUES (?, 'discord', ?, ?, ?, ?, ?, ?)
    `).run(targetUserId, profile.id, profile.username, profile.email || "", profile.avatar || "", JSON.stringify({ linked_via: "oauth2" }), clientIp);

    // Update users table
    db.prepare(`
      UPDATE users
      SET discord_id = ?, discord_username = ?, discord_avatar = ?
      WHERE id = ?
    `).run(profile.id, profile.username, profile.avatar || "", targetUserId);

    audit(targetUserId, "identity.discord_linked", `Linked Discord account @${profile.username} (${profile.id}) via OAuth2`, req);

    res.redirect("/#profile?discord_success=linked");
  } catch (err) {
    console.error("[Discord OAuth2 Callback Error]:", err.message);
    res.redirect("/#profile?discord_error=" + encodeURIComponent(err.message || "Failed to link Discord"));
  }
});

// Unlink Discord Account (protected against accidental lockout)
app.post("/api/auth/discord/unlink", requireAuth, (req, res, next) => {
  try {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    if (user.two_factor_enabled) {
      return res.status(400).json({
        error: "Please disable Two-Factor Authentication before unlinking your Discord account to prevent account lockout."
      });
    }

    db.prepare("DELETE FROM user_identities WHERE user_id = ? AND provider = 'discord'").run(user.id);
    db.prepare("UPDATE users SET discord_id = NULL, discord_username = NULL, discord_avatar = NULL WHERE id = ?").run(user.id);

    audit(user.id, "identity.discord_unlinked", "Unlinked Discord account from profile", req);

    res.json({ ok: true, message: "Discord account successfully unlinked." });
  } catch (e) { next(e); }
});

// Live Discord Bot Status for Administrators
app.get("/api/admin/security/discord-bot-status", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const status = await discord2fa.getDiscordBotStatus();
    res.json({ ok: true, botStatus: status });
  } catch (e) { next(e); }
});

// Admin Reset 2FA for locked-out user
app.post("/api/admin/users/:id/2fa/reset", requireAuth, requireAdmin, (req, res, next) => {
  try {
    const targetId = Number(req.params.id);
    const target = db.prepare("SELECT * FROM users WHERE id = ?").get(targetId);
    if (!target) return res.status(404).json({ error: "User not found." });

    db.prepare("UPDATE users SET two_factor_enabled = 0, two_factor_backup_codes = '[]' WHERE id = ?").run(targetId);
    db.prepare("DELETE FROM two_factor_challenges WHERE user_id = ?").run(targetId);

    audit(req.user.id, "admin.2fa_reset", `Admin reset 2FA protection for user #${target.id} (${target.username})`, req);

    res.json({
      ok: true,
      message: `Two-Factor Authentication for ${target.username} has been reset successfully.`
    });
  } catch (e) { next(e); }
});

// Profile Management Endpoints
app.get("/api/user/profile", requireAuth, async (req, res, next) => {
  try {
    const row = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
    if (!row) return res.status(404).json({ error: "User not found." });

    const serverCount = row.role === "admin"
      ? db.prepare("SELECT COUNT(*) AS count FROM servers").get().count
      : db.prepare("SELECT COUNT(*) AS count FROM servers WHERE user_id=?").get(req.user.id).count;

    const serverRows = row.role === "admin"
      ? db.prepare("SELECT s.id, s.name, s.vmid, s.type, s.pve_node, s.node_id, n.name AS node_name FROM servers s JOIN nodes n ON n.id=s.node_id ORDER BY s.id DESC LIMIT 30").all()
      : db.prepare("SELECT s.id, s.name, s.vmid, s.type, s.pve_node, s.node_id, n.name AS node_name FROM servers s JOIN nodes n ON n.id=s.node_id WHERE s.user_id=? ORDER BY s.id DESC").all(req.user.id);

    // Query live cluster resources in parallel to get exact status for all assigned servers
    const nodeIds = [...new Set(serverRows.map(s => s.node_id))];
    const pveVmMap = new Map();

    await Promise.allSettled(nodeIds.map(async (nId) => {
      try {
        const node = getNode(nId);
        if (node && node.enabled) {
          const list = await pve(node, "GET", "/cluster/resources?type=vm");
          if (Array.isArray(list)) {
            for (const item of list) {
              const st = item.status || "stopped";
              pveVmMap.set(`${nId}_${item.vmid}`, st);
              pveVmMap.set(Number(item.vmid), st);
            }
          }
        }
      } catch (_) {}
    }));

    const servers = serverRows.map(s => {
      const liveStatus = pveVmMap.get(`${s.node_id}_${s.vmid}`) || pveVmMap.get(Number(s.vmid)) || "stopped";
      return {
        id: s.id,
        name: s.name,
        vmid: s.vmid,
        type: s.type,
        node: s.pve_node || s.node_name || "Proxmox",
        status: liveStatus
      };
    });

    let identities = [];
    try {
      identities = db.prepare(`
        SELECT id, provider, provider_user_id, provider_username, provider_email, provider_avatar, metadata, linked_at
        FROM user_identities
        WHERE user_id = ?
        ORDER BY id ASC
      `).all(req.user.id);
    } catch {}

    let backupCodesCount = 0;
    try {
      backupCodesCount = JSON.parse(row.two_factor_backup_codes || "[]").length;
    } catch {}

    res.json({
      user: {
        ...safeUser(row),
        two_factor_backup_codes_count: backupCodesCount
      },
      identities,
      stats: {
        serverCount,
        servers
      }
    });
  } catch (err) {
    next(err);
  }
});

app.patch("/api/user/profile", requireAuth, async (req, res, next) => {
  try {
    const user = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found." });

    // Explicit Privilege Escalation Prevention: Block attempts to tamper with role/status
    if (req.body.role !== undefined || req.body.active !== undefined || req.body.id !== undefined || req.body.uuid !== undefined) {
      audit(req.user.id, "security.privilege_escalation_blocked", `Blocked unauthorized role/permission escalation attempt on user #${req.user.id}`, req);
      return res.status(403).json({ error: "Permission denied: Account role and administrative flags cannot be altered." });
    }

    const updates = [];
    const params = [];

    // 1. Username
    if (req.body.username !== undefined && req.body.username.trim() !== user.username) {
      const username = validateString(req.body.username, "Username", 32);
      if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
        return res.status(400).json({ error: "Username must be 3–32 characters (letters, numbers, . _ -)." });
      }
      const existing = db.prepare("SELECT id FROM users WHERE username=? COLLATE NOCASE AND id!=?").get(username, user.id);
      if (existing) {
        return res.status(409).json({ error: "This username is already taken by another account." });
      }
      updates.push("username=?");
      params.push(username);
    }

    // 2. Email
    if (req.body.email !== undefined && req.body.email.trim().toLowerCase() !== user.email.toLowerCase()) {
      const email = validateString(req.body.email, "Email", 120).toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: "Please enter a valid email address." });
      }
      const existing = db.prepare("SELECT id FROM users WHERE email=? COLLATE NOCASE AND id!=?").get(email, user.id);
      if (existing) {
        return res.status(409).json({ error: "This email is already in use by another account." });
      }
      updates.push("email=?");
      params.push(email);
    }

    // 3. Avatar URL
    if (req.body.avatar_url !== undefined) {
      const avatarUrl = String(req.body.avatar_url || "").trim().slice(0, 2000);
      if (avatarUrl && !avatarUrl.startsWith("/uploads/") && !avatarUrl.startsWith("http://") && !avatarUrl.startsWith("https://")) {
        return res.status(400).json({ error: "Avatar URL must be a valid HTTP or HTTPS link, or an uploaded image." });
      }
      updates.push("avatar_url=?");
      params.push(avatarUrl);
    }

    // 4. Password Change
    if (req.body.new_password) {
      const currentPassword = req.body.current_password;
      if (!currentPassword) {
        return res.status(400).json({ error: "Current password is required to change your password." });
      }
      const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
      if (!isMatch) {
        return res.status(400).json({ error: "Incorrect current password. Please try again." });
      }
      const newPassword = validateString(req.body.new_password, "New password", 200);
      if (newPassword.length < 8) {
        return res.status(400).json({ error: "New password must be at least 8 characters." });
      }
      const newHash = await bcrypt.hash(newPassword, 12);
      updates.push("password_hash=?");
      params.push(newHash);
    }

    if (updates.length > 0) {
      params.push(user.id);
      db.prepare(`UPDATE users SET ${updates.join(", ")} WHERE id=?`).run(...params);
    }

    audit(user.id, "profile_update", "Updated personal profile information", req);

    const updated = db.prepare("SELECT * FROM users WHERE id=?").get(user.id);
    res.json({ ok: true, user: safeUser(updated), message: "Profile updated successfully!" });
  } catch (e) {
    next(e);
  }
});

app.post("/api/user/avatar/upload", requireAuth, (req, res) => {
  try {
    const rawData = req.body.data || req.body.fileData;
    if (!rawData || typeof rawData !== "string" || !rawData.startsWith("data:image/")) {
      return res.status(400).json({ error: "Invalid image format. Please upload a valid PNG, JPG, WEBP, or SVG image." });
    }

    const matches = rawData.match(/^data:image\/([a-zA-Z0-9+.-]+);base64,(.+)$/);
    if (!matches) {
      return res.status(400).json({ error: "Invalid base64 image data." });
    }

    let ext = matches[1].toLowerCase();
    if (ext === "svg+xml") ext = "svg";
    if (ext === "jpeg") ext = "jpg";
    const allowedExts = ["png", "jpg", "jpeg", "webp", "svg"];
    if (!allowedExts.includes(ext)) {
      return res.status(400).json({ error: "Unsupported image format. Allowed: PNG, JPG, WEBP, SVG." });
    }

    const buffer = Buffer.from(matches[2], "base64");
    if (buffer.length > 5 * 1024 * 1024) {
      return res.status(400).json({ error: "Image file exceeds maximum 5MB size limit." });
    }

    const avatarDir = path.join(UPLOADS_DIR, "avatars");
    if (!fs.existsSync(avatarDir)) fs.mkdirSync(avatarDir, { recursive: true });

    const outFilename = `avatar-${req.user.id}-${Date.now()}.${ext}`;
    const outPath = path.join(avatarDir, outFilename);
    fs.writeFileSync(outPath, buffer);

    const publicUrl = `/uploads/avatars/${outFilename}`;
    db.prepare("UPDATE users SET avatar_url=? WHERE id=?").run(publicUrl, req.user.id);

    audit(req.user.id, "avatar_upload", `Updated avatar image (${outFilename})`, req);
    res.json({ ok: true, url: publicUrl, message: "Avatar uploaded successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message || "Failed to process avatar upload." });
  }
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

    const enrichedRows = rows.map(s => enrichServerExpiry(s));
    res.json({ counts, servers: enrichedRows });
  } catch (e) { next(e); }
});

app.get("/api/servers/:id/status", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    const node = getNode(s.node_id);
    await ensureServerPveNode(s, node);
    const status = await pve(node, "GET", serverEndpoint(s, "/status/current"));
    const enriched = enrichServerExpiry(s);
    res.json({
      status,
      is_suspended: Boolean(s.is_suspended),
      suspended_at: s.suspended_at || null,
      suspend_reason: s.suspend_reason || null,
      expires_at: enriched.expires_at,
      duration_days: enriched.duration_days,
      is_expired: enriched.is_expired,
      days_left: enriched.days_left,
      expiry_status: enriched.expiry_status
    });
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

const activeConsoleSessions = new Map();

function cleanConsoleSessions() {
  const now = Date.now();
  for (const [id, sess] of activeConsoleSessions.entries()) {
    if (now - sess.createdAt > 60000) {
      activeConsoleSessions.delete(id);
    }
  }
}

app.post("/api/servers/:id/termproxy", requireAuth, async (req, res, next) => {
  try {
    const s = ownedServer(req, Number(req.params.id));
    if (req.user.role !== "admin" && s.is_suspended) {
      return res.status(403).json({ error: "This virtual server is suspended by administration. Console access is disabled." });
    }
    const node = getNode(s.node_id);
    const pveNode = await ensureServerPveNode(s, node);

    let vmStatus = "unknown";
    try {
      const st = await pve(node, "GET", serverEndpoint(s, "/status/current"));
      vmStatus = st.status || "unknown";
    } catch {}

    const endpoint = `/nodes/${encodeURIComponent(pveNode)}/${s.type}/${s.vmid}/termproxy`;
    const pveData = await pve(node, "POST", endpoint);

    cleanConsoleSessions();

    const sessionId = crypto.randomBytes(24).toString("hex");
    activeConsoleSessions.set(sessionId, {
      server: s,
      node,
      pveNode,
      pveData,
      userId: req.user.id,
      createdAt: Date.now()
    });

    audit(req.user.id, "CONSOLE_OPEN", `Opened web console for ${s.type} #${s.vmid} (${s.name})`, req);

    res.json({
      ok: true,
      sessionId,
      name: s.name,
      vmid: s.vmid,
      type: s.type,
      pveNode,
      status: vmStatus
    });
  } catch (e) {
    next(e);
  }
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
    if (req.user.role !== "admin" && s.is_suspended) {
      return res.status(403).json({ error: "This virtual server is suspended by administration. Actions are locked." });
    }
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

// One-click Suspend VPS (Admin only or API Key with vps:write/*)
app.post("/api/servers/:id/suspend", requireAuth, async (req, res, next) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Administrator permission required to suspend virtual servers." });
    }
    const s = ownedServer(req, Number(req.params.id));
    const reason = (typeof req.body.reason === "string" && req.body.reason.trim()) ? req.body.reason.trim() : "Administrative suspension";

    // Power off the VM if running so it stops consuming CPU/RAM resources
    let poweredDown = false;
    try {
      const node = getNode(s.node_id);
      await ensureServerPveNode(s, node);
      const st = await pve(node, "GET", serverEndpoint(s, "/status/current"));
      if (st && st.status === "running") {
        await pve(node, "POST", serverEndpoint(s, "/status/stop"));
        poweredDown = true;
      }
    } catch (pveErr) {
      console.warn(`[Suspend Notice] Could not issue stop to Proxmox VM ${s.vmid}:`, pveErr.message);
    }

    db.prepare(`
      UPDATE servers
      SET is_suspended = 1,
          suspended_at = CURRENT_TIMESTAMP,
          suspend_reason = ?
      WHERE id = ?
    `).run(reason, s.id);

    audit(req.user.id, "server_suspend", `VPS #${s.id} (VMID ${s.vmid}) suspended. Reason: ${reason}. Powered off: ${poweredDown}`, req);
    notifyVpsChanged(s.id, "suspend");
    if (typeof io !== "undefined" && io) {
      io.emit("vps:suspended", { id: s.id, vmid: s.vmid, is_suspended: 1, reason });
    }

    res.json({
      ok: true,
      is_suspended: true,
      suspended: true,
      is_suspended_int: 1,
      powered_down: poweredDown,
      message: `VPS "${s.name}" (VMID ${s.vmid}) suspended successfully.${poweredDown ? " Virtual machine powered off." : ""}`
    });
  } catch (e) { next(e); }
});

// One-click Unsuspend VPS (Admin only or API Key with vps:write/*)
app.post("/api/servers/:id/unsuspend", requireAuth, async (req, res, next) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Administrator permission required to unsuspend virtual servers." });
    }
    const s = ownedServer(req, Number(req.params.id));

    db.prepare(`
      UPDATE servers
      SET is_suspended = 0,
          suspended_at = NULL,
          suspend_reason = ''
      WHERE id = ?
    `).run(s.id);

    audit(req.user.id, "server_unsuspend", `VPS #${s.id} (VMID ${s.vmid}) unsuspended. User access restored.`, req);
    notifyVpsChanged(s.id, "unsuspend");
    if (typeof io !== "undefined" && io) {
      io.emit("vps:unsuspended", { id: s.id, vmid: s.vmid, is_suspended: 0 });
    }

    res.json({
      ok: true,
      is_suspended: false,
      suspended: false,
      is_suspended_int: 0,
      message: `VPS "${s.name}" (VMID ${s.vmid}) unsuspended successfully. User access restored.`
    });
  } catch (e) { next(e); }
});

// One-click Toggle Suspend
app.post("/api/servers/:id/toggle-suspend", requireAuth, async (req, res, next) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Administrator permission required." });
    }
    const s = ownedServer(req, Number(req.params.id));
    const targetAction = s.is_suspended ? "unsuspend" : "suspend";
    const reason = (typeof req.body.reason === "string" && req.body.reason.trim()) ? req.body.reason.trim() : "Administrative toggle";

    let poweredDown = false;
    if (!s.is_suspended) {
      try {
        const node = getNode(s.node_id);
        await ensureServerPveNode(s, node);
        const st = await pve(node, "GET", serverEndpoint(s, "/status/current"));
        if (st && st.status === "running") {
          await pve(node, "POST", serverEndpoint(s, "/status/stop"));
          poweredDown = true;
        }
      } catch (err) {}

      db.prepare(`
        UPDATE servers
        SET is_suspended = 1,
            suspended_at = CURRENT_TIMESTAMP,
            suspend_reason = ?
        WHERE id = ?
      `).run(reason, s.id);
      audit(req.user.id, "server_suspend", `VPS #${s.id} (VMID ${s.vmid}) suspended via toggle.`, req);
      notifyVpsChanged(s.id, "suspend");
      if (typeof io !== "undefined" && io) {
        io.emit("vps:suspended", { id: s.id, vmid: s.vmid, is_suspended: 1, reason });
      }
      return res.json({
        ok: true,
        is_suspended: true,
        suspended: true,
        is_suspended_int: 1,
        powered_down: poweredDown,
        message: `VPS "${s.name}" suspended successfully.`
      });
    } else {
      db.prepare(`
        UPDATE servers
        SET is_suspended = 0,
            suspended_at = NULL,
            suspend_reason = ''
        WHERE id = ?
      `).run(s.id);
      audit(req.user.id, "server_unsuspend", `VPS #${s.id} (VMID ${s.vmid}) unsuspended via toggle.`, req);
      notifyVpsChanged(s.id, "unsuspend");
      if (typeof io !== "undefined" && io) {
        io.emit("vps:unsuspended", { id: s.id, vmid: s.vmid, is_suspended: 0 });
      }
      return res.json({
        ok: true,
        is_suspended: 0,
        message: `VPS "${s.name}" unsuspended successfully. User access restored.`
      });
    }
  } catch (e) { next(e); }
});

// One-click / Granular Renew VPS Endpoint: POST /api/servers/:id/renew
// Extends duration, recalculates expires_at, and automatically unsuspends if suspended
app.post("/api/servers/:id/renew", requireAuth, async (req, res, next) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Administrator permission required to renew virtual servers." });
    }
    const s = ownedServer(req, Number(req.params.id));
    const now = Date.now();
    let newExpiresAt = null;
    let daysAdded = 0;
    const isLifetime = req.body.lifetime === true || req.body.lifetime === "true";

    if (isLifetime) {
      newExpiresAt = null;
      daysAdded = 0;
    } else if (req.body.expires_at) {
      const explicitDate = new Date(req.body.expires_at);
      if (isNaN(explicitDate.getTime())) {
        return res.status(400).json({ error: "Invalid expires_at date provided." });
      }
      if (explicitDate.getTime() <= now) {
        return res.status(400).json({ error: "Expiration date must be set to a future date." });
      }
      newExpiresAt = explicitDate.toISOString();
      daysAdded = Math.max(1, Math.round((explicitDate.getTime() - now) / 86400000));
    } else {
      let days = Number(req.body.days || 0);
      if (!days && req.body.months) {
        days = Number(req.body.months) * 30;
      }
      if (!days || isNaN(days) || days <= 0) {
        return res.status(400).json({ error: "Please specify duration in days (e.g. 30), months, lifetime, or a valid future expires_at date." });
      }
      daysAdded = days;

      // If server currently has an active future expiration, extend from that future date!
      // Otherwise extend from now.
      let baseTime = now;
      if (s.expires_at) {
        const curExp = new Date(s.expires_at).getTime();
        if (!isNaN(curExp) && curExp > now) {
          baseTime = curExp;
        }
      }
      const expDate = new Date(baseTime + daysAdded * 86400000);
      newExpiresAt = expDate.toISOString();
    }

    const shouldUnsuspend = req.body.auto_unsuspend !== false && req.body.auto_unsuspend !== "false";
    let autoUnsuspended = false;

    let updateSql = `
      UPDATE servers
      SET expires_at = ?,
          duration_days = ?,
          expired_at = NULL,
          last_renewed_at = CURRENT_TIMESTAMP
    `;
    const params = [newExpiresAt, isLifetime ? 0 : daysAdded];

    if (shouldUnsuspend && s.is_suspended) {
      updateSql += `,
          is_suspended = 0,
          suspended_at = NULL,
          suspend_reason = ''
      `;
      autoUnsuspended = true;
    }

    updateSql += ` WHERE id = ?`;
    params.push(s.id);

    db.prepare(updateSql).run(...params);

    const renewalSummary = isLifetime
      ? "Set to Lifetime plan (no expiration)"
      : `Extended by ${daysAdded} days (New expiration: ${newExpiresAt})`;

    audit(req.user.id, "server_renew", `VPS #${s.id} (VMID ${s.vmid}) renewed. ${renewalSummary}.${autoUnsuspended ? " Auto-unsuspended and restored access." : ""}`, req);
    notifyVpsChanged(s.id, "renew");

    if (typeof io !== "undefined" && io) {
      io.emit("vps:renewed", {
        id: s.id,
        vmid: s.vmid,
        expires_at: newExpiresAt,
        days_added: daysAdded,
        is_lifetime: isLifetime,
        auto_unsuspended: autoUnsuspended
      });
      if (autoUnsuspended) {
        io.emit("vps:unsuspended", { id: s.id, vmid: s.vmid, is_suspended: 0 });
      }
    }

    const updated = db.prepare("SELECT * FROM servers WHERE id = ?").get(s.id);
    const enriched = enrichServerExpiry(updated);

    res.json({
      ok: true,
      message: `VPS "${s.name}" renewed successfully! ${isLifetime ? "Server has no expiration (Lifetime)." : `New expiration date: ${new Date(newExpiresAt).toLocaleString()}`}.${autoUnsuspended ? " Server was automatically unsuspended and restored." : ""}`,
      server: enriched,
      auto_unsuspended: autoUnsuspended,
      new_expires_at: newExpiresAt,
      days_added: daysAdded
    });
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
          if (typeof res.exitstatus === "string" && res.exitstatus.startsWith("WARNINGS:")) {
            console.warn(`[Proxmox Task Notice] Task ${upid} completed with non-fatal warnings: ${res.exitstatus}`);
            return res;
          }
          throw new Error(`Proxmox task failed: ${res.exitstatus}`);
        }
        return res;
      }
    } catch (err) {
      if (err.message && err.message.includes("Proxmox task failed")) throw err;
    }
  }
}

/**
 * Ensures an LXC container template is downloaded and available on the Proxmox VE node.
 * If the template is an official appliance that is not yet downloaded, it triggers an
 * automated download via Proxmox aplinfo API and waits for completion.
 */
async function ensureLxcTemplateDownloaded(node, pveNode, rawTemplate, defaultStorage = "local", forceDownload = false) {
  if (!rawTemplate || typeof rawTemplate !== "string") {
    throw new Error("Invalid OS template name specified.");
  }

  // 1. Determine storage and filename
  let storage = defaultStorage || "local";
  let filename = rawTemplate.trim();

  if (filename.includes(":")) {
    const parts = filename.split(":");
    storage = parts[0];
    filename = parts[1].replace(/^vztmpl\//, "");
  } else if (filename.includes("/")) {
    filename = filename.split("/").pop();
  }

  // 2. Validate/discover a storage that supports 'vztmpl'
  try {
    const sList = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage`);
    if (Array.isArray(sList)) {
      const supportsVz = sList.some(s => s.storage === storage && s.content && s.content.includes("vztmpl"));
      if (!supportsVz) {
        const validVzStorage = sList.find(s => s.active !== 0 && s.enabled !== 0 && s.content && s.content.includes("vztmpl"));
        if (validVzStorage) {
          storage = validVzStorage.storage;
        }
      }
    }
  } catch (err) {
    console.warn("[LXC Template Warning] Failed to inspect storages:", err.message);
  }

  const expectedVolid = `${storage}:vztmpl/${filename}`;

  // 3. Check if already downloaded on this storage (unless forceDownload requested)
  if (!forceDownload) {
    try {
      const contents = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage/${encodeURIComponent(storage)}/content?content=vztmpl`);
      if (Array.isArray(contents)) {
        const exists = contents.find(c => c.volid === expectedVolid || c.volid?.endsWith("/" + filename));
        if (exists) {
          console.log(`[LXC Template] "${filename}" already exists on storage "${storage}" (${exists.volid}). Ready to use.`);
          return exists.volid;
        }
      }
    } catch (checkErr) {
      console.warn("[LXC Template Check Notice]:", checkErr.message);
    }
  }

  // 4. Also check if it already exists on any other vztmpl storage on the node
  if (!forceDownload) {
    try {
      const sList = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage`);
      if (Array.isArray(sList)) {
        for (const s of sList) {
          if (s.storage !== storage && s.content && s.content.includes("vztmpl")) {
            try {
              const otherContents = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage/${encodeURIComponent(s.storage)}/content?content=vztmpl`);
              if (Array.isArray(otherContents)) {
                const found = otherContents.find(c => c.volid?.endsWith("/" + filename));
                if (found) {
                  console.log(`[LXC Template] "${filename}" found on alternative storage "${s.storage}" (${found.volid}). Ready to use.`);
                  return found.volid;
                }
              }
            } catch {}
          }
        }
      }
    } catch {}
  }

  // 5. Template is not downloaded yet — find exact template name in Proxmox aplinfo
  console.log(`[LXC Template] "${filename}" is not downloaded on node '${pveNode}'. Initiating download to storage '${storage}'...`);
  let templateToDownload = filename;
  try {
    const aplList = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/aplinfo`);
    if (Array.isArray(aplList)) {
      const match = aplList.find(a =>
        a.template === filename ||
        a.template?.endsWith("/" + filename) ||
        a.package === filename ||
        (a.package && filename.includes(a.package))
      );
      if (match && match.template) {
        templateToDownload = match.template;
      }
    }
  } catch (aplErr) {
    console.warn("[LXC Template Notice] Could not query aplinfo list:", aplErr.message);
  }

  // 6. Trigger download task in Proxmox VE
  try {
    const dlTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/aplinfo`, {
      storage,
      template: templateToDownload
    });
    console.log(`[LXC Template] Download task submitted for "${templateToDownload}": ${dlTask}. Waiting for completion...`);
    await waitForPveTask(node, pveNode, dlTask, 300);
    console.log(`[LXC Template] Successfully downloaded "${templateToDownload}" to ${expectedVolid}.`);
  } catch (dlErr) {
    // If download task returned an error or warning, check if file exists anyway
    try {
      const contentsAfter = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage/${encodeURIComponent(storage)}/content?content=vztmpl`);
      if (Array.isArray(contentsAfter) && contentsAfter.some(c => c.volid === expectedVolid || c.volid?.endsWith("/" + filename))) {
        return expectedVolid;
      }
    } catch {}

    if (dlErr.message && (dlErr.message.includes("Datastore.AllocateTemplate") || dlErr.message.includes("Permission check failed"))) {
      const permErr = new Error(
        `Proxmox permission required: Datastore.AllocateTemplate on storage '${storage}'. ` +
        `The OS template "${filename}" is not yet downloaded on node '${pveNode}'. ` +
        `To allow automatic OS template downloads, please go to Proxmox VE (Datacenter -> Permissions) and grant role 'PVEDatastoreAdmin' or 'Administrator' to API token '${node.token_id}' on path '/storage' (or remove the '/storage' override so it inherits Administrator from '/'). ` +
        `Alternatively, download "${filename}" once directly in Proxmox VE under '${pveNode}' -> '${storage}' -> 'CT Templates' -> 'Templates'.`
      );
      permErr.status = 403;
      throw permErr;
    }

    const customErr = new Error(`Failed to download LXC OS template "${filename}" to storage "${storage}": ${dlErr.message}`);
    customErr.status = 400;
    throw customErr;
  }

  return expectedVolid;
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
        const vzList = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage`);
        if (Array.isArray(vzList)) {
          for (const st of vzList) {
            if (st.content && st.content.includes("vztmpl")) {
              try {
                const tmpls = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage/${encodeURIComponent(st.storage)}/content?content=vztmpl`);
                if (Array.isArray(tmpls)) {
                  for (const t of tmpls) {
                    if (t.volid) {
                      templates.push({
                        id: t.volid,
                        package: t.volid.split("/").pop(),
                        name: t.volid.split("/").pop(),
                        template: t.volid,
                        type: "lxc",
                        isLocal: true
                      });
                    }
                  }
                }
              } catch {}
            }
          }
        }
      } catch {}

      try {
        const apl = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/aplinfo`);
        if (Array.isArray(apl)) {
          const popular = apl.filter(x => 
            /ubuntu|debian|alpine|almalinux|rocky|centos|archlinux/i.test(x.package) &&
            (x.architecture === "amd64" || !x.architecture)
          );
          for (const x of popular) {
            if (!templates.some(t => t.id === x.template || t.name === x.package)) {
              templates.push({
                id: x.template,
                package: x.package,
                name: x.headline || x.package,
                template: x.template,
                type: "lxc",
                isLocal: false
              });
            }
          }
        }
      } catch (err) {
        console.warn("Could not query aplinfo:", err.message);
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

      // Auto-verify and download template before reinstalling
      const verifiedTemplate = await ensureLxcTemplateDownloaded(node, pveNode, templateVolid, "local");

      // Create fresh container
      const createParams = {
        vmid: s.vmid,
        ostemplate: verifiedTemplate,
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
        const errMsg = String(err.message).toLowerCase();
        if (errMsg.includes("does not exist") || errMsg.includes("no such file")) {
          const forcedVolid = await ensureLxcTemplateDownloaded(node, pveNode, templateVolid, "local", true);
          createParams.ostemplate = forcedVolid;
          const retryTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/lxc`, createParams);
          await waitForPveTask(node, pveNode, retryTask, 120);
        } else if (String(err.message).includes("AllocateSpace")) {
          return res.status(403).json({
            error: "Proxmox permission required: Datastore.AllocateSpace. Please add role 'PVEDatastoreUser' or 'Administrator' to API token in Proxmox VE (Datacenter -> Permissions)."
          });
        } else {
          throw new Error(`Failed to create fresh container: ${err.message}`);
        }
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
    const pveNode = await ensureServerPveNode(row, node);

    // 1. Live Proxmox config directly from hypervisor
    let config = null;
    let configError = null;
    try {
      config = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/${row.type}/${row.vmid}/config`);
    } catch (err) {
      configError = err.message;
      console.error(`[Edit Options] Failed to fetch Proxmox config for VM ${row.vmid} on node ${pveNode}:`, err.message);
    }

    if (!config) {
      return res.status(502).json({
        error: `Could not fetch live configuration from Proxmox VE (Node: ${pveNode}): ${configError || 'Hypervisor unavailable'}. Please verify node connectivity.`
      });
    }

    // 2. Live Proxmox status
    let status = {};
    try {
      status = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/${row.type}/${row.vmid}/status/current`);
    } catch (stErr) {
      console.warn(`[Edit Options] Live status fetch notice:`, stErr.message);
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

    // 5. Detect primary disk and current disk size in GB directly from live Proxmox config
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

    // 6. Granular primary disk options
    let diskOptions = {
      cache: "writeback",
      discard: false,
      ssd: false,
      mbps_rd: "",
      mbps_wr: "",
      iops_rd: "",
      iops_wr: ""
    };
    const primaryDiskStr = config[diskKey] || "";
    if (primaryDiskStr && typeof primaryDiskStr === "string") {
      const cacheM = primaryDiskStr.match(/cache=([a-z0-9_-]+)/i);
      if (cacheM) diskOptions.cache = cacheM[1].toLowerCase();
      diskOptions.discard = primaryDiskStr.includes("discard=on");
      diskOptions.ssd = primaryDiskStr.includes("ssd=1");
      const mbpsRdM = primaryDiskStr.match(/mbps_rd=([0-9.]+)/i);
      if (mbpsRdM) diskOptions.mbps_rd = mbpsRdM[1];
      const mbpsWrM = primaryDiskStr.match(/mbps_wr=([0-9.]+)/i);
      if (mbpsWrM) diskOptions.mbps_wr = mbpsWrM[1];
      const iopsRdM = primaryDiskStr.match(/iops_rd=([0-9]+)/i);
      if (iopsRdM) diskOptions.iops_rd = iopsRdM[1];
      const iopsWrM = primaryDiskStr.match(/iops_wr=([0-9]+)/i);
      if (iopsWrM) diskOptions.iops_wr = iopsWrM[1];
    }

    // 7. Network bandwidth rate limit from net0
    let netRate = "";
    if (config.net0 && typeof config.net0 === "string") {
      const rateM = config.net0.match(/rate=([0-9.]+)/i);
      if (rateM) netRate = rateM[1];
    }

    // 8. Startup order & delay parameters
    let startupOrder = "";
    let startupUp = "";
    let startupDown = "";
    if (config.startup && typeof config.startup === "string") {
      const orderM = config.startup.match(/order=([0-9]+)/i);
      if (orderM) startupOrder = orderM[1];
      const upM = config.startup.match(/up=([0-9]+)/i);
      if (upM) startupUp = upM[1];
      const downM = config.startup.match(/down=([0-9]+)/i);
      if (downM) startupDown = downM[1];
    }

    // 9. Live Proxmox Name / Hostname synchronization
    const proxmoxName = config.name || config.hostname || row.name;
    if (proxmoxName && proxmoxName !== row.name) {
      db.prepare("UPDATE servers SET name=? WHERE node_id=? AND vmid=?").run(proxmoxName, row.node_id, row.vmid);
      row.name = proxmoxName;
    }

    // 10. Live QEMU Guest Agent reported IPs
    let guestIps = [];
    if (row.type === "qemu") {
      try {
        const agRes = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/qemu/${row.vmid}/agent/network-get-interfaces`);
        const ifaces = agRes?.result || agRes;
        if (Array.isArray(ifaces)) {
          for (const ifc of ifaces) {
            if (ifc.name === "lo") continue;
            const ips = ifc["ip-addresses"] || [];
            for (const ipObj of ips) {
              if (ipObj["ip-address-type"] === "ipv4" && !ipObj["ip-address"].startsWith("127.")) {
                guestIps.push(ipObj["ip-address"]);
              }
            }
          }
        }
      } catch {}
    }

    // 11. Standard Proxmox supported CPU models
    const cpuModels = [
      "host",
      "kvm64",
      "qemu64",
      "x86-64-v2-AES",
      "x86-64-v3",
      "x86-64-v4",
      "Broadwell",
      "Haswell",
      "Skylake-Client",
      "Skylake-Server",
      "Cascadelake-Server",
      "EPYC",
      "EPYC-Rome",
      "EPYC-Milan",
      "EPYC-Genoa"
    ];

    res.json({
      server: { ...row, pve_node: pveNode },
      config,
      status,
      bridges,
      users,
      diskKey,
      currentDiskGb,
      diskOptions,
      netRate,
      startupOrder,
      startupUp,
      startupDown,
      proxmoxName,
      guestIps,
      cpuModels,
      fetchedAt: new Date().toISOString()
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
    const pveNode = await ensureServerPveNode(row, node);

    const newName = req.body.name ? validateString(req.body.name, "Server name", 80) : row.name;
    const newUserId = (req.user.role === "admin" && req.body.userId) ? Number(req.body.userId) : row.user_id;

    // 1. Update Database record if name or user changed
    if (newName !== row.name || newUserId !== row.user_id) {
      if (newUserId !== row.user_id) {
        const existingForUser = db.prepare("SELECT id FROM servers WHERE node_id=? AND vmid=? AND user_id=?").get(row.node_id, row.vmid, newUserId);
        if (existingForUser) {
          return res.status(409).json({ error: "The target user is already assigned to this VPS." });
        }
      }
      db.prepare("UPDATE servers SET name=?, user_id=? WHERE id=?").run(newName, newUserId, id);
      db.prepare("UPDATE servers SET name=? WHERE node_id=? AND vmid=?").run(newName, row.node_id, row.vmid);
    }

    // 2. Prepare Proxmox config changes
    const configUpdate = {};
    const toDelete = [];

    // Name / Hostname in Proxmox
    if (row.type === "lxc") {
      configUpdate.hostname = newName;
    } else {
      configUpdate.name = newName;
    }

    const isAdmin = req.user.role === "admin";

    // Plan Expiry & Duration (Admin only)
    if (isAdmin && (req.body.expires_at !== undefined || req.body.duration_days !== undefined || req.body.lifetime !== undefined)) {
      let newExpiresAt = row.expires_at;
      let newDurationDays = row.duration_days || 0;
      if (req.body.lifetime === true || req.body.lifetime === "true" || req.body.expires_at === null || req.body.expires_at === "") {
        newExpiresAt = null;
        newDurationDays = 0;
      } else if (req.body.expires_at) {
        const d = new Date(req.body.expires_at);
        if (!isNaN(d.getTime())) {
          newExpiresAt = d.toISOString();
        }
      }
      if (req.body.duration_days !== undefined && !req.body.lifetime) {
        newDurationDays = Number(req.body.duration_days) || 0;
      }
      db.prepare("UPDATE servers SET expires_at=?, duration_days=? WHERE id=?").run(newExpiresAt, newDurationDays, id);

      // If set to lifetime or future expiration, clear expired_at and auto-unsuspend if suspended due to expiry
      if (!newExpiresAt || new Date(newExpiresAt).getTime() > Date.now()) {
        db.prepare("UPDATE servers SET expired_at = NULL WHERE id = ?").run(id);
        if (row.is_suspended && row.suspend_reason && row.suspend_reason.toLowerCase().includes("expired")) {
          db.prepare("UPDATE servers SET is_suspended = 0, suspended_at = NULL, suspend_reason = '' WHERE id = ?").run(id);
          if (typeof io !== "undefined" && io) {
            io.emit("vps:unsuspended", { id: row.id, vmid: row.vmid, is_suspended: 0 });
          }
        }
      }
    }

    // CPU, Sockets, Type, Limits & Memory (Admin only)
    if (isAdmin) {
      if (req.body.cores) {
        configUpdate.cores = Math.max(1, Math.min(128, Number(req.body.cores)));
      }
      if (row.type === "qemu") {
        if (req.body.sockets) {
          configUpdate.sockets = Math.max(1, Math.min(8, Number(req.body.sockets)));
        }
        if (req.body.cpu) {
          configUpdate.cpu = String(req.body.cpu).trim();
        }
        if (req.body.numa != null) {
          configUpdate.numa = (req.body.numa === true || req.body.numa === "true" || req.body.numa === 1 || req.body.numa === "on") ? 1 : 0;
        }
      }
      if (req.body.cpulimit != null && req.body.cpulimit !== "") {
        const lim = Number(req.body.cpulimit);
        if (lim > 0) configUpdate.cpulimit = lim;
        else toDelete.push("cpulimit");
      } else if (req.body.cpulimit === "") {
        toDelete.push("cpulimit");
      }
      if (req.body.cpuunits != null && req.body.cpuunits !== "") {
        const units = Number(req.body.cpuunits);
        if (units > 0) configUpdate.cpuunits = units;
        else toDelete.push("cpuunits");
      }
      if (req.body.memory) {
        configUpdate.memory = Math.max(256, Math.min(524288, Number(req.body.memory)));
      }
      if (row.type === "qemu") {
        if (req.body.balloon != null && req.body.balloon !== "" && Number(req.body.balloon) > 0) {
          configUpdate.balloon = Math.max(0, Math.min(524288, Number(req.body.balloon)));
        } else if (req.body.balloon === "" || Number(req.body.balloon) === 0) {
          toDelete.push("balloon");
        }
      }
      if (row.type === "lxc" && req.body.swap != null) {
        configUpdate.swap = Math.max(0, Math.min(65536, Number(req.body.swap)));
      }
    }

    // Network & IP Settings (Restricted strictly to Administrator only)
    if (isAdmin && req.body.bridge) {
      const bridge = validateString(req.body.bridge, "Bridge", 30);
      const vlan = req.body.vlan ? Number(req.body.vlan) : null;
      const mac = req.body.mac ? req.body.mac.trim() : null;
      const firewall = req.body.firewall != null ? (req.body.firewall === true || req.body.firewall === "true" || req.body.firewall === 1 || req.body.firewall === "on") : null;
      const netRate = req.body.netRate ? Number(req.body.netRate) : null;
      const net = buildIpConfig(req.body.ip4Type, req.body.ip4Address, req.body.ip4Gateway, req.body.ip6Type, req.body.ip6Address, req.body.ip6Gateway);

      if (row.type === "lxc") {
        let net0Str = `name=eth0,bridge=${bridge}`;
        if (vlan) net0Str += `,tag=${vlan}`;
        if (mac) net0Str += `,hwaddr=${mac}`;
        if (firewall) net0Str += `,firewall=1`;
        if (netRate && netRate > 0) net0Str += `,rate=${netRate}`;
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
        let net0Str = mac ? `virtio=${mac},bridge=${bridge}` : `virtio,bridge=${bridge}`;
        if (vlan) net0Str += `,tag=${vlan}`;
        if (firewall) net0Str += `,firewall=1`;
        if (netRate && netRate > 0) net0Str += `,rate=${netRate}`;
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

    // Primary Disk Options & Policies (Admin only, QEMU)
    if (isAdmin && row.type === "qemu") {
      let targetDiskKey = req.body.diskKey || "scsi0";
      try {
        const liveCfg = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/qemu/${row.vmid}/config`);
        if (!liveCfg[targetDiskKey]) {
          for (let i = 0; i < 16; i++) {
            const kCandidates = [`scsi${i}`, `virtio${i}`, `sata${i}`, `ide${i}`];
            for (const cand of kCandidates) {
              const val = liveCfg[cand] || "";
              if (val && typeof val === "string" && !val.includes("media=cdrom") && !val.includes("cloudinit") && !val.includes("none")) {
                targetDiskKey = cand;
                break;
              }
            }
            if (liveCfg[targetDiskKey]) break;
          }
        }
        const existingDiskStr = liveCfg[targetDiskKey] || "";
        if (existingDiskStr && typeof existingDiskStr === "string") {
          const parts = existingDiskStr.split(",");
          const volPart = parts[0];
          const sizePart = parts.find(p => p.startsWith("size=")) || "";
          let updatedParts = [volPart];
          if (sizePart) updatedParts.push(sizePart);

          const cacheMode = req.body.diskCache || "writeback";
          if (cacheMode) updatedParts.push(`cache=${cacheMode}`);

          if (req.body.discard === true || req.body.discard === "true" || req.body.discard === "on" || req.body.discard === 1) {
            updatedParts.push("discard=on");
          }
          if (req.body.ssd === true || req.body.ssd === "true" || req.body.ssd === "on" || req.body.ssd === 1) {
            updatedParts.push("ssd=1");
          }
          if (req.body.mbps_rd && Number(req.body.mbps_rd) > 0) updatedParts.push(`mbps_rd=${Number(req.body.mbps_rd)}`);
          if (req.body.mbps_wr && Number(req.body.mbps_wr) > 0) updatedParts.push(`mbps_wr=${Number(req.body.mbps_wr)}`);
          if (req.body.iops_rd && Number(req.body.iops_rd) > 0) updatedParts.push(`iops_rd=${Number(req.body.iops_rd)}`);
          if (req.body.iops_wr && Number(req.body.iops_wr) > 0) updatedParts.push(`iops_wr=${Number(req.body.iops_wr)}`);

          configUpdate[targetDiskKey] = updatedParts.join(",");
        }
      } catch (err) {
        console.warn("Could not pre-configure disk parameters:", err.message);
      }
    }

    // DNS Settings (Restricted to Administrator only)
    if (isAdmin) {
      if (req.body.searchDomain != null) {
        const sd = req.body.searchDomain.trim();
        if (sd) configUpdate.searchdomain = sd;
        else toDelete.push("searchdomain");
      }
      if (req.body.nameServers != null) {
        const ns = req.body.nameServers.trim();
        if (ns) configUpdate.nameserver = ns;
        else toDelete.push("nameserver");
      }
    }

    // Credentials & Keys (Owner / Client can update their root password and SSH keys)
    if (req.body.password && req.body.password.trim().length >= 8) {
      if (row.type === "qemu") {
        configUpdate.cipassword = req.body.password.trim();
      }
    }
    if (req.body.sshKey != null) {
      const k = req.body.sshKey.trim();
      if (row.type === "qemu") {
        if (k) configUpdate.sshkeys = encodeURIComponent(k);
        else toDelete.push("sshkeys");
      }
    }
    if (isAdmin && row.type === "qemu" && req.body.ciUser) {
      configUpdate.ciuser = req.body.ciUser.trim();
    }

    // Hypervisor Flags & Features (Restricted to Administrator only)
    if (isAdmin && row.type === "lxc") {
      const feats = [];
      if (req.body.nesting === true || req.body.nesting === "true" || req.body.nesting === "on" || req.body.nesting === 1) feats.push("nesting=1");
      if (req.body.keyctl === true || req.body.keyctl === "true" || req.body.keyctl === "on" || req.body.keyctl === 1) feats.push("keyctl=1");
      if (req.body.fuse === true || req.body.fuse === "true" || req.body.fuse === "on" || req.body.fuse === 1) feats.push("fuse=1");
      if (req.body.mknod === true || req.body.mknod === "true" || req.body.mknod === "on" || req.body.mknod === 1) feats.push("mknod=1");
      if (feats.length > 0) {
        configUpdate.features = feats.join(",");
      } else {
        toDelete.push("features");
      }
    }
    if (isAdmin && row.type === "qemu") {
      if (req.body.qemuAgent != null) {
        const agentOn = req.body.qemuAgent === true || req.body.qemuAgent === "true" || req.body.qemuAgent === "on" || req.body.qemuAgent === 1;
        configUpdate.agent = agentOn ? 1 : 0;
      }
      if (req.body.vga) {
        configUpdate.vga = String(req.body.vga).trim();
      }
      if (req.body.bios) {
        configUpdate.bios = String(req.body.bios).trim();
      }
      if (req.body.machine) {
        configUpdate.machine = String(req.body.machine).trim();
      }
    }

    // Boot & Autostart options (Restricted to Administrator only)
    if (isAdmin) {
      if (req.body.onboot != null) {
        configUpdate.onboot = (req.body.onboot === true || req.body.onboot === "true" || req.body.onboot === 1 || req.body.onboot === "1" || req.body.onboot === "on") ? 1 : 0;
      }
      if (req.body.startupOrder != null || req.body.startupUp != null || req.body.startupDown != null) {
        const sParts = [];
        if (req.body.startupOrder !== "" && req.body.startupOrder != null && Number(req.body.startupOrder) >= 0) sParts.push(`order=${Number(req.body.startupOrder)}`);
        if (req.body.startupUp !== "" && req.body.startupUp != null && Number(req.body.startupUp) >= 0) sParts.push(`up=${Number(req.body.startupUp)}`);
        if (req.body.startupDown !== "" && req.body.startupDown != null && Number(req.body.startupDown) >= 0) sParts.push(`down=${Number(req.body.startupDown)}`);
        if (sParts.length > 0) {
          configUpdate.startup = sParts.join(",");
        } else {
          toDelete.push("startup");
        }
      }
      if (row.type === "qemu") {
        if (req.body.boot != null && String(req.body.boot).trim()) {
          configUpdate.boot = String(req.body.boot).trim();
        } else if (req.body.boot === "") {
          toDelete.push("boot");
        }
      }
    }

    // Handle delete keys
    if (toDelete.length > 0) {
      configUpdate.delete = toDelete.join(",");
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
  const { site_name, site_description, seo_description, site_bg_type, site_bg_url, site_bg_opacity, site_bg_blur } = req.body;
  const site_icon = req.body.site_icon !== undefined ? req.body.site_icon : req.body.site_icon_url;
  const site_favicon = req.body.site_favicon !== undefined ? req.body.site_favicon : req.body.site_favicon_url;
  const og_image = req.body.og_image !== undefined ? req.body.og_image : req.body.og_image_url;

  const isValidUrl = (url) => !url || url.startsWith("/") || url.startsWith("http://") || url.startsWith("https://");

  if (site_name !== undefined) setSetting("site_name", String(site_name).trim().slice(0, 100));
  if (site_description !== undefined) setSetting("site_description", String(site_description).trim().slice(0, 500));
  if (site_icon !== undefined) {
    const s = String(site_icon).trim().slice(0, 2000);
    if (isValidUrl(s)) setSetting("site_icon", s);
  }
  if (site_favicon !== undefined) {
    const s = String(site_favicon).trim().slice(0, 2000);
    if (isValidUrl(s)) setSetting("site_favicon", s);
  }
  if (og_image !== undefined) {
    const s = String(og_image).trim().slice(0, 2000);
    if (isValidUrl(s)) setSetting("og_image", s);
  }
  if (seo_description !== undefined) setSetting("seo_description", String(seo_description).trim().slice(0, 1000));

  if (site_bg_type !== undefined) {
    const safeType = ["none", "image", "video"].includes(site_bg_type) ? site_bg_type : "none";
    setSetting("site_bg_type", safeType);
  }
  if (site_bg_url !== undefined) {
    const s = String(site_bg_url).trim().slice(0, 2000);
    if (isValidUrl(s)) setSetting("site_bg_url", s);
  }
  if (site_bg_opacity !== undefined) {
    const num = Math.min(100, Math.max(0, parseInt(site_bg_opacity, 10) || 55));
    setSetting("site_bg_opacity", String(num));
  }
  if (site_bg_blur !== undefined) {
    const num = Math.min(30, Math.max(0, parseInt(site_bg_blur, 10) || 0));
    setSetting("site_bg_blur", String(num));
  }

  if (req.body.allow_registration !== undefined) {
    const allow = req.body.allow_registration === true || req.body.allow_registration === "1" || req.body.allow_registration === 1 || req.body.allow_registration === "true";
    setSetting("allow_registration", allow ? "1" : "0");
  }

  audit(req.user.id, "settings_update", "Updated site branding, background, registration & SEO settings", req);
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
  const users = db.prepare("SELECT id, uuid, username, email, role, active, created_at, avatar_url FROM users ORDER BY id DESC").all();
  let identities = [];
  try {
    identities = db.prepare("SELECT user_id, provider, provider_user_id, provider_username, linked_at FROM user_identities").all();
  } catch {}
  const identityMap = new Map();
  for (const ident of identities) {
    if (!identityMap.has(ident.user_id)) identityMap.set(ident.user_id, []);
    identityMap.get(ident.user_id).push(ident);
  }
  const result = users.map(u => ({
    ...safeUser(u),
    identities: identityMap.get(u.id) || []
  }));
  res.json({ users: result });
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
    const userUuid = "usr_" + crypto.randomUUID();
    const result = db.prepare("INSERT INTO users(username,email,password_hash,role,uuid) VALUES(?,?,?,?,?)").run(username,email,hash,role,userUuid);
    audit(req.user.id, "user_create", `${username} (${role})`, req);
    res.status(201).json({ user: safeUser(db.prepare("SELECT * FROM users WHERE id=?").get(result.lastInsertRowid)) });
  } catch (e) { if (String(e.message).includes("UNIQUE")) e.status = 409; next(e); }
});
app.patch("/api/admin/users/:id", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const target = db.prepare("SELECT * FROM users WHERE id=?").get(id);
    if (!target) return res.status(404).json({ error: "User not found." });

    const newActive = typeof req.body.active === "boolean" ? (req.body.active ? 1 : 0) : (req.body.active !== undefined ? (Number(req.body.active) ? 1 : 0) : target.active);
    const newRole = req.body.role ? (req.body.role === "admin" ? "admin" : "user") : target.role;

    if (id === req.user.id && newActive === 0) {
      return res.status(400).json({ error: "You cannot disable your own administrator account." });
    }
    if (id === req.user.id && newRole !== "admin") {
      return res.status(400).json({ error: "You cannot revoke your own administrator role." });
    }

    if (target.role === "admin" && (newActive === 0 || newRole === "user")) {
      const activeAdminCount = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role='admin' AND active=1 AND id!=?").get(id).c;
      if (activeAdminCount < 1) {
        return res.status(400).json({ error: "Cannot modify this user: platform must have at least one active administrator." });
      }
    }

    let newUsername = target.username;
    if (req.body.username && typeof req.body.username === "string" && req.body.username.trim() && req.body.username.trim() !== target.username) {
      const u = validateString(req.body.username.trim(), "Username", 32);
      if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(u)) {
        return res.status(400).json({ error: "Username must be 3–32 characters (letters, numbers, . _ -)." });
      }
      const existing = db.prepare("SELECT id FROM users WHERE username=? COLLATE NOCASE AND id!=?").get(u, id);
      if (existing) {
        return res.status(409).json({ error: "Username is already taken by another account." });
      }
      newUsername = u;
    }

    let newEmail = target.email;
    if (req.body.email && typeof req.body.email === "string" && req.body.email.trim() && req.body.email.trim().toLowerCase() !== target.email.toLowerCase()) {
      const e = validateString(req.body.email.trim().toLowerCase(), "Email", 120);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) {
        return res.status(400).json({ error: "Please enter a valid email address." });
      }
      const existing = db.prepare("SELECT id FROM users WHERE email=? COLLATE NOCASE AND id!=?").get(e, id);
      if (existing) {
        return res.status(409).json({ error: "Email address is already in use by another account." });
      }
      newEmail = e;
    }

    let newHash = target.password_hash;
    if (req.body.password && typeof req.body.password === "string" && req.body.password.trim()) {
      const p = req.body.password.trim();
      if (p.length < 8) {
        return res.status(400).json({ error: "New password must be at least 8 characters long." });
      }
      newHash = await bcrypt.hash(p, 12);
    }

    db.prepare(`
      UPDATE users SET
        username = ?,
        email = ?,
        password_hash = ?,
        role = ?,
        active = ?
      WHERE id = ?
    `).run(newUsername, newEmail, newHash, newRole, newActive, id);

    audit(req.user.id, "user_edit", `Edited user #${id} (${newUsername}, role: ${newRole}, active: ${newActive})`, req);
    const updated = db.prepare("SELECT * FROM users WHERE id=?").get(id);
    res.json({ ok: true, user: safeUser(updated) });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) e.status = 409;
    next(e);
  }
});
app.delete("/api/admin/users/:id", requireAuth, requireAdmin, (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (id === req.user.id) return res.status(400).json({ error: "You cannot delete your own account." });
    const target = db.prepare("SELECT * FROM users WHERE id=?").get(id);
    if (!target) return res.status(404).json({ error: "User not found." });

    if (target.role === "admin") {
      const activeAdminCount = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role='admin' AND active=1 AND id!=?").get(id).c;
      if (activeAdminCount < 1) {
        return res.status(400).json({ error: "Cannot delete the last active administrator." });
      }
    }

    db.prepare("DELETE FROM servers WHERE user_id=?").run(id);
    db.prepare("DELETE FROM users WHERE id=?").run(id);
    audit(req.user.id, "user_delete", `User ${id} (${target.username})`, req);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.get("/api/nodes/health", requireAuth, (req, res) => {
  const nodes = db.prepare("SELECT id, name, host, port, enabled FROM nodes WHERE enabled = 1").all();
  const list = nodes.map(n => {
    const h = nodeHealthState.get(n.id);
    return {
      id: n.id,
      name: n.name,
      host: n.host,
      port: n.port,
      status: h ? h.status : "unknown",
      reason: h ? h.reason : null,
      message: h ? h.message : null,
      updated_at: h ? h.updatedAt : null
    };
  });
  res.json({ ok: true, nodes: list });
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
    const users = db.prepare("SELECT id, username, email, role FROM users WHERE active=1 ORDER BY username ASC").all();

    if (nodes.length === 0) {
      return res.json({ ok: true, nodes: [], users, error: "No enabled Proxmox nodes found." });
    }

    const requestedNodeId = req.query.nodeId ? Number(req.query.nodeId) : nodes[0].id;
    const node = getNode(requestedNodeId);

    // Resolve internal node name
    let pveNode = "";
    try {
      const nodesList = await pve(node, "GET", "/nodes");
      if (Array.isArray(nodesList)) {
        const found = nodesList.find(n => n.node === node.name || n.status === "online") || nodesList[0];
        pveNode = found?.node || "";
      }
    } catch {}
    if (!pveNode) pveNode = node.name.toLowerCase().replace(/[^a-z0-9_-]/g, "");

    // 1. Node system stats & hardware summary
    let nodeStats = null;
    try {
      const statusRes = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/status`);
      if (statusRes) {
        nodeStats = {
          node: pveNode,
          cpuModel: statusRes.cpuinfo?.model || "",
          cpus: statusRes.cpuinfo?.cpus || statusRes.cpus || 0,
          memoryTotal: statusRes.memory?.total || 0,
          memoryFree: statusRes.memory?.free || 0,
          memoryUsed: statusRes.memory?.used || 0,
          pveVersion: statusRes.pveversion || ""
        };
      }
    } catch {}

    // 2. Next free VMID
    let nextVmid = 100;
    try {
      const nid = await pve(node, "GET", "/cluster/nextid");
      if (nid) nextVmid = Number(nid);
    } catch {
      const maxRow = db.prepare("SELECT MAX(vmid) as max FROM servers WHERE node_id=?").get(node.id);
      nextVmid = (maxRow?.max || 100) + 1;
    }

    // 3. QEMU Templates (Real templates on this node or cluster)
    let qemuTemplates = [];
    try {
      const allVms = await pve(node, "GET", "/cluster/resources?type=vm");
      if (Array.isArray(allVms)) {
        qemuTemplates = allVms
          .filter(v => v.template === 1 && v.type === "qemu" && (v.node === pveNode || !v.node))
          .map(v => ({
            id: v.vmid,
            vmid: v.vmid,
            name: v.name || `Template ${v.vmid}`,
            type: "qemu",
            node: v.node || pveNode,
            disk: v.maxdisk || 0,
            mem: v.maxmem || 0,
            cpus: v.maxcpu || 1
          }));
      }
    } catch {}
    if (qemuTemplates.length === 0) {
      try {
        const qList = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/qemu`);
        if (Array.isArray(qList)) {
          qemuTemplates = qList
            .filter(v => v.template === 1)
            .map(v => ({
              id: v.vmid,
              vmid: v.vmid,
              name: v.name || `Template ${v.vmid}`,
              type: "qemu",
              node: pveNode,
              disk: v.maxdisk || 0,
              mem: v.maxmem || 0,
              cpus: v.maxcpu || 1
            }));
        }
      } catch {}
    }

    // 4. Storages: query real storages on this node
    let allStorages = [];
    let vmStorages = [];
    let ctStorages = [];
    let isoStorages = [];
    let vztmplStorages = [];
    try {
      const stList = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage`);
      if (Array.isArray(stList)) {
        allStorages = stList.map(s => ({
          storage: s.storage,
          type: s.type || "",
          content: s.content || "",
          avail: s.avail || 0,
          total: s.total || 0,
          used: s.used || 0,
          shared: s.shared === 1,
          enabled: s.enabled !== 0 && s.active !== 0
        }));

        vmStorages = allStorages.filter(s => s.enabled && s.content.includes("images"));
        ctStorages = allStorages.filter(s => s.enabled && s.content.includes("rootdir"));
        isoStorages = allStorages.filter(s => s.enabled && s.content.includes("iso"));
        vztmplStorages = allStorages.filter(s => s.enabled && s.content.includes("vztmpl"));
      }
    } catch {}

    const diskStorages = allStorages.filter(s => s.enabled && (s.content.includes("images") || s.content.includes("rootdir")));

    // 5. ISOs across real ISO storages
    let isoList = [];
    try {
      const searchStorages = isoStorages.length > 0 ? isoStorages.map(s => s.storage) : ["local"];
      for (const st of searchStorages) {
        try {
          const res = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage/${encodeURIComponent(st)}/content?content=iso`);
          if (Array.isArray(res)) {
            for (const item of res) {
              if (item.volid) {
                isoList.push({
                  volid: item.volid,
                  name: item.volid.split("/").pop() || item.volid,
                  storage: st,
                  size: item.size || 0,
                  format: item.format || "iso"
                });
              }
            }
          }
        } catch {}
      }
    } catch {}

    // 6. LXC Templates: (A) Locally downloaded vztmpl + (B) Online appliance repository
    let localLxcTemplates = [];
    try {
      const vzStorages = vztmplStorages.length > 0 ? vztmplStorages.map(s => s.storage) : ["local"];
      for (const st of vzStorages) {
        try {
          const res = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage/${encodeURIComponent(st)}/content?content=vztmpl`);
          if (Array.isArray(res)) {
            for (const item of res) {
              if (item.volid) {
                localLxcTemplates.push({
                  volid: item.volid,
                  package: item.volid.split("/").pop(),
                  name: item.volid.split("/").pop(),
                  storage: st,
                  size: item.size || 0,
                  isLocal: true
                });
              }
            }
          }
        } catch {}
      }
    } catch {}

    let onlineLxcTemplates = [];
    try {
      const apl = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/aplinfo`);
      if (Array.isArray(apl)) {
        const x64 = apl.filter(x => x.architecture === "amd64" || !x.architecture);
        onlineLxcTemplates = x64.map(x => ({
          volid: x.template,
          package: x.package,
          name: x.headline || x.package,
          section: x.section || "system",
          version: x.version || "",
          description: x.description || "",
          isLocal: false
        }));
      }
    } catch {}

    // Combined LXC templates list
    let lxcTemplates = [...localLxcTemplates];
    if (onlineLxcTemplates.length > 0) {
      for (const onl of onlineLxcTemplates) {
        if (!lxcTemplates.some(t => t.volid === onl.volid || t.package === onl.package)) {
          lxcTemplates.push(onl);
        }
      }
    }

    // 7. Network Bridges: Real live interfaces from Proxmox
    let bridges = [];
    try {
      const net = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/network`);
      if (Array.isArray(net)) {
        bridges = net
          .filter(x => x.type === "bridge" || String(x.iface).startsWith("vmbr"))
          .map(x => ({
            iface: x.iface,
            cidr: x.cidr || (x.address ? `${x.address}/${x.netmask || '24'}` : ""),
            address: x.address || "",
            gateway: x.gateway || "",
            ports: x.bridge_ports || "",
            active: x.active === 1 || x.active === true || x.exists === 1,
            comment: x.comments || x.comment || ""
          }));
      }
    } catch {}
    if (bridges.length === 0) {
      bridges = [{ iface: "vmbr0", cidr: "", gateway: "", ports: "", active: true, comment: "" }];
    }
    // Sort so vmbr0 or bridge with active gateway is first
    bridges.sort((a, b) => {
      if (a.gateway && !b.gateway) return -1;
      if (!a.gateway && b.gateway) return 1;
      return a.iface.localeCompare(b.iface);
    });

    // 8. CPU Models: Query real supported CPU capabilities from Proxmox VE
    let pveCpuModels = [];
    try {
      const caps = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/capabilities/qemu/cpu`);
      if (Array.isArray(caps)) {
        pveCpuModels = caps.map(c => ({
          name: c.name,
          vendor: c.vendor || "",
          custom: c.custom === 1
        }));
      }
    } catch {}

    const standardCpus = [
      { name: "host", desc: "host (Host CPU passthrough - Maximum performance & AES-NI)" },
      { name: "x86-64-v2-AES", desc: "x86-64-v2-AES (Recommended for cluster migration)" },
      { name: "x86-64-v3", desc: "x86-64-v3 (AVX, AVX2, modern instructions)" },
      { name: "kvm64", desc: "kvm64 (Proxmox standard universal compatibility)" },
      { name: "qemu64", desc: "qemu64 (QEMU default)" },
      { name: "max", desc: "max (All features supported by host)" }
    ];

    const cpuModels = [...standardCpus];
    for (const p of pveCpuModels) {
      if (!cpuModels.some(c => c.name === p.name)) {
        cpuModels.push({
          name: p.name,
          desc: `${p.name} ${p.vendor ? `(${p.vendor})` : ''}`
        });
      }
    }

    // 9. Check Datastore permissions
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
      nodeStats,
      nodes,
      users,
      nextVmid,
      qemuTemplates,
      lxcTemplates,
      localLxcTemplates,
      isoList,
      storages: diskStorages,
      vmStorages,
      ctStorages,
      isoStorages,
      vztmplStorages,
      allStorages,
      cpuModels,
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
    const provisionMethod = (req.body.provisionMethod === "iso" || req.body.source === "iso") ? "iso" : (req.body.source === "none" ? "none" : "template");

    const createDurationDays = req.body.duration_days !== undefined && req.body.duration_days !== null ? Number(req.body.duration_days) : (req.body.duration ? Number(req.body.duration) : 0);
    const createExplicitExpiresAt = req.body.expires_at || null;
    const { expires_at: serverExpiresAt, duration_days: serverDurationDays } = computeServerExpiry(createDurationDays, createExplicitExpiresAt, 0);

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
      if (Array.isArray(nodesList)) {
        const found = nodesList.find(n => n.node === node.name || n.status === "online") || nodesList[0];
        pveNode = found?.node || "";
      }
    } catch {}
    if (!pveNode) pveNode = node.name.toLowerCase().replace(/[^a-z0-9_-]/g, "");

    // Check if VMID is already taken in panel database
    const existingInDb = db.prepare("SELECT id FROM servers WHERE node_id=? AND vmid=?").get(nodeId, vmid);
    if (existingInDb) {
      return res.status(409).json({ error: `A VPS with VMID ${vmid} already exists in the panel database.` });
    }

    // CPU Specifications
    const cores = Math.max(1, Math.min(128, Number(req.body.cores || 2)));
    const sockets = Math.max(1, Math.min(8, Number(req.body.sockets || 1)));
    const cpu = validateString(req.body.cpu || "host", "CPU Model", 50);
    const numa = req.body.numa === true || req.body.numa === "true" || req.body.numa === 1 || req.body.numa === "1";

    // Memory Specifications
    const memory = Math.max(256, Math.min(1048576, Number(req.body.memory || 2048)));
    const balloon = req.body.balloon != null && req.body.balloon !== "" && Number(req.body.balloon) > 0 ? Number(req.body.balloon) : null;
    const swap = Math.max(0, Math.min(65536, Number(req.body.swap != null ? req.body.swap : 512)));

    // Storage & Disk Configuration
    const diskSize = Math.max(1, Math.min(50000, Number(req.body.disk || req.body.diskSize || req.body.disk_size || 25)));
    const storage = validateString(req.body.storage || "local-lvm", "Storage", 50);
    const diskBus = ["scsi", "virtio", "sata", "ide"].includes(req.body.diskBus) ? req.body.diskBus : "scsi";
    const diskCache = ["none", "writeback", "writethrough", "directsync"].includes(req.body.diskCache) ? req.body.diskCache : "none";
    const discard = req.body.discard !== false && req.body.discard !== "false" && req.body.discard !== 0;
    const ssd = req.body.ssd !== false && req.body.ssd !== "false" && req.body.ssd !== 0;
    const iothread = req.body.iothread !== false && req.body.iothread !== "false" && req.body.iothread !== 0;

    // QEMU System Options
    const machine = req.body.machine === "i440fx" ? "i440fx" : "q35";
    const bios = req.body.bios === "ovmf" ? "ovmf" : "seabios";
    const vga = ["std", "serial0", "virtio", "qxl"].includes(req.body.vga) ? req.body.vga : "std";
    const scsihw = ["virtio-scsi-single", "virtio-scsi", "lsi", "megaraid", "pvscsi"].includes(req.body.scsihw) ? req.body.scsihw : "virtio-scsi-single";

    // Network & IP Settings
    const bridge = validateString(req.body.bridge || "vmbr0", "Bridge", 30);
    const netModel = ["virtio", "e1000", "vmxnet3", "rtl8139"].includes(req.body.netModel) ? req.body.netModel : "virtio";
    const netifName = req.body.netifName && typeof req.body.netifName === "string" ? req.body.netifName.trim() : "eth0";
    const vlan = req.body.vlan ? Number(req.body.vlan) : null;
    const mac = req.body.mac && typeof req.body.mac === "string" && req.body.mac.trim() ? req.body.mac.trim() : null;
    const firewall = req.body.firewall !== false && req.body.firewall !== "false" && req.body.firewall !== 0 && req.body.firewall !== "0";
    const rateLimit = req.body.rateLimit && Number(req.body.rateLimit) > 0 ? Number(req.body.rateLimit) : null;

    const net = buildIpConfig(req.body.ip4Type, req.body.ip4Address, req.body.ip4Gateway, req.body.ip6Type, req.body.ip6Address, req.body.ip6Gateway);

    // DNS Settings
    const searchDomain = req.body.searchDomain && typeof req.body.searchDomain === "string" ? req.body.searchDomain.trim() : "";
    const nameServers = req.body.nameServers && typeof req.body.nameServers === "string" ? req.body.nameServers.trim() : "";

    // Credentials & Keys
    const password = req.body.password && typeof req.body.password === "string" ? req.body.password.trim() : "";
    const sshKey = req.body.sshKey && typeof req.body.sshKey === "string" ? req.body.sshKey.trim() : "";
    const ciUser = req.body.ciUser && typeof req.body.ciUser === "string" && req.body.ciUser.trim() ? req.body.ciUser.trim() : "root";

    // Boot & Startup Options
    const onboot = req.body.onboot === true || req.body.onboot === "true" || req.body.onboot === 1 || req.body.onboot === "1";
    const startAfterCreate = req.body.start !== false && req.body.startAfterCreate !== false && req.body.start !== "false" && req.body.startAfterCreate !== "false";

    // Container / QEMU Options
    const unprivileged = req.body.unprivileged !== false && req.body.unprivileged !== "false";
    const nesting = req.body.nesting !== false && req.body.nesting !== "false";
    const keyctl = req.body.keyctl === true || req.body.keyctl === "true" || req.body.keyctl === 1 || req.body.keyctl === "1";
    const fuse = req.body.fuse === true || req.body.fuse === "true" || req.body.fuse === 1 || req.body.fuse === "1";
    const ciUpgrade = req.body.ciUpgrade === true || req.body.ciUpgrade === "true" || req.body.ciUpgrade === 1 || req.body.ciUpgrade === "1";
    const qemuAgent = req.body.qemuAgent !== false && req.body.qemuAgent !== "false";

    if (provisionMethod === "template" && password.length < 8) {
      return res.status(400).json({ error: "Root password must be at least 8 characters long." });
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
          await waitForPveTask(node, pveNode, cloneTask, 180);
        } catch (err) {
          if (String(err.message).includes("AllocateSpace")) {
            return res.status(403).json({
              error: "Proxmox permission required: Datastore.AllocateSpace. Please add role 'PVEDatastoreUser' or 'Administrator' to API token in Proxmox VE (Datacenter -> Permissions)."
            });
          }
          throw new Error(`Failed to clone VM template: ${err.message}`);
        }

        // Build net0 string
        let net0Str = `${netModel}`;
        if (mac) net0Str += `=${mac}`;
        net0Str += `,bridge=${bridge}`;
        if (vlan) net0Str += `,tag=${vlan}`;
        if (firewall) net0Str += `,firewall=1`;
        if (rateLimit) net0Str += `,rate=${rateLimit}`;

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
          cpu,
          memory,
          net0: net0Str,
          ipconfig0: ipconfig0Str,
          ciuser: ciUser,
          cipassword: password
        };
        if (numa) configUpdate.numa = 1;
        if (balloon != null && balloon > 0) configUpdate.balloon = balloon;
        if (scsihw) configUpdate.scsihw = scsihw;
        if (vga) configUpdate.vga = vga;
        if (onboot) configUpdate.onboot = 1;
        if (sshKey) configUpdate.sshkeys = encodeURIComponent(sshKey);
        if (searchDomain) configUpdate.searchdomain = searchDomain;
        if (nameServers) configUpdate.nameserver = nameServers;
        if (ciUpgrade) configUpdate.ciupgrade = 1;
        if (qemuAgent) configUpdate.agent = 1;

        await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu/${vmid}/config`, configUpdate);

        // Resize disk to target size if larger
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
        // Provision from ISO or Blank Disk
        const isoVolid = req.body.iso || req.body.isoVolid || "";
        const osType = req.body.osType && ["l26", "win11", "win10", "other"].includes(req.body.osType) ? req.body.osType : "l26";

        let net0Qemu = `${netModel}`;
        if (mac) net0Qemu += `=${mac}`;
        net0Qemu += `,bridge=${bridge}`;
        if (vlan) net0Qemu += `,tag=${vlan}`;
        if (firewall) net0Qemu += `,firewall=1`;
        if (rateLimit) net0Qemu += `,rate=${rateLimit}`;

        const createParams = {
          vmid,
          name,
          memory,
          cores,
          sockets,
          cpu,
          ostype: osType,
          machine,
          bios,
          vga,
          scsihw,
          net0: net0Qemu,
          agent: qemuAgent ? 1 : 0
        };
        if (numa) createParams.numa = 1;
        if (onboot) createParams.onboot = 1;
        if (balloon != null && balloon > 0) createParams.balloon = balloon;

        let diskOptions = `${storage}:${diskSize}`;
        if (discard) diskOptions += ",discard=on";
        if (ssd) diskOptions += ",ssd=1";
        if (iothread) diskOptions += ",iothread=1";
        if (diskCache && diskCache !== "none") diskOptions += `,cache=${diskCache}`;

        const diskKey = `${diskBus}0`;
        createParams[diskKey] = diskOptions;

        if (isoVolid && isoVolid !== "__none__" && isoVolid !== "__custom__") {
          createParams.ide2 = `${isoVolid},media=cdrom`;
          createParams.boot = `order=ide2;${diskKey}`;
        } else {
          createParams.boot = `order=${diskKey}`;
        }

        try {
          const createTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu`, createParams);
          await waitForPveTask(node, pveNode, createTask, 90);
        } catch (err) {
          if (String(err.message).includes("AllocateSpace")) {
            return res.status(403).json({
              error: "Proxmox permission required: Datastore.AllocateSpace. Please add role 'PVEDatastoreUser' or 'Administrator' to API token in Proxmox VE (Datacenter -> Permissions)."
            });
          }
          throw new Error(`Failed to create VM: ${err.message}`);
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
      let net0Lxc = `name=${netifName},bridge=${bridge}`;
      if (mac) net0Lxc += `,hwaddr=${mac}`;
      if (vlan) net0Lxc += `,tag=${vlan}`;
      if (firewall) net0Lxc += `,firewall=1`;
      if (rateLimit) net0Lxc += `,rate=${rateLimit}`;

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

      // Automatically check and download template if not already present on Proxmox VE
      const verifiedTemplate = await ensureLxcTemplateDownloaded(node, pveNode, templateVolid, "local");

      const featureList = [];
      if (nesting) featureList.push("nesting=1");
      if (keyctl) featureList.push("keyctl=1");
      if (fuse) featureList.push("fuse=1");

      const createParams = {
        vmid,
        hostname: name,
        ostemplate: verifiedTemplate,
        cores,
        memory,
        swap,
        net0: net0Lxc,
        rootfs: `${storage}:${diskSize},acl=1`,
        password,
        unprivileged: unprivileged ? 1 : 0
      };
      if (featureList.length > 0) createParams.features = featureList.join(",");
      if (onboot) createParams.onboot = 1;
      if (sshKey) createParams["ssh-public-keys"] = encodeURIComponent(sshKey);
      if (searchDomain) createParams.searchdomain = searchDomain;
      if (nameServers) createParams.nameserver = nameServers;

      try {
        const createTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/lxc`, createParams);
        await waitForPveTask(node, pveNode, createTask, 120);
      } catch (err) {
        const errMsg = String(err.message).toLowerCase();
        if (errMsg.includes("does not exist") || errMsg.includes("no such file")) {
          const forcedVolid = await ensureLxcTemplateDownloaded(node, pveNode, templateVolid, "local", true);
          createParams.ostemplate = forcedVolid;
          const retryTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/lxc`, createParams);
          await waitForPveTask(node, pveNode, retryTask, 120);
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

    // Insert newly created server into panel SQLite database with duration & expiry
    const result = db.prepare(`
      INSERT INTO servers(user_id, node_id, vmid, type, pve_node, name, expires_at, duration_days)
      VALUES(?, ?, ?, ?, ?, ?, ?, ?)
    `).run(userId, nodeId, vmid, type, pveNode, name, serverExpiresAt, serverDurationDays);

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
    // Check if this exact VPS is already assigned to this specific user
    const alreadyAssigned = db.prepare("SELECT id FROM servers WHERE node_id=? AND vmid=? AND user_id=?").get(nodeId, vmid, userId);
    if (alreadyAssigned) {
      return res.status(409).json({ error: `This VPS (VMID ${vmid}) is already assigned to this user.` });
    }

    const result = db.prepare("INSERT INTO servers(user_id,node_id,vmid,type,pve_node,name) VALUES(?,?,?,?,?,?)").run(userId,nodeId,vmid,type,pveNode,name);
    audit(req.user.id, "server_assign", `${type}:${vmid} (node: ${pveNode}) to user ${userId}`, req);
    io.emit("vps:list_changed");
    setTimeout(pollLiveMetrics, 300);
    res.status(201).json({ ok: true, id: result.lastInsertRowid, pve_node: pveNode, type });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) {
      return res.status(409).json({ error: `This VPS is already assigned to this user.` });
    }
    next(e);
  }
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

async function destroyVpsHandler(req, res, next) {
  try {
    const sId = Number(req.params.id);
    if (!sId || isNaN(sId)) {
      return res.status(400).json({ error: "Invalid server ID." });
    }

    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Administrator privileges required to permanently destroy virtual servers." });
    }

    if (req.apiKey) {
      const scopes = (req.apiKey.scopes || "").split(",").map(x => x.trim());
      const hasPerm = scopes.includes("*") || scopes.includes("admin") || scopes.includes("servers:delete") || scopes.includes("vps:write");
      if (!hasPerm) {
        return res.status(403).json({ error: "API key lacks 'servers:delete' or 'vps:write' scope." });
      }
    }

    const s = db.prepare(`
      SELECT s.*, n.name AS node_name, n.host, n.port, n.token_id, n.token_secret_enc, n.tls_verify, n.enabled, u.username
      FROM servers s
      LEFT JOIN nodes n ON n.id = s.node_id
      LEFT JOIN users u ON u.id = s.user_id
      WHERE s.id = ?
    `).get(sId);

    if (!s) {
      return res.status(404).json({ error: "Server not found." });
    }

    const confirmVmid = req.body && req.body.confirm_vmid ? String(req.body.confirm_vmid).trim() : (req.query.confirm_vmid ? String(req.query.confirm_vmid).trim() : null);
    if (confirmVmid && confirmVmid !== String(s.vmid)) {
      return res.status(400).json({ error: `Confirmation VMID '${confirmVmid}' does not match target VMID ${s.vmid}.` });
    }

    const purge = (req.body?.purge === 0 || req.body?.purge === false || req.query?.purge === "0" || req.query?.purge === "false") ? 0 : 1;
    const rawDisks = req.body?.["destroy-unreferenced-disks"] ?? req.body?.destroy_unreferenced_disks ?? req.query?.["destroy-unreferenced-disks"] ?? req.query?.destroy_unreferenced_disks;
    const destroyDisks = (rawDisks === 0 || rawDisks === false || rawDisks === "0" || rawDisks === "false") ? 0 : 1;
    const isForce = Boolean(req.body?.force || req.query?.force === "true" || req.query?.force === "1");

    let pveNode = s.pve_node || s.node_name || "proxmox";
    let upid = null;
    let pveError = null;

    if (s.node_id) {
      let node = null;
      try {
        node = getNode(s.node_id);
      } catch (err) {
        if (!isForce) throw err;
      }

      if (node && node.enabled) {
        try {
          pveNode = await ensureServerPveNode(s, node);
        } catch {}

        try {
          const st = await pve(node, "GET", serverEndpoint(s, "/status/current"));
          if (st && (st.status === "running" || st.qmpstatus === "running")) {
            try {
              await pve(node, "POST", serverEndpoint(s, "/status/stop"));
              for (let i = 0; i < 10; i++) {
                await new Promise(r => setTimeout(r, 1000));
                try {
                  const checkSt = await pve(node, "GET", serverEndpoint(s, "/status/current"));
                  if (!checkSt || checkSt.status === "stopped") break;
                } catch {
                  break;
                }
              }
            } catch (stopErr) {
              console.warn(`[Destroy] Warning while stopping VM ${s.vmid}:`, stopErr.message);
            }
          }
        } catch (statusErr) {}

        try {
          const pveDeleteUrl = `/nodes/${encodeURIComponent(pveNode)}/${s.type}/${s.vmid}?purge=${purge}&destroy-unreferenced-disks=${destroyDisks}`;
          upid = await pve(node, "DELETE", pveDeleteUrl);
        } catch (delErr) {
          const msg = delErr.originalMessage || delErr.message || "";
          if (msg.includes("does not exist") || msg.includes("not found") || delErr.status === 404) {
            // Already destroyed on Proxmox VE
          } else if (isForce) {
            pveError = msg;
            console.warn(`[Destroy] Forced removal of VM #${s.vmid} despite Proxmox error: ${msg}`);
          } else {
            throw new Error(`Proxmox VE error while destroying guest #${s.vmid}: ${msg}`);
          }
        }
      }
    }

    try {
      db.prepare(`
        UPDATE template_ips SET
          status = 'available',
          server_id = NULL,
          assigned_vmid = NULL,
          assigned_server_name = '',
          assigned_user_id = NULL,
          assigned_user_name = '',
          assigned_at = NULL
        WHERE server_id = ? OR assigned_vmid = ?
      `).run(s.id, s.vmid);
    } catch (ipErr) {
      console.warn("[Destroy] Error freeing template_ips:", ipErr.message);
    }

    for (const [sessId, sess] of activeConsoleSessions.entries()) {
      if (sess.server && (sess.server.id === s.id || sess.server.vmid === s.vmid)) {
        activeConsoleSessions.delete(sessId);
      }
    }

    db.prepare("DELETE FROM servers WHERE id = ?").run(s.id);

    audit(
      req.user.id,
      "vps_destroy",
      `Permanently destroyed ${s.type.toUpperCase()} #${s.vmid} (${s.name}) on node ${pveNode} (purge=${purge}, destroy-unreferenced-disks=${destroyDisks})${pveError ? ` [PVE warning: ${pveError}]` : ''}`,
      req
    );

    io.emit("vps:deleted", { id: s.id, vmid: s.vmid, name: s.name });
    io.emit("vps:list_changed");
    setTimeout(pollLiveMetrics, 300);

    res.json({
      ok: true,
      message: `Virtual server #${s.vmid} (${s.name}) was permanently destroyed and deleted from Proxmox VE.`,
      vmid: s.vmid,
      name: s.name,
      type: s.type,
      node: pveNode,
      upid,
      purge: Boolean(purge),
      destroy_unreferenced_disks: Boolean(destroyDisks),
      pve_warning: pveError || null
    });
  } catch (e) {
    next(e);
  }
}

app.delete("/api/servers/:id", requireAuth, requireAdmin, destroyVpsHandler);
app.delete("/api/admin/servers/:id", requireAuth, requireAdmin, destroyVpsHandler);

app.get("/api/admin/logs", requireAuth, requireAdmin, (req, res) => {
  const logs = db.prepare("SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200").all();
  res.json({ logs });
});

app.get("/api/admin/tasks", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const nodes = db.prepare("SELECT * FROM nodes WHERE enabled = 1").all();
    if (!nodes.length) return res.json({ tasks: [] });

    const results = await Promise.allSettled(nodes.map(async (n) => {
      try {
        const list = await pve(n, "GET", "/cluster/tasks");
        if (Array.isArray(list)) {
          return list.map(t => ({ ...t, node_name: n.name }));
        }
      } catch {
        try {
          const nDetails = await pve(n, "GET", "/nodes");
          if (Array.isArray(nDetails) && nDetails[0]) {
            const pveName = nDetails[0].node;
            const nTasks = await pve(n, "GET", `/nodes/${encodeURIComponent(pveName)}/tasks`);
            if (Array.isArray(nTasks)) {
              return nTasks.map(t => ({ ...t, node_name: n.name }));
            }
          }
        } catch {}
      }
      return [];
    }));

    let allTasks = [];
    results.forEach(r => {
      if (r.status === "fulfilled" && Array.isArray(r.value)) {
        allTasks.push(...r.value);
      }
    });

    allTasks.sort((a, b) => (b.starttime || 0) - (a.starttime || 0));
    res.json({ tasks: allTasks.slice(0, 100) });
  } catch (e) { next(e); }
});

// --- VM Templates Management Endpoints ---

app.get("/api/admin/templates", requireAuth, requireAdmin, (req, res) => {
  const templates = db.prepare(`
    SELECT t.*, n.name as node_name, n.host as node_host,
      (SELECT COUNT(*) FROM template_ips WHERE template_id = t.id) as total_ips,
      (SELECT COUNT(*) FROM template_ips WHERE template_id = t.id AND status = 'available') as available_ips,
      (SELECT COUNT(*) FROM template_ips WHERE template_id = t.id AND status = 'used') as used_ips,
      (SELECT ip_address FROM template_ips WHERE template_id = t.id AND status = 'available' ORDER BY id ASC LIMIT 1) as next_ip
    FROM vm_templates t
    LEFT JOIN nodes n ON n.id = t.node_id
    ORDER BY t.type ASC, t.id DESC
  `).all();
  res.json({ templates });
});

app.get("/api/admin/templates/options", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const nodes = db.prepare("SELECT id, name, host, enabled FROM nodes WHERE enabled = 1").all();
    const users = db.prepare("SELECT id, username, email, role FROM users WHERE active = 1 ORDER BY username ASC").all();

    const nodeId = req.query.nodeId ? Number(req.query.nodeId) : (nodes[0]?.id || null);
    let lxcTemplates = [];
    let qemuTemplates = [];
    let storages = [];
    let bridges = [];
    let nextVmid = 100;
    let nodeStats = null;

    if (nodeId) {
      const node = getNode(nodeId);
      let pveNode = "";
      try {
        const nList = await pve(node, "GET", "/nodes");
        if (Array.isArray(nList)) {
          const found = nList.find(n => n.node === node.name || n.status === "online") || nList[0];
          pveNode = found?.node || "";
        }
      } catch {}
      if (!pveNode) pveNode = node.name.toLowerCase().replace(/[^a-z0-9_-]/g, "");

      // 1. Next free VMID from Proxmox cluster
      try {
        const nid = await pve(node, "GET", "/cluster/nextid");
        if (nid) nextVmid = Number(nid);
      } catch {
        const maxRow = db.prepare("SELECT MAX(vmid) as max FROM servers WHERE node_id=?").get(node.id);
        nextVmid = (maxRow?.max || 100) + 1;
      }

      // 2. Node system stats
      try {
        const stRes = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/status`);
        if (stRes) {
          nodeStats = {
            node: pveNode,
            cpuModel: stRes.cpuinfo?.model || "",
            cpus: stRes.cpuinfo?.cpus || stRes.cpus || 0,
            memoryTotal: stRes.memory?.total || 0,
            memoryFree: stRes.memory?.free || 0
          };
        }
      } catch {}

      // 3. Storages on this node
      let vmStorages = [];
      let ctStorages = [];
      let allStorages = [];
      try {
        const sList = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage`);
        if (Array.isArray(sList)) {
          allStorages = sList.map(s => ({
            storage: s.storage,
            type: s.type || "",
            content: s.content || "",
            avail: s.avail || 0,
            total: s.total || 0,
            used: s.used || 0,
            shared: s.shared === 1,
            enabled: s.enabled !== 0 && s.active !== 0
          }));

          storages = allStorages.filter(s => s.enabled && (s.content.includes("images") || s.content.includes("rootdir") || s.content.includes("vztmpl")));
          vmStorages = allStorages.filter(s => s.enabled && s.content.includes("images"));
          ctStorages = allStorages.filter(s => s.enabled && s.content.includes("rootdir"));

          // Downloaded local vztmpl from storages
          for (const st of sList) {
            if (st.content && st.content.includes("vztmpl")) {
              try {
                const tmpl = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/storage/${encodeURIComponent(st.storage)}/content?content=vztmpl`);
                if (Array.isArray(tmpl)) {
                  lxcTemplates.push(...tmpl.map(t => ({
                    volid: t.volid,
                    name: t.volid.split("/").pop(),
                    size: t.size,
                    storage: st.storage,
                    isLocal: true
                  })));
                }
              } catch {}
            }
          }
        }
      } catch {}

      // Official Proxmox appliance repository for LXC
      try {
        const apl = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/aplinfo`);
        if (Array.isArray(apl)) {
          const x64 = apl.filter(x => x.architecture === "amd64" || !x.architecture);
          for (const a of x64) {
            if (!lxcTemplates.some(t => t.volid === a.template || t.name === a.package)) {
              lxcTemplates.push({
                volid: a.template,
                name: a.headline || a.package,
                package: a.package,
                section: a.section || "system",
                isLocal: false
              });
            }
          }
        }
      } catch {}

      // 4. Real QEMU Templates (check cluster resources and node)
      try {
        const allVms = await pve(node, "GET", "/cluster/resources?type=vm");
        if (Array.isArray(allVms)) {
          qemuTemplates = allVms
            .filter(v => v.template === 1 && v.type === "qemu" && (v.node === pveNode || !v.node))
            .map(v => ({
              id: v.vmid,
              vmid: v.vmid,
              name: v.name || `Template ${v.vmid}`,
              disk: v.maxdisk || 0,
              mem: v.maxmem || 0,
              cpus: v.maxcpu || 1,
              node: v.node || pveNode
            }));
        }
      } catch {}
      if (qemuTemplates.length === 0) {
        try {
          const qList = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/qemu`);
          if (Array.isArray(qList)) {
            qemuTemplates = qList.filter(v => v.template === 1).map(v => ({
              id: v.vmid,
              vmid: v.vmid,
              name: v.name,
              disk: v.maxdisk || 0,
              mem: v.maxmem || 0
            }));
          }
        } catch {}
      }

      // 5. Network Bridges (real interfaces from Proxmox)
      try {
        const nList = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/network`);
        if (Array.isArray(nList)) {
          bridges = nList
            .filter(n => n.type === "bridge" || (n.iface && n.iface.startsWith("vmbr")))
            .map(n => ({
              iface: n.iface,
              active: n.active === 1,
              cidr: n.cidr || "",
              gateway: n.gateway || "",
              comments: n.comments || ""
            }));
        }
      } catch {}
      if (bridges.length === 0) {
        bridges = [{ iface: "vmbr0", active: true, cidr: "", gateway: "" }];
      }

      // 6. CPU Models (Query capabilities from Proxmox VE)
      let pveCpuModels = [];
      try {
        const caps = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/capabilities/qemu/cpu`);
        if (Array.isArray(caps)) {
          pveCpuModels = caps.map(c => ({
            name: c.name,
            vendor: c.vendor || "",
            custom: c.custom === 1
          }));
        }
      } catch {}

      const standardCpus = [
        { name: "host", desc: "host (Host CPU passthrough - Maximum performance & AES-NI)" },
        { name: "x86-64-v2-AES", desc: "x86-64-v2-AES (Recommended for cluster migration)" },
        { name: "x86-64-v3", desc: "x86-64-v3 (AVX, AVX2, modern instructions)" },
        { name: "kvm64", desc: "kvm64 (Proxmox standard universal compatibility)" },
        { name: "qemu64", desc: "qemu64 (QEMU default)" },
        { name: "max", desc: "max (All features supported by host)" }
      ];

      const cpuModels = [...standardCpus];
      for (const p of pveCpuModels) {
        if (!cpuModels.some(c => c.name === p.name)) {
          cpuModels.push({
            name: p.name,
            desc: `${p.name} ${p.vendor ? `(${p.vendor})` : ''}`
          });
        }
      }

      return res.json({
        nodes,
        users,
        selectedNodeId: nodeId,
        nextVmid,
        nodeStats,
        lxcTemplates,
        qemuTemplates,
        storages,
        vmStorages,
        ctStorages,
        allStorages,
        cpuModels,
        bridges
      });
    }

    res.json({
      nodes,
      users,
      selectedNodeId: nodeId,
      nextVmid,
      nodeStats,
      lxcTemplates,
      qemuTemplates,
      storages,
      bridges
    });
  } catch (e) { next(e); }
});

app.get("/api/admin/templates/:id", requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const template = db.prepare(`
    SELECT t.*, n.name as node_name, n.host as node_host
    FROM vm_templates t
    LEFT JOIN nodes n ON n.id = t.node_id
    WHERE t.id = ?
  `).get(id);
  if (!template) return res.status(404).json({ error: "Template not found." });

  const ips = db.prepare(`
    SELECT * FROM template_ips
    WHERE template_id = ?
    ORDER BY CASE status WHEN 'available' THEN 0 ELSE 1 END, id ASC
  `).all(id);

  const stats = {
    total: ips.length,
    available: ips.filter(x => x.status === "available").length,
    used: ips.filter(x => x.status === "used").length
  };

  res.json({ template, ips, stats });
});

app.post("/api/admin/templates", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const name = validateString(req.body.name, "Template name", 80);
    const type = req.body.type === "lxc" ? "lxc" : "qemu";
    const nodeId = Number(req.body.node_id);
    const osMode = (req.body.os_mode === "custom" || req.body.osMode === "custom") ? "custom" : "fixed";
    const templateSource = osMode === "custom"
      ? (req.body.template_source ? String(req.body.template_source).trim() : "custom")
      : validateString(req.body.template_source, "Template image/source", 250);
    const description = typeof req.body.description === "string" ? req.body.description.trim() : "";

    const node = getNode(nodeId);
    if (!node) return res.status(404).json({ error: "Proxmox node not found." });

    const cores = Math.max(1, Math.min(128, Number(req.body.cores || 2)));
    const sockets = Math.max(1, Math.min(8, Number(req.body.sockets || 1)));
    const cpu = validateString(req.body.cpu || "host", "CPU Model", 50);
    const numa = req.body.numa ? 1 : 0;
    const memory = Math.max(256, Math.min(1048576, Number(req.body.memory || 2048)));
    const swap = Math.max(0, Math.min(65536, Number(req.body.swap != null ? req.body.swap : 512)));
    const balloon = req.body.balloon ? Number(req.body.balloon) : 0;
    const diskSize = Math.max(1, Math.min(50000, Number(req.body.disk_size || 25)));
    const storage = validateString(req.body.storage || "local-lvm", "Storage", 50);
    const diskBus = ["scsi", "virtio", "sata", "ide"].includes(req.body.disk_bus) ? req.body.disk_bus : "scsi";
    const diskCache = ["none", "writeback", "writethrough", "directsync"].includes(req.body.disk_cache) ? req.body.disk_cache : "none";
    const discard = req.body.discard !== false && req.body.discard !== 0 ? 1 : 0;
    const ssd = req.body.ssd !== false && req.body.ssd !== 0 ? 1 : 0;
    const iothread = req.body.iothread !== false && req.body.iothread !== 0 ? 1 : 0;
    const bridge = validateString(req.body.bridge || "vmbr0", "Bridge", 30);
    const netModel = ["virtio", "e1000", "vmxnet3", "rtl8139"].includes(req.body.net_model) ? req.body.net_model : "virtio";
    const netifName = req.body.netif_name ? req.body.netif_name.trim() : "eth0";
    const vlan = req.body.vlan ? Number(req.body.vlan) : null;
    const firewall = req.body.firewall !== false && req.body.firewall !== 0 ? 1 : 0;
    const rateLimit = req.body.rate_limit ? Number(req.body.rate_limit) : null;
    const gateway = req.body.gateway ? req.body.gateway.trim() : "";
    const cidr = req.body.cidr ? String(req.body.cidr).replace("/", "").trim() : "24";
    const nameservers = req.body.nameservers ? req.body.nameservers.trim() : "1.1.1.1 8.8.8.8";
    const searchDomain = req.body.search_domain ? req.body.search_domain.trim() : "";
    const onboot = req.body.onboot ? 1 : 0;
    const unprivileged = req.body.unprivileged !== false && req.body.unprivileged !== 0 ? 1 : 0;
    const nesting = req.body.nesting !== false && req.body.nesting !== 0 ? 1 : 0;
    const qemuAgent = req.body.qemu_agent !== false && req.body.qemu_agent !== 0 ? 1 : 0;
    const scsihw = ["virtio-scsi-single", "virtio-scsi", "lsi", "megaraid", "pvscsi"].includes(req.body.scsihw) ? req.body.scsihw : "virtio-scsi-single";
    const machine = req.body.machine === "i440fx" ? "i440fx" : "q35";
    const bios = req.body.bios === "ovmf" ? "ovmf" : "seabios";
    const vga = ["std", "serial0", "virtio", "qxl"].includes(req.body.vga) ? req.body.vga : "std";
    const ciUser = typeof req.body.ci_user === "string" && req.body.ci_user.trim() ? req.body.ci_user.trim() : (typeof req.body.ciUser === "string" && req.body.ciUser.trim() ? req.body.ciUser.trim() : "root");
    const ciUpgrade = req.body.ci_upgrade !== false && req.body.ci_upgrade !== 0 && req.body.ciUpgrade !== false && req.body.ciUpgrade !== 0 ? 1 : 0;
    const keyctl = req.body.keyctl !== false && req.body.keyctl !== 0 ? 1 : 0;
    const fuse = req.body.fuse ? 1 : 0;
    const ip6Type = ["disabled", "auto", "dhcp", "static"].includes(req.body.ip6_type || req.body.ip6Type) ? (req.body.ip6_type || req.body.ip6Type) : "disabled";
    const ip6Gateway = req.body.ip6_gateway ? req.body.ip6_gateway.trim() : (req.body.ip6Gateway ? req.body.ip6Gateway.trim() : "");
    const startAfterCreate = req.body.start_after_create !== false && req.body.start_after_create !== 0 ? 1 : 0;
    const defaultDurationDays = Math.max(0, Number(req.body.default_duration_days || req.body.duration_days || 0));

    const result = db.prepare(`
      INSERT INTO vm_templates (
        name, type, description, node_id, template_source, os_mode,
        cores, sockets, cpu, numa, memory, swap, balloon,
        disk_size, storage, disk_bus, disk_cache, discard, ssd, iothread,
        bridge, net_model, netif_name, vlan, firewall, rate_limit,
        gateway, cidr, nameservers, search_domain,
        onboot, unprivileged, nesting, qemu_agent,
        scsihw, machine, bios, vga, ci_user, ci_upgrade,
        keyctl, fuse, ip6_type, ip6_gateway, start_after_create, default_duration_days
      ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?
      )
    `).run(
      name, type, description, nodeId, templateSource, osMode,
      cores, sockets, cpu, numa, memory, swap, balloon,
      diskSize, storage, diskBus, diskCache, discard, ssd, iothread,
      bridge, netModel, netifName, vlan, firewall, rateLimit,
      gateway, cidr, nameservers, searchDomain,
      onboot, unprivileged, nesting, qemuAgent,
      scsihw, machine, bios, vga, ciUser, ciUpgrade,
      keyctl, fuse, ip6Type, ip6Gateway, startAfterCreate, defaultDurationDays
    );
    const templateId = result.lastInsertRowid;

    // Parse and insert initial IPs if provided
    let addedCount = 0;
    if (req.body.ips) {
      const parsedIps = parseIpEntries(req.body.ips, cidr, gateway);
      const insertIp = db.prepare(`
        INSERT OR IGNORE INTO template_ips (template_id, ip_address, cidr, gateway, status)
        VALUES (?, ?, ?, ?, 'available')
      `);
      for (const entry of parsedIps) {
        const ipRes = insertIp.run(templateId, entry.ip, entry.cidr || cidr, entry.gateway || gateway);
        if (ipRes.changes > 0) addedCount++;
      }
    }

    audit(req.user.id, "template_create", `${type.toUpperCase()} template "${name}" created (ID: ${templateId}) with ${addedCount} initial IPs.`, req);
    res.status(201).json({
      ok: true,
      id: templateId,
      message: `VM Template "${name}" created successfully with ${addedCount} IPs in its pool!`
    });
  } catch (e) { next(e); }
});

app.put("/api/admin/templates/:id", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const existing = db.prepare("SELECT * FROM vm_templates WHERE id = ?").get(id);
    if (!existing) return res.status(404).json({ error: "Template not found." });

    const name = validateString(req.body.name || existing.name, "Template name", 80);
    const description = req.body.description !== undefined ? String(req.body.description).trim() : existing.description;
    const nodeId = req.body.node_id ? Number(req.body.node_id) : existing.node_id;
    const osMode = req.body.os_mode !== undefined ? (req.body.os_mode === "custom" ? "custom" : "fixed") : (existing.os_mode || "fixed");
    const templateSource = osMode === "custom"
      ? (req.body.template_source !== undefined ? String(req.body.template_source).trim() : (existing.template_source || "custom"))
      : (req.body.template_source ? validateString(req.body.template_source, "Template image/source", 250) : existing.template_source);
    const cores = Math.max(1, Math.min(128, Number(req.body.cores || existing.cores)));
    const sockets = Math.max(1, Math.min(8, Number(req.body.sockets || existing.sockets)));
    const cpu = validateString(req.body.cpu || existing.cpu, "CPU Model", 50);
    const numa = req.body.numa != null ? (req.body.numa ? 1 : 0) : existing.numa;
    const memory = Math.max(256, Math.min(1048576, Number(req.body.memory || existing.memory)));
    const swap = Math.max(0, Math.min(65536, Number(req.body.swap != null ? req.body.swap : existing.swap)));
    const balloon = req.body.balloon != null ? Number(req.body.balloon) : existing.balloon;
    const diskSize = Math.max(1, Math.min(50000, Number(req.body.disk_size || existing.disk_size)));
    const storage = validateString(req.body.storage || existing.storage, "Storage", 50);
    const diskBus = ["scsi", "virtio", "sata", "ide"].includes(req.body.disk_bus) ? req.body.disk_bus : existing.disk_bus;
    const diskCache = ["none", "writeback", "writethrough", "directsync"].includes(req.body.disk_cache) ? req.body.disk_cache : existing.disk_cache;
    const discard = req.body.discard != null ? (req.body.discard ? 1 : 0) : existing.discard;
    const ssd = req.body.ssd != null ? (req.body.ssd ? 1 : 0) : existing.ssd;
    const iothread = req.body.iothread != null ? (req.body.iothread ? 1 : 0) : existing.iothread;
    const bridge = validateString(req.body.bridge || existing.bridge, "Bridge", 30);
    const netModel = ["virtio", "e1000", "vmxnet3", "rtl8139"].includes(req.body.net_model) ? req.body.net_model : existing.net_model;
    const netifName = req.body.netif_name ? req.body.netif_name.trim() : existing.netif_name;
    const vlan = req.body.vlan !== undefined ? (req.body.vlan ? Number(req.body.vlan) : null) : existing.vlan;
    const firewall = req.body.firewall != null ? (req.body.firewall ? 1 : 0) : existing.firewall;
    const rateLimit = req.body.rate_limit !== undefined ? (req.body.rate_limit ? Number(req.body.rate_limit) : null) : existing.rate_limit;
    const gateway = req.body.gateway !== undefined ? req.body.gateway.trim() : existing.gateway;
    const cidr = req.body.cidr ? String(req.body.cidr).replace("/", "").trim() : existing.cidr;
    const nameservers = req.body.nameservers !== undefined ? req.body.nameservers.trim() : existing.nameservers;
    const searchDomain = req.body.search_domain !== undefined ? req.body.search_domain.trim() : existing.search_domain;
    const onboot = req.body.onboot != null ? (req.body.onboot ? 1 : 0) : existing.onboot;
    const unprivileged = req.body.unprivileged != null ? (req.body.unprivileged ? 1 : 0) : existing.unprivileged;
    const nesting = req.body.nesting != null ? (req.body.nesting ? 1 : 0) : existing.nesting;
    const qemuAgent = req.body.qemu_agent != null ? (req.body.qemu_agent ? 1 : 0) : existing.qemu_agent;
    const scsihw = req.body.scsihw ? (["virtio-scsi-single", "virtio-scsi", "lsi", "megaraid", "pvscsi"].includes(req.body.scsihw) ? req.body.scsihw : existing.scsihw) : existing.scsihw;
    const machine = req.body.machine ? (req.body.machine === "i440fx" ? "i440fx" : "q35") : existing.machine;
    const bios = req.body.bios ? (req.body.bios === "ovmf" ? "ovmf" : "seabios") : existing.bios;
    const vga = req.body.vga ? (["std", "serial0", "virtio", "qxl"].includes(req.body.vga) ? req.body.vga : existing.vga) : existing.vga;
    const ciUser = req.body.ci_user !== undefined ? String(req.body.ci_user).trim() : (req.body.ciUser !== undefined ? String(req.body.ciUser).trim() : existing.ci_user);
    const ciUpgrade = req.body.ci_upgrade != null ? (req.body.ci_upgrade ? 1 : 0) : (req.body.ciUpgrade != null ? (req.body.ciUpgrade ? 1 : 0) : existing.ci_upgrade);
    const keyctl = req.body.keyctl != null ? (req.body.keyctl ? 1 : 0) : existing.keyctl;
    const fuse = req.body.fuse != null ? (req.body.fuse ? 1 : 0) : existing.fuse;
    const ip6Type = req.body.ip6_type ? req.body.ip6_type : (req.body.ip6Type ? req.body.ip6Type : existing.ip6_type);
    const ip6Gateway = req.body.ip6_gateway !== undefined ? String(req.body.ip6_gateway).trim() : (req.body.ip6Gateway !== undefined ? String(req.body.ip6Gateway).trim() : existing.ip6_gateway);
    const startAfterCreate = req.body.start_after_create != null ? (req.body.start_after_create ? 1 : 0) : existing.start_after_create;
    const defaultDurationDays = req.body.default_duration_days !== undefined
      ? Math.max(0, Number(req.body.default_duration_days))
      : (req.body.duration_days !== undefined ? Math.max(0, Number(req.body.duration_days)) : (existing.default_duration_days || 0));

    db.prepare(`
      UPDATE vm_templates SET
        name = ?, description = ?, node_id = ?, template_source = ?, os_mode = ?,
        cores = ?, sockets = ?, cpu = ?, numa = ?, memory = ?, swap = ?, balloon = ?,
        disk_size = ?, storage = ?, disk_bus = ?, disk_cache = ?, discard = ?, ssd = ?, iothread = ?,
        bridge = ?, net_model = ?, netif_name = ?, vlan = ?, firewall = ?, rate_limit = ?,
        gateway = ?, cidr = ?, nameservers = ?, search_domain = ?,
        onboot = ?, unprivileged = ?, nesting = ?, qemu_agent = ?,
        scsihw = ?, machine = ?, bios = ?, vga = ?, ci_user = ?, ci_upgrade = ?,
        keyctl = ?, fuse = ?, ip6_type = ?, ip6_gateway = ?, start_after_create = ?, default_duration_days = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      name, description, nodeId, templateSource, osMode,
      cores, sockets, cpu, numa, memory, swap, balloon,
      diskSize, storage, diskBus, diskCache, discard, ssd, iothread,
      bridge, netModel, netifName, vlan, firewall, rateLimit,
      gateway, cidr, nameservers, searchDomain,
      onboot, unprivileged, nesting, qemuAgent,
      scsihw, machine, bios, vga, ciUser, ciUpgrade,
      keyctl, fuse, ip6Type, ip6Gateway, startAfterCreate, defaultDurationDays,
      id
    );

    // If new IPs are provided in update payload, append them
    let addedCount = 0;
    if (req.body.new_ips) {
      const parsedIps = parseIpEntries(req.body.new_ips, cidr, gateway);
      const insertIp = db.prepare(`
        INSERT OR IGNORE INTO template_ips (template_id, ip_address, cidr, gateway, status)
        VALUES (?, ?, ?, ?, 'available')
      `);
      for (const entry of parsedIps) {
        const ipRes = insertIp.run(id, entry.ip, entry.cidr || cidr, entry.gateway || gateway);
        if (ipRes.changes > 0) addedCount++;
      }
    }

    audit(req.user.id, "template_edit", `Template "${name}" (ID: ${id}) updated.${addedCount ? ` Added ${addedCount} new IPs.` : ""}`, req);
    res.json({
      ok: true,
      message: `Template "${name}" updated successfully!${addedCount ? ` (${addedCount} new IPs added to pool)` : ""}`
    });
  } catch (e) { next(e); }
});

app.delete("/api/admin/templates/:id", requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const t = db.prepare("SELECT name FROM vm_templates WHERE id = ?").get(id);
  if (!t) return res.status(404).json({ error: "Template not found." });

  db.prepare("DELETE FROM template_ips WHERE template_id = ?").run(id);
  db.prepare("DELETE FROM vm_templates WHERE id = ?").run(id);

  audit(req.user.id, "template_delete", `Template "${t.name}" (ID: ${id}) and its IP pool deleted.`, req);
  res.json({ ok: true, message: `Template "${t.name}" deleted successfully.` });
});

app.post("/api/admin/templates/:id/ips", requireAuth, requireAdmin, (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const template = db.prepare("SELECT id, cidr, gateway FROM vm_templates WHERE id = ?").get(id);
    if (!template) return res.status(404).json({ error: "Template not found." });

    const raw = req.body.ips || req.body.ip;
    if (!raw) return res.status(400).json({ error: "Please enter at least one IP address." });

    const defaultCidr = req.body.cidr || template.cidr || "24";
    const defaultGateway = req.body.gateway || template.gateway || "";
    const parsed = parseIpEntries(raw, defaultCidr, defaultGateway);

    if (parsed.length === 0) {
      return res.status(400).json({ error: "No valid IPv4/IPv6 addresses found in input." });
    }

    const insertIp = db.prepare(`
      INSERT OR IGNORE INTO template_ips (template_id, ip_address, cidr, gateway, status)
      VALUES (?, ?, ?, ?, 'available')
    `);

    let added = 0;
    let duplicate = 0;
    for (const entry of parsed) {
      const r = insertIp.run(id, entry.ip, entry.cidr, entry.gateway);
      if (r.changes > 0) added++;
      else duplicate++;
    }

    res.json({
      ok: true,
      added,
      duplicate,
      message: `${added} IP address(es) added successfully to template pool.${duplicate > 0 ? ` (${duplicate} duplicates skipped)` : ""}`
    });
  } catch (e) { next(e); }
});

app.delete("/api/admin/templates/:id/ips/:ipId", requireAuth, requireAdmin, (req, res) => {
  const templateId = Number(req.params.id);
  const ipId = Number(req.params.ipId);
  const ipRow = db.prepare("SELECT ip_address, status FROM template_ips WHERE id = ? AND template_id = ?").get(ipId, templateId);
  if (!ipRow) return res.status(404).json({ error: "IP not found in template." });

  db.prepare("DELETE FROM template_ips WHERE id = ?").run(ipId);
  res.json({ ok: true, message: `IP ${ipRow.ip_address} removed from template pool.` });
});

app.post("/api/admin/templates/:id/ips/:ipId/release", requireAuth, requireAdmin, (req, res) => {
  const templateId = Number(req.params.id);
  const ipId = Number(req.params.ipId);
  const ipRow = db.prepare("SELECT ip_address, status FROM template_ips WHERE id = ? AND template_id = ?").get(ipId, templateId);
  if (!ipRow) return res.status(404).json({ error: "IP not found in template." });

  db.prepare(`
    UPDATE template_ips SET
      status = 'available',
      server_id = NULL,
      assigned_vmid = NULL,
      assigned_server_name = '',
      assigned_user_id = NULL,
      assigned_user_name = '',
      assigned_at = NULL
    WHERE id = ?
  `).run(ipId);

  audit(req.user.id, "template_ip_release", `IP ${ipRow.ip_address} in template ID ${templateId} released back to available.`, req);
  res.json({ ok: true, message: `IP ${ipRow.ip_address} has been marked as Available!` });
});

app.post("/api/admin/templates/:id/deploy", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const templateId = Number(req.params.id);
    const template = db.prepare("SELECT * FROM vm_templates WHERE id = ?").get(templateId);
    if (!template) return res.status(404).json({ error: "VM Template not found." });

    const userId = Number(req.body.userId);
    const user = db.prepare("SELECT id, username FROM users WHERE id = ? AND active = 1").get(userId);
    if (!user) return res.status(404).json({ error: "Selected user not found or inactive." });

    const name = validateString(req.body.name, "Server name / hostname", 80);
    const password = (req.body.password && typeof req.body.password === "string" && req.body.password.trim().length >= 8)
      ? req.body.password.trim()
      : ("At!" + crypto.randomBytes(6).toString("base64").replace(/[+/=]/g, "a") + "9");
    const sshKey = typeof req.body.sshKey === "string" ? req.body.sshKey.trim() : "";
    const startAfterCreate = req.body.start !== false && req.body.start !== "false";

    // 1. Atomically pick the first available IP from this template's dedicated pool
    const allocatedIp = db.prepare(`
      SELECT * FROM template_ips 
      WHERE template_id = ? AND status = 'available' 
      ORDER BY id ASC LIMIT 1
    `).get(templateId);

    if (!allocatedIp) {
      return res.status(400).json({
        error: `No available IP addresses found in the "${template.name}" IP pool. Please add more IPs to this template before deploying.`
      });
    }

    const node = getNode(template.node_id);
    let pveNode = "";
    try {
      const nodesList = await pve(node, "GET", "/nodes");
      if (Array.isArray(nodesList)) {
        const found = nodesList.find(n => n.node === node.name || n.status === "online") || nodesList[0];
        pveNode = found?.node || "";
      }
    } catch {}
    if (!pveNode) pveNode = node.name.toLowerCase().replace(/[^a-z0-9_-]/g, "");

    // 2. Determine VMID
    let vmid = Number(req.body.vmid);
    if (!Number.isInteger(vmid) || vmid < 100) {
      try {
        const nextIdRes = await pve(node, "GET", "/cluster/nextid");
        vmid = Number(nextIdRes);
      } catch {}
      if (!Number.isInteger(vmid) || vmid < 100) {
        const maxVmidRow = db.prepare("SELECT MAX(vmid) as maxVmid FROM servers WHERE node_id = ?").get(template.node_id);
        vmid = (maxVmidRow?.maxVmid ? maxVmidRow.maxVmid + 1 : 110);
      }
    }

    // Ensure VMID not taken in DB
    const existingInDb = db.prepare("SELECT id FROM servers WHERE node_id = ? AND vmid = ?").get(template.node_id, vmid);
    if (existingInDb) {
      return res.status(409).json({ error: `A VPS with VMID ${vmid} already exists in the panel database.` });
    }

    // Ensure VMID not taken on Proxmox VE node / cluster
    let vmidTakenOnPve = false;
    try {
      const allClusterVms = await pve(node, "GET", "/cluster/resources?type=vm");
      if (Array.isArray(allClusterVms)) {
        vmidTakenOnPve = allClusterVms.some(v => Number(v.vmid) === Number(vmid));
      }
    } catch {
      try {
        const qCheck = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/qemu/${vmid}/status/current`);
        if (qCheck) vmidTakenOnPve = true;
      } catch {}
      if (!vmidTakenOnPve) {
        try {
          const lCheck = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/lxc/${vmid}/status/current`);
          if (lCheck) vmidTakenOnPve = true;
        } catch {}
      }
    }

    if (vmidTakenOnPve) {
      try {
        const nextFree = await pve(node, "GET", "/cluster/nextid");
        if (nextFree && Number(nextFree) !== Number(vmid)) {
          console.log(`[Deploy Notice] Requested VMID ${vmid} already exists on Proxmox node '${pveNode}'. Automatically assigned next free VMID ${nextFree}.`);
          vmid = Number(nextFree);
        } else {
          return res.status(409).json({ error: `VMID ${vmid} already exists on Proxmox node '${pveNode}'. Please enter another VMID.` });
        }
      } catch {
        return res.status(409).json({ error: `VMID ${vmid} already exists on Proxmox node '${pveNode}'. Please enter another VMID.` });
      }
    }

    const ipCidr = allocatedIp.cidr || template.cidr || "24";
    const fullIp = `${allocatedIp.ip_address}/${ipCidr}`;
    const gw = allocatedIp.gateway || template.gateway || "";

    const selectedSource = (req.body.templateSource && String(req.body.templateSource).trim()) ||
                           (req.body.template_source && String(req.body.template_source).trim()) ||
                           template.template_source;

    // 3. Proxmox Provisioning
    if (template.type === "qemu") {
      const templateVmid = Number(selectedSource);
      if (!Number.isInteger(templateVmid) || templateVmid < 100) {
        return res.status(400).json({ error: `Selected template image "${selectedSource}" is not a valid QEMU template VMID. Please select a valid QEMU template.` });
      }

      // Clone QEMU template
      const cloneTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu/${templateVmid}/clone`, {
        newid: vmid,
        name,
        full: 1,
        storage: template.storage
      });
      await waitForPveTask(node, pveNode, cloneTask, 180);

      // Cloud-Init & Hardware Config
      let net0Str = `${template.net_model || 'virtio'},bridge=${template.bridge}`;
      if (template.vlan) net0Str += `,tag=${template.vlan}`;
      if (template.firewall) net0Str += `,firewall=1`;
      if (template.rate_limit) net0Str += `,rate=${template.rate_limit}`;

      let ipconfig0Str = `ip=${fullIp}`;
      if (gw) ipconfig0Str += `,gw=${gw}`;

      const configUpdate = {
        cores: template.cores,
        sockets: template.sockets,
        cpu: template.cpu,
        memory: template.memory,
        net0: net0Str,
        ipconfig0: ipconfig0Str,
        ciuser: req.body.ciUser || template.ci_user || "root",
        cipassword: password
      };
      if (template.numa) configUpdate.numa = 1;
      if (template.balloon > 0) configUpdate.balloon = template.balloon;
      if (template.onboot) configUpdate.onboot = 1;
      if (template.qemu_agent) configUpdate.agent = 1;
      if (template.machine) configUpdate.machine = template.machine;
      if (template.bios) configUpdate.bios = template.bios;
      if (template.scsihw) configUpdate.scsihw = template.scsihw;
      if (template.vga) configUpdate.vga = template.vga;
      if (template.ci_upgrade) configUpdate.ciupgrade = 1;
      if (sshKey) configUpdate.sshkeys = encodeURIComponent(sshKey);
      if (template.search_domain) configUpdate.searchdomain = template.search_domain;
      if (template.nameservers) configUpdate.nameserver = template.nameservers;

      await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu/${vmid}/config`, configUpdate);

      // Resize disk if requested disk size > template disk size
      try {
        const newCfg = await pve(node, "GET", `/nodes/${encodeURIComponent(pveNode)}/qemu/${vmid}/config`);
        let newDiskKey = "scsi0";
        let templateDiskGb = 0;
        const candidateKeys = [];
        for (let i = 0; i < 16; i++) candidateKeys.push(`scsi${i}`, `virtio${i}`, `sata${i}`, `ide${i}`);
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
        if (template.disk_size > templateDiskGb) {
          const resizeRes = await pve(node, "PUT", `/nodes/${encodeURIComponent(pveNode)}/qemu/${vmid}/resize`, {
            disk: newDiskKey,
            size: `${template.disk_size}G`
          });
          if (typeof resizeRes === "string" && resizeRes.startsWith("UPID")) {
            await waitForPveTask(node, pveNode, resizeRes, 60);
          }
        }
      } catch (resizeErr) {
        console.warn("Template deploy disk resize warning:", resizeErr.message);
      }

      if (startAfterCreate) {
        try {
          await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/qemu/${vmid}/status/start`);
        } catch {}
      }

    } else if (template.type === "lxc") {
      let net0Lxc = `name=${template.netif_name || 'eth0'},bridge=${template.bridge},ip=${fullIp}`;
      if (gw) net0Lxc += `,gw=${gw}`;
      if (template.vlan) net0Lxc += `,tag=${template.vlan}`;
      if (template.firewall) net0Lxc += `,firewall=1`;
      if (template.rate_limit) net0Lxc += `,rate=${template.rate_limit}`;

      let ostemplate = selectedSource;
      if (!ostemplate || ostemplate === "custom") {
        return res.status(400).json({ error: "Please select an LXC OS container template image for deployment." });
      }

      // Automatically check and download template if not already present on Proxmox VE
      ostemplate = await ensureLxcTemplateDownloaded(node, pveNode, ostemplate, "local");

      const featureList = [];
      if (template.nesting) featureList.push("nesting=1");
      if (template.keyctl !== 0) featureList.push("keyctl=1");
      if (template.fuse) featureList.push("fuse=1");

      const createParams = {
        vmid,
        hostname: name,
        ostemplate,
        cores: template.cores,
        memory: template.memory,
        swap: template.swap,
        net0: net0Lxc,
        rootfs: `${template.storage}:${template.disk_size},acl=1`,
        password,
        unprivileged: template.unprivileged ? 1 : 0
      };
      if (featureList.length > 0) createParams.features = featureList.join(",");
      if (template.onboot) createParams.onboot = 1;
      if (sshKey) createParams["ssh-public-keys"] = encodeURIComponent(sshKey);
      if (template.search_domain) createParams.searchdomain = template.search_domain;
      if (template.nameservers) createParams.nameserver = template.nameservers;

      try {
        const createTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/lxc`, createParams);
        await waitForPveTask(node, pveNode, createTask, 120);
      } catch (err) {
        const errMsg = String(err.message).toLowerCase();
        if (errMsg.includes("does not exist") || errMsg.includes("no such file")) {
          console.log(`[Deploy Notice] Container creation failed due to missing template. Forcing download and retrying...`);
          const forcedVolid = await ensureLxcTemplateDownloaded(node, pveNode, ostemplate, "local", true);
          createParams.ostemplate = forcedVolid;
          const retryTask = await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/lxc`, createParams);
          await waitForPveTask(node, pveNode, retryTask, 120);
        } else {
          throw err;
        }
      }

      if (startAfterCreate) {
        try {
          await pve(node, "POST", `/nodes/${encodeURIComponent(pveNode)}/lxc/${vmid}/status/start`);
        } catch {}
      }
    }

    // 4. Determine duration / expiry and save server in DB
    const deployDurationDays = req.body.duration_days !== undefined && req.body.duration_days !== null
      ? Number(req.body.duration_days)
      : (template.default_duration_days || 0);
    const deployExplicitExpiresAt = req.body.expires_at || null;
    const { expires_at: deployExpiresAt, duration_days: deployDurDays } = computeServerExpiry(deployDurationDays, deployExplicitExpiresAt, template.default_duration_days || 0);

    const sRes = db.prepare(`
      INSERT INTO servers(user_id, node_id, vmid, type, pve_node, name, expires_at, duration_days)
      VALUES(?, ?, ?, ?, ?, ?, ?, ?)
    `).run(userId, template.node_id, vmid, template.type, pveNode, name, deployExpiresAt, deployDurDays);
    const newServerId = sRes.lastInsertRowid;

    // 5. Permanently mark IP as USED with complete tracking details
    db.prepare(`
      UPDATE template_ips SET
        status = 'used',
        server_id = ?,
        assigned_vmid = ?,
        assigned_server_name = ?,
        assigned_user_id = ?,
        assigned_user_name = ?,
        assigned_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(newServerId, vmid, name, user.id, user.username, allocatedIp.id);

    audit(req.user.id, "server_create_template", `${template.type.toUpperCase()}:${vmid} (${name}) created from template "${template.name}" with dedicated IP ${allocatedIp.ip_address} for user ${user.username}`, req);
    io.emit("vps:list_changed");
    setTimeout(pollLiveMetrics, 300);

    res.status(201).json({
      ok: true,
      id: newServerId,
      vmid,
      name,
      type: template.type,
      ip: allocatedIp.ip_address,
      cidr: ipCidr,
      gateway: gw,
      message: `${template.type.toUpperCase()} instance "${name}" (VMID ${vmid}) deployed successfully with dedicated IP ${allocatedIp.ip_address}!`
    });

  } catch (e) {
    if (String(e.message).includes("UNIQUE")) e.status = 409;
    next(e);
  }
});

// ==========================================
// API KEYS MANAGEMENT ENDPOINTS
// ==========================================

app.get("/api/admin/api-keys", requireAuth, requireAdmin, (req, res) => {
  const keys = db.prepare(`
    SELECT k.id, k.name, k.key_prefix, k.scopes, k.allowed_ips, k.rate_limit,
           k.expires_at, k.active, k.request_count, k.last_used_at, k.last_used_ip,
           k.created_at, k.created_by_ip, u.id AS user_id, u.username AS user_name
    FROM api_keys k
    JOIN users u ON k.user_id = u.id
    ORDER BY k.id DESC
  `).all();

  const total = keys.length;
  const active = keys.filter(k => k.active === 1).length;
  const totalRequests = keys.reduce((acc, k) => acc + (k.request_count || 0), 0);

  res.json({
    keys,
    stats: {
      total,
      active,
      disabled: total - active,
      total_requests: totalRequests
    }
  });
});

app.post("/api/admin/api-keys", requireAuth, requireAdmin, (req, res) => {
  const name = validateString(req.body.name, "API Key Name", 80);
  const scopes = (typeof req.body.scopes === "string" && req.body.scopes.trim()) ? req.body.scopes.trim() : "*";
  const allowedIps = (typeof req.body.allowed_ips === "string") ? req.body.allowed_ips.trim() : "";
  let rateLimitVal = parseInt(req.body.rate_limit, 10);
  if (isNaN(rateLimitVal) || rateLimitVal < 10) rateLimitVal = 120;
  if (rateLimitVal > 10000) rateLimitVal = 10000;

  let expiresAt = null;
  if (req.body.expires_in_days) {
    const days = parseInt(req.body.expires_in_days, 10);
    if (!isNaN(days) && days > 0) {
      const d = new Date();
      d.setDate(d.getDate() + days);
      expiresAt = d.toISOString().replace("T", " ").slice(0, 19);
    }
  } else if (req.body.expires_at) {
    const d = new Date(req.body.expires_at);
    if (!isNaN(d.getTime())) {
      expiresAt = d.toISOString().replace("T", " ").slice(0, 19);
    }
  }

  // 64-char cryptographically secure random token (75 chars total with atyro_live_ prefix)
  const rawSecret = "atyro_live_" + crypto.randomBytes(32).toString("hex");
  const keyPrefix = rawSecret.slice(0, 15) + "..." + rawSecret.slice(-4);
  const keyHash = crypto.createHash("sha256").update(rawSecret).digest("hex");
  const clientIp = (req.headers["x-forwarded-for"]?.split(",")[0] || req.ip || req.socket.remoteAddress || "").trim();

  const result = db.prepare(`
    INSERT INTO api_keys (
      user_id, name, key_prefix, key_hash, key_token, scopes, allowed_ips,
      rate_limit, expires_at, active, created_by_ip
    ) VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, 1, ?)
  `).run(req.user.id, name, keyPrefix, keyHash, scopes, allowedIps, rateLimitVal, expiresAt, clientIp);

  audit(req.user.id, "api_key.create", `Created API key "${name}" (${keyPrefix}) with scopes: ${scopes}`, req);

  res.status(201).json({
    ok: true,
    key: {
      id: result.lastInsertRowid,
      name,
      key_prefix: keyPrefix,
      key_token: rawSecret,
      scopes,
      allowed_ips: allowedIps,
      rate_limit: rateLimitVal,
      expires_at: expiresAt,
      active: 1
    },
    raw_key: rawSecret,
    message: "API Key created successfully. Store this key safely; it cannot be displayed again."
  });
});

app.put("/api/admin/api-keys/:id", requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare("SELECT * FROM api_keys WHERE id = ?").get(id);
  if (!existing) return res.status(404).json({ error: "API key not found." });

  const name = validateString(req.body.name || existing.name, "API Key Name", 80);
  const scopes = (typeof req.body.scopes === "string" && req.body.scopes.trim()) ? req.body.scopes.trim() : existing.scopes;
  const allowedIps = (typeof req.body.allowed_ips === "string") ? req.body.allowed_ips.trim() : existing.allowed_ips;
  let rateLimitVal = req.body.rate_limit !== undefined ? parseInt(req.body.rate_limit, 10) : existing.rate_limit;
  if (isNaN(rateLimitVal) || rateLimitVal < 10) rateLimitVal = 120;
  if (rateLimitVal > 10000) rateLimitVal = 10000;

  let expiresAt = existing.expires_at;
  if (req.body.expires_at !== undefined) {
    if (!req.body.expires_at) {
      expiresAt = null;
    } else {
      const d = new Date(req.body.expires_at);
      if (!isNaN(d.getTime())) expiresAt = d.toISOString().replace("T", " ").slice(0, 19);
    }
  }

  db.prepare(`
    UPDATE api_keys SET
      name = ?, scopes = ?, allowed_ips = ?, rate_limit = ?, expires_at = ?
    WHERE id = ?
  `).run(name, scopes, allowedIps, rateLimitVal, expiresAt, id);

  audit(req.user.id, "api_key.update", `Updated API key #${id} ("${name}")`, req);
  res.json({ ok: true, message: "API key updated successfully." });
});

app.post("/api/admin/api-keys/:id/toggle", requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const key = db.prepare("SELECT id, name, active FROM api_keys WHERE id = ?").get(id);
  if (!key) return res.status(404).json({ error: "API key not found." });

  const newActive = key.active ? 0 : 1;
  db.prepare("UPDATE api_keys SET active = ? WHERE id = ?").run(newActive, id);

  audit(req.user.id, "api_key.toggle", `${newActive ? "Enabled" : "Disabled"} API key #${id} ("${key.name}")`, req);
  res.json({ ok: true, active: newActive, message: `API key ${newActive ? "activated" : "disabled"} successfully.` });
});

app.delete("/api/admin/api-keys/:id", requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const key = db.prepare("SELECT id, name FROM api_keys WHERE id = ?").get(id);
  if (!key) return res.status(404).json({ error: "API key not found." });

  db.prepare("DELETE FROM api_keys WHERE id = ?").run(id);
  apiKeyRateLimits.delete(id);

  audit(req.user.id, "api_key.delete", `Revoked and deleted API key #${id} ("${key.name}")`, req);
  res.json({ ok: true, message: "API key permanently revoked and deleted." });
});

app.post("/api/admin/api-keys/:id/regenerate", requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const key = db.prepare("SELECT * FROM api_keys WHERE id = ?").get(id);
  if (!key) return res.status(404).json({ error: "API key not found." });

  const rawSecret = "atyro_live_" + crypto.randomBytes(32).toString("hex");
  const keyPrefix = rawSecret.slice(0, 15) + "..." + rawSecret.slice(-4);
  const keyHash = crypto.createHash("sha256").update(rawSecret).digest("hex");

  db.prepare(`
    UPDATE api_keys SET
      key_prefix = ?, key_hash = ?, key_token = '', active = 1
    WHERE id = ?
  `).run(keyPrefix, keyHash, id);

  apiKeyRateLimits.delete(id);
  audit(req.user.id, "api_key.regenerate", `Regenerated secret token for API key #${id} ("${key.name}")`, req);

  res.json({
    ok: true,
    raw_key: rawSecret,
    key_prefix: keyPrefix,
    message: "New secret key generated. Save it now; it cannot be retrieved later."
  });
});

app.get("/api/admin/api-keys/docs", requireAuth, requireAdmin, (req, res) => {
  const docsData = {
    title: "Atyro Proxmox Panel REST API",
    version: "2.0",
    auth: {
      header: "Authorization: Bearer <your_api_key>",
      alternative_header: "X-API-Key: <your_api_key>",
      query_param: "?api_key=<your_api_key>"
    },
    endpoints: [
      {
        category: "Pterodactyl-Style User & VPS API (Discord Bot & Billing)",
        items: [
          { method: "GET", path: "/api/users/email/:email", desc: "Lookup user and their assigned VPS instances by email", scopes: ["users:read", "vps:read", "*"] },
          { method: "GET", path: "/api/application/users", desc: "Pterodactyl-compatible users query (supports ?filter[email]=, ?filter[username]=)", scopes: ["users:read", "*"] },
          { method: "GET", path: "/api/users/lookup", desc: "Lookup user by query parameter (?email=, ?username=, ?id=)", scopes: ["users:read", "*"] },
          { method: "GET", path: "/api/users/:id/servers", desc: "Get list of servers belonging to a specific user", scopes: ["vps:read", "users:read", "*"] },
          { method: "GET", path: "/api/application/servers", desc: "List all virtual servers across all cluster nodes with owner details", scopes: ["vps:read", "*"] },
          { method: "POST", path: "/api/servers/:id/power", desc: "Pterodactyl-compatible power control ({ action: 'start'|'stop'|'restart'|'kill' })", scopes: ["vps:power", "vps:write", "*"] },
          { method: "POST", path: "/api/servers/:id/suspend", desc: "1-Click suspend VPS and power off machine", scopes: ["vps:power", "vps:write", "*"] },
          { method: "POST", path: "/api/servers/:id/unsuspend", desc: "1-Click unsuspend VPS and restore user access", scopes: ["vps:power", "vps:write", "*"] },
          { method: "POST", path: "/api/servers/:id/renew", desc: "Renew/Extend VPS plan duration and auto-unsuspend: { days: 30, auto_unsuspend: true }", scopes: ["vps:power", "vps:write", "*"] }
        ]
      },
      {
        category: "System & Authentication",
        items: [
          { method: "GET", path: "/api/me", desc: "Get current user profile, role, and API key info", scopes: ["*"] },
          { method: "GET", path: "/api/health", desc: "Panel service health check", scopes: ["*"] },
          { method: "GET", path: "/api/settings", desc: "Panel public settings & branding", scopes: ["*"] }
        ]
      },
      {
        category: "Virtual Servers (VPS) Management",
        items: [
          { method: "GET", path: "/api/dashboard", desc: "List all virtual servers, status, IP, and summary statistics", scopes: ["vps:read", "*"] },
          { method: "GET", path: "/api/servers/:id/status", desc: "Get live runtime status, CPU/RAM/Disk metrics for a VPS", scopes: ["vps:read", "*"] },
          { method: "GET", path: "/api/servers/:id/config", desc: "Get full Proxmox VM/CT hardware configuration", scopes: ["vps:read", "*"] },
          { method: "POST", path: "/api/servers/:id/action", desc: "Execute power action: { action: 'start' | 'stop' | 'reboot' | 'reset' | 'shutdown' }", scopes: ["vps:power", "vps:write", "*"] },
          { method: "POST", path: "/api/servers/:id/termproxy", desc: "Generate live WebSocket xterm.js / noVNC console credentials", scopes: ["vps:write", "*"] },
          { method: "GET", path: "/api/servers/:id/rrd", desc: "Get RRD performance historical graph points (cpu, memory, disk, net)", scopes: ["vps:read", "*"] },
          { method: "GET", path: "/api/servers/:id/snapshots", desc: "List all snapshots for a VPS", scopes: ["vps:read", "*"] },
          { method: "POST", path: "/api/servers/:id/snapshots", desc: "Create snapshot: { snapname: 'snap1', description: 'desc' }", scopes: ["vps:write", "*"] },
          { method: "POST", path: "/api/servers/:id/snapshots/:name/rollback", desc: "Rollback VPS to selected snapshot", scopes: ["vps:write", "*"] },
          { method: "DELETE", path: "/api/servers/:id/snapshots/:name", desc: "Delete snapshot", scopes: ["vps:write", "*"] },
          { method: "GET", path: "/api/servers/:id/backups", desc: "List all Proxmox vzdump backup files for this server", scopes: ["vps:read", "*"] },
          { method: "POST", path: "/api/servers/:id/backups", desc: "Trigger immediate Proxmox vzdump backup job: { mode: 'snapshot', compress: 'zstd' }", scopes: ["vps:write", "*"] },
          { method: "POST", path: "/api/servers/:id/backups/restore", desc: "Restore VPS from backup archive: { volid: 'local:backup/...' }", scopes: ["vps:write", "*"] },
          { method: "POST", path: "/api/servers/:id/resize", desc: "Live resize specs: { cores: 4, memory: 4096, diskSize: 50 }", scopes: ["vps:write", "*"] },
          { method: "POST", path: "/api/servers/:id/suspend", desc: "One-click suspend VPS (powers off VM & locks user access): { reason: '...' }", scopes: ["vps:write", "*"] },
          { method: "POST", path: "/api/servers/:id/unsuspend", desc: "One-click unsuspend VPS (restores user access)", scopes: ["vps:write", "*"] },
          { method: "POST", path: "/api/servers/:id/toggle-suspend", desc: "One-click toggle VPS suspension state", scopes: ["vps:write", "*"] },
          { method: "POST", path: "/api/servers/:id/reinstall", desc: "Reinstall OS: { templateId: '...', password: '...', hostname: '...' }", scopes: ["vps:reinstall", "vps:write", "*"] },
          { method: "DELETE", path: "/api/servers/:id", desc: "Permanently destroy VPS, wipe disks and purge from Proxmox VE: { purge: 1, 'destroy-unreferenced-disks': 1, confirm_vmid: 100 }", scopes: ["servers:delete", "vps:write", "*"] }
        ]
      },
      {
        category: "VM Templates & IP Pools",
        items: [
          { method: "GET", path: "/api/admin/templates", desc: "List all LXC and QEMU templates with IP pool statistics", scopes: ["templates:read", "*"] },
          { method: "GET", path: "/api/admin/templates/:id", desc: "Get detailed template specification and all assigned/available IPs", scopes: ["templates:read", "*"] },
          { method: "GET", path: "/api/admin/templates/options", desc: "Fetch live Proxmox nodes, storages, bridges, appliances, and templates", scopes: ["templates:read", "*"] },
          { method: "POST", path: "/api/admin/templates", desc: "Create a new LXC or QEMU template with initial IP pool", scopes: ["templates:write", "*"] },
          { method: "PUT", path: "/api/admin/templates/:id", desc: "Update existing VM template specifications", scopes: ["templates:write", "*"] },
          { method: "DELETE", path: "/api/admin/templates/:id", desc: "Delete a VM template", scopes: ["templates:write", "*"] },
          { method: "POST", path: "/api/admin/templates/:id/ips", desc: "Add IPs to template pool: { ips: '192.168.1.101\\n192.168.1.102', cidr: '24', gateway: '192.168.1.1' }", scopes: ["templates:write", "*"] },
          { method: "DELETE", path: "/api/admin/templates/:id/ips/:ipId", desc: "Remove an IP from the template pool", scopes: ["templates:write", "*"] },
          { method: "POST", path: "/api/admin/templates/:id/ips/:ipId/release", desc: "Force release a used IP back to available status", scopes: ["templates:write", "*"] },
          { method: "POST", path: "/api/admin/templates/:id/deploy", desc: "Deploy new VPS from template with automatic dedicated IP allocation: { userId, name, password, sshKey, templateSource }", scopes: ["templates:deploy", "templates:write", "*"] }
        ]
      },
      {
        category: "Proxmox Nodes & Infrastructure",
        items: [
          { method: "GET", path: "/api/admin/nodes", desc: "List all Proxmox cluster nodes", scopes: ["nodes:read", "*"] },
          { method: "POST", path: "/api/admin/nodes", desc: "Connect new Proxmox node with API Token", scopes: ["nodes:write", "*"] },
          { method: "POST", path: "/api/admin/nodes/:id/test", desc: "Test connection to Proxmox VE API", scopes: ["nodes:read", "*"] },
          { method: "GET", path: "/api/admin/nodes/:id/details", desc: "Get node hardware specs, CPU cores, RAM, uptime, and PVE version", scopes: ["nodes:read", "*"] },
          { method: "GET", path: "/api/admin/proxmox/nodes/:nodeId/resources", desc: "Fetch live storage pools, network bridges, appliances, and ISOs", scopes: ["nodes:read", "*"] },
          { method: "PUT", path: "/api/admin/nodes/:id", desc: "Update Proxmox node connection parameters", scopes: ["nodes:write", "*"] },
          { method: "DELETE", path: "/api/admin/nodes/:id", desc: "Remove a Proxmox node from panel", scopes: ["nodes:write", "*"] }
        ]
      },
      {
        category: "User Management & Audit Logs",
        items: [
          { method: "GET", path: "/api/admin/users", desc: "List all panel users", scopes: ["users:read", "*"] },
          { method: "POST", path: "/api/admin/users", desc: "Create a user account: { username, email, password, role }", scopes: ["users:write", "*"] },
          { method: "PUT", path: "/api/admin/users/:id", desc: "Update user profile, role, password or active status", scopes: ["users:write", "*"] },
          { method: "DELETE", path: "/api/admin/users/:id", desc: "Delete a user account", scopes: ["users:write", "*"] },
          { method: "GET", path: "/api/admin/logs", desc: "Fetch system audit log trail", scopes: ["logs:read", "*"] },
          { method: "GET", path: "/api/admin/tasks", desc: "Fetch active Proxmox cluster tasks", scopes: ["logs:read", "*"] },
          { method: "GET", path: "/api/admin/overview", desc: "Get cluster-wide CPU, memory, and disk totals", scopes: ["monitoring:read", "*"] }
        ]
      },
      {
        category: "API Keys Management",
        items: [
          { method: "GET", path: "/api/admin/api-keys", desc: "List all created API keys with usage metrics", scopes: ["keys:manage", "*"] },
          { method: "POST", path: "/api/admin/api-keys", desc: "Generate a new API key: { name, scopes, allowed_ips, rate_limit, expires_in_days }", scopes: ["keys:manage", "*"] },
          { method: "PUT", path: "/api/admin/api-keys/:id", desc: "Update API key configuration", scopes: ["keys:manage", "*"] },
          { method: "POST", path: "/api/admin/api-keys/:id/toggle", desc: "Toggle API key active/disabled status", scopes: ["keys:manage", "*"] },
          { method: "POST", path: "/api/admin/api-keys/:id/regenerate", desc: "Regenerate API key secret token", scopes: ["keys:manage", "*"] },
          { method: "DELETE", path: "/api/admin/api-keys/:id", desc: "Permanently delete and revoke an API key", scopes: ["keys:manage", "*"] }
        ]
      },
      {
        category: "Centralized User Identity Mapping & Discord Bot",
        items: [
          { method: "GET", path: "/api/identity/lookup?provider=discord&id=:discord_id", desc: "Lookup panel user, role, permanent ID, and assigned VPS instances by external identity (Discord)", scopes: ["identity:read", "users:read", "*"] },
          { method: "GET", path: "/api/identity/discord/:id", desc: "Direct route alias to lookup user by Discord snowflake ID", scopes: ["identity:read", "users:read", "*"] },
          { method: "GET", path: "/api/identity/permanent/:permanent_id", desc: "Lookup user identity by global permanent UUID (usr_...)", scopes: ["identity:read", "users:read", "*"] },
          { method: "GET", path: "/api/identity/me", desc: "Fetch current user's permanent ID and all linked external platform accounts", scopes: ["identity:read", "*"] },
          { method: "POST", path: "/api/identity/link-code", desc: "Generate a secure, single-use 15-minute link code for Discord bot /link or panel pairing", scopes: ["identity:write", "*"] },
          { method: "POST", path: "/api/identity/verify-link", desc: "Verify link code and bind external identity with strict duplicate prevention: { code, provider_user_id, provider_username }", scopes: ["identity:write", "*"] },
          { method: "POST", path: "/api/identity/unlink", desc: "Unlink an external provider identity from panel user: { provider, user_id? }", scopes: ["identity:write", "*"] },
          { method: "GET", path: "/api/admin/users/:id/identities", desc: "Admin view of all external identities linked to a specific user", scopes: ["users:read", "identity:read", "*"] },
          { method: "POST", path: "/api/admin/users/:id/identities/link", desc: "Admin direct manual linking of an external provider identity: { provider, provider_user_id, provider_username }", scopes: ["users:manage", "identity:write", "*"] }
        ]
      },
      {
        category: "Discord Two-Factor Authentication (2FA) & Account Recovery",
        items: [
          { method: "POST", path: "/api/auth/2fa/verify", desc: "Verify 6-digit OTP code or single-use backup recovery code during login: { challengeToken, code, isBackupCode? }", scopes: ["*"] },
          { method: "POST", path: "/api/auth/2fa/resend", desc: "Resend 6-digit OTP code to user's Discord DM (60s cooldown): { challengeToken }", scopes: ["*"] },
          { method: "POST", path: "/api/auth/2fa/setup/start", desc: "Start 2FA enrollment: dispatches test 6-digit OTP to user's Discord DM", scopes: ["*"] },
          { method: "POST", path: "/api/auth/2fa/setup/confirm", desc: "Confirm test OTP, activate 2FA, and generate 10 single-use backup recovery codes: { challengeToken, code }", scopes: ["*"] },
          { method: "POST", path: "/api/auth/2fa/disable", desc: "Disable 2FA security protection: { password }", scopes: ["*"] },
          { method: "POST", path: "/api/auth/2fa/backup-codes/regenerate", desc: "Regenerate 10 new single-use backup recovery codes: { password }", scopes: ["*"] },
          { method: "POST", path: "/api/auth/forgot-password/request", desc: "Request account password reset OTP via Discord DM: { identifier }", scopes: ["*"] },
          { method: "POST", path: "/api/auth/forgot-password/verify-reset", desc: "Verify Discord reset OTP and set new password: { challengeToken, code, newPassword }", scopes: ["*"] },
          { method: "GET", path: "/api/auth/discord/connect", desc: "Get Discord OAuth2 account authorization URL", scopes: ["*"] },
          { method: "POST", path: "/api/auth/discord/unlink", desc: "Unlink Discord account from profile (requires 2FA disabled)", scopes: ["*"] },
          { method: "GET", path: "/api/admin/security/discord-bot-status", desc: "Admin check live Discord bot connection and API latency", scopes: ["monitoring:read", "*"] },
          { method: "POST", path: "/api/admin/users/:id/2fa/reset", desc: "Admin reset 2FA for locked-out user account", scopes: ["users:manage", "*"] }
        ]
      }
    ]
  };
  res.json({ ok: true, docs: docsData, ...docsData });
});

// ==========================================
// CENTRALIZED USER IDENTITY MAPPING ENDPOINTS
// ==========================================

function cleanupExpiredLinkCodes() {
  try {
    db.prepare("DELETE FROM identity_link_codes WHERE expires_at < CURRENT_TIMESTAMP OR used = 1").run();
  } catch {}
}

function handleIdentityLookup(provider, externalId, req, res, next) {
  try {
    if (!externalId) {
      return res.status(400).json({ error: "Missing external user identifier (e.g. Discord user ID)." });
    }

    const identityRow = db.prepare(`
      SELECT ui.*, u.id AS user_id, u.uuid, u.username, u.email, u.role, u.active, u.created_at AS user_created_at
      FROM user_identities ui
      JOIN users u ON ui.user_id = u.id
      WHERE ui.provider = ? AND ui.provider_user_id = ?
    `).get(provider, externalId);

    if (!identityRow) {
      return res.status(404).json({
        ok: false,
        found: false,
        provider,
        provider_user_id: externalId,
        error: `No panel user is mapped to ${provider} ID: ${externalId}. Account is not linked.`
      });
    }

    // Role-based access control: Non-admins can only look up their own linked identities
    if (!req.apiKey && req.user.role !== "admin" && identityRow.user_id !== req.user.id) {
      return res.status(403).json({ error: "Access denied. Insufficient permissions to inspect another user's identity." });
    }

    const servers = db.prepare(`
      SELECT s.id, s.vmid, s.name, s.type, s.pve_node, s.node_id, s.is_suspended, s.suspended_at, s.created_at, n.name AS node_name
      FROM servers s
      LEFT JOIN nodes n ON n.id = s.node_id
      WHERE s.user_id = ?
      ORDER BY s.id DESC
    `).all(identityRow.user_id);

    const enrichedServers = servers.map(s => {
      const live = serverLiveStatsMap.get(s.id) || {};
      return {
        ...s,
        status: live.status || "unknown",
        cpu_usage: live.cpu !== undefined ? live.cpu : null,
        mem_usage: live.mem !== undefined ? live.mem : null,
        ip: live.ip || null
      };
    });

    const allIdentities = db.prepare(`
      SELECT id, provider, provider_user_id, provider_username, provider_email, provider_avatar, linked_at
      FROM user_identities
      WHERE user_id = ?
      ORDER BY id ASC
    `).all(identityRow.user_id);

    audit(identityRow.user_id, "identity.lookup", `External query by ${req.apiKey ? 'API Key #' + req.apiKey.id : req.user.username} for ${provider}:${externalId}`, req);

    res.json({
      ok: true,
      found: true,
      permanent_id: identityRow.uuid,
      user: {
        id: identityRow.user_id,
        uuid: identityRow.uuid,
        permanent_id: identityRow.uuid,
        username: identityRow.username,
        email: identityRow.email,
        role: identityRow.role,
        active: !!identityRow.active,
        created_at: identityRow.user_created_at
      },
      matched_identity: {
        provider: identityRow.provider,
        provider_user_id: identityRow.provider_user_id,
        provider_username: identityRow.provider_username,
        provider_email: identityRow.provider_email,
        linked_at: identityRow.linked_at
      },
      linked_identities: allIdentities,
      stats: {
        total_servers: servers.length,
        suspended_servers: servers.filter(s => !!s.is_suspended).length,
        active_servers: servers.filter(s => !s.is_suspended).length
      },
      permissions: {
        is_admin: identityRow.role === "admin",
        is_active: !!identityRow.active,
        can_power: !!identityRow.active,
        can_reinstall: !!identityRow.active,
        can_create_vps: !!identityRow.active
      },
      servers: enrichedServers
    });
  } catch (e) {
    next(e);
  }
}

app.get("/api/identity/lookup", requireAuth, (req, res, next) => {
  const provider = String(req.query.provider || "discord").toLowerCase().trim();
  const externalId = String(req.query.id || req.query.discord_id || req.query.external_id || "").trim();
  handleIdentityLookup(provider, externalId, req, res, next);
});

app.get("/api/identity/discord/:id", requireAuth, (req, res, next) => {
  handleIdentityLookup("discord", String(req.params.id || "").trim(), req, res, next);
});

app.get("/api/identity/permanent/:permanent_id", requireAuth, (req, res, next) => {
  try {
    const permanentId = String(req.params.permanent_id || "").trim();
    if (!permanentId) return res.status(400).json({ error: "Missing permanent_id parameter." });

    const userRow = db.prepare(`
      SELECT id, uuid, username, email, role, active, created_at, avatar_url
      FROM users
      WHERE uuid = ?
    `).get(permanentId);

    if (!userRow) {
      return res.status(404).json({ ok: false, found: false, error: `No user found with permanent ID: ${permanentId}` });
    }

    if (!req.apiKey && req.user.role !== "admin" && userRow.id !== req.user.id) {
      return res.status(403).json({ error: "Access denied. Insufficient permissions." });
    }

    const servers = db.prepare(`
      SELECT s.id, s.vmid, s.name, s.type, s.pve_node, s.node_id, s.is_suspended, s.suspended_at, s.created_at, n.name AS node_name
      FROM servers s
      LEFT JOIN nodes n ON n.id = s.node_id
      WHERE s.user_id = ?
      ORDER BY s.id DESC
    `).all(userRow.id);

    const enrichedServers = servers.map(s => {
      const live = serverLiveStatsMap.get(s.id) || {};
      return {
        ...s,
        status: live.status || "unknown",
        cpu_usage: live.cpu !== undefined ? live.cpu : null,
        mem_usage: live.mem !== undefined ? live.mem : null,
        ip: live.ip || null
      };
    });

    const linkedIdentities = db.prepare(`
      SELECT id, provider, provider_user_id, provider_username, provider_email, provider_avatar, linked_at
      FROM user_identities
      WHERE user_id = ?
      ORDER BY id ASC
    `).all(userRow.id);

    audit(userRow.id, "identity.permanent_lookup", `External query by ${req.apiKey ? 'API Key #' + req.apiKey.id : req.user.username} for permanent_id:${permanentId}`, req);

    res.json({
      ok: true,
      found: true,
      permanent_id: userRow.uuid,
      user: safeUser(userRow),
      linked_identities: linkedIdentities,
      stats: {
        total_servers: servers.length,
        suspended_servers: servers.filter(s => !!s.is_suspended).length,
        active_servers: servers.filter(s => !s.is_suspended).length
      },
      permissions: {
        is_admin: userRow.role === "admin",
        is_active: !!userRow.active,
        can_power: !!userRow.active,
        can_reinstall: !!userRow.active,
        can_create_vps: !!userRow.active
      },
      servers: enrichedServers
    });
  } catch (e) {
    next(e);
  }
});

app.get("/api/identity/by-uuid/:uuid", requireAuth, (req, res, next) => {
  req.params.permanent_id = req.params.uuid;
  try {
    const permanentId = String(req.params.permanent_id || "").trim();
    const userRow = db.prepare(`
      SELECT id, uuid, username, email, role, active, created_at, avatar_url
      FROM users
      WHERE uuid = ?
    `).get(permanentId);

    if (!userRow) {
      return res.status(404).json({ ok: false, found: false, error: `No user found with permanent ID: ${permanentId}` });
    }

    if (!req.apiKey && req.user.role !== "admin" && userRow.id !== req.user.id) {
      return res.status(403).json({ error: "Access denied. Insufficient permissions." });
    }

    const servers = db.prepare(`
      SELECT s.id, s.vmid, s.name, s.type, s.pve_node, s.node_id, s.is_suspended, s.suspended_at, s.created_at, n.name AS node_name
      FROM servers s
      LEFT JOIN nodes n ON n.id = s.node_id
      WHERE s.user_id = ?
      ORDER BY s.id DESC
    `).all(userRow.id);

    const enrichedServers = servers.map(s => {
      const live = serverLiveStatsMap.get(s.id) || {};
      return {
        ...s,
        status: live.status || "unknown",
        cpu_usage: live.cpu !== undefined ? live.cpu : null,
        mem_usage: live.mem !== undefined ? live.mem : null,
        ip: live.ip || null
      };
    });

    const linkedIdentities = db.prepare(`
      SELECT id, provider, provider_user_id, provider_username, provider_email, provider_avatar, linked_at
      FROM user_identities
      WHERE user_id = ?
      ORDER BY id ASC
    `).all(userRow.id);

    audit(userRow.id, "identity.permanent_lookup", `External query by ${req.apiKey ? 'API Key #' + req.apiKey.id : req.user.username} for permanent_id:${permanentId}`, req);

    res.json({
      ok: true,
      found: true,
      permanent_id: userRow.uuid,
      user: safeUser(userRow),
      linked_identities: linkedIdentities,
      stats: {
        total_servers: servers.length,
        suspended_servers: servers.filter(s => !!s.is_suspended).length,
        active_servers: servers.filter(s => !s.is_suspended).length
      },
      permissions: {
        is_admin: userRow.role === "admin",
        is_active: !!userRow.active,
        can_power: !!userRow.active,
        can_reinstall: !!userRow.active,
        can_create_vps: !!userRow.active
      },
      servers: enrichedServers
    });
  } catch (e) {
    next(e);
  }
});

app.get("/api/identity/me", requireAuth, (req, res, next) => {
  try {
    const userRow = db.prepare("SELECT id, uuid, username, email, role, active, created_at, avatar_url FROM users WHERE id=?").get(req.user.id);
    if (!userRow) return res.status(404).json({ error: "User not found." });

    const identities = db.prepare(`
      SELECT id, provider, provider_user_id, provider_username, provider_email, provider_avatar, linked_at
      FROM user_identities
      WHERE user_id = ?
      ORDER BY id ASC
    `).all(req.user.id);

    res.json({
      ok: true,
      permanent_id: userRow.uuid,
      user: safeUser(userRow),
      identities
    });
  } catch (e) {
    next(e);
  }
});

app.post("/api/identity/link-code", requireAuth, (req, res, next) => {
  try {
    cleanupExpiredLinkCodes();
    const provider = String(req.body.provider || "discord").toLowerCase().trim();
    if (!["discord", "github", "google", "custom"].includes(provider)) {
      return res.status(400).json({ error: "Unsupported identity provider: " + provider });
    }

    let isBotInitiated = false;
    let providerUserId = "";
    let providerUsername = "";

    if (req.body.provider_user_id) {
      if (!req.apiKey && req.user.role !== "admin") {
        return res.status(403).json({ error: "Only API keys or administrators can generate bot-initiated linking codes." });
      }
      isBotInitiated = true;
      providerUserId = String(req.body.provider_user_id).trim();
      providerUsername = String(req.body.provider_username || "").trim();

      // DUPLICATE ACCOUNT PREVENTION: Check if already mapped
      const existing = db.prepare("SELECT u.username, u.id FROM user_identities ui JOIN users u ON ui.user_id = u.id WHERE ui.provider = ? AND ui.provider_user_id = ?").get(provider, providerUserId);
      if (existing) {
        return res.status(409).json({
          error: `This ${provider} account (${providerUsername || providerUserId}) is already bound to user @${existing.username}. Duplicate linking is prevented.`,
          already_linked: true,
          linked_user_id: existing.id
        });
      }
    }

    // Generate secure 6-character code
    const randomChars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let randomPart = "";
    for (let i = 0; i < 6; i++) {
      randomPart += randomChars[crypto.randomInt(0, randomChars.length)];
    }
    const code = "ATY-" + randomPart;

    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString().replace("T", " ").slice(0, 19);

    if (isBotInitiated) {
      db.prepare("DELETE FROM identity_link_codes WHERE provider = ? AND provider_user_id = ?").run(provider, providerUserId);
      db.prepare(`
        INSERT INTO identity_link_codes (provider, provider_user_id, provider_username, code, initiated_by, expires_at)
        VALUES (?, ?, ?, ?, 'bot', ?)
      `).run(provider, providerUserId, providerUsername, code, expiresAt);

      audit(null, "identity.bot_link_code_generated", `Bot generated code ${code} for ${provider}:${providerUserId} (${providerUsername})`, req);
    } else {
      db.prepare("DELETE FROM identity_link_codes WHERE user_id = ? AND provider = ?").run(req.user.id, provider);
      db.prepare(`
        INSERT INTO identity_link_codes (user_id, provider, code, initiated_by, expires_at)
        VALUES (?, ?, ?, 'panel', ?)
      `).run(req.user.id, provider, code, expiresAt);

      audit(req.user.id, "identity.panel_link_code_generated", `Generated link code ${code} for ${provider}`, req);
    }

    res.json({
      ok: true,
      code,
      provider,
      expires_in_seconds: 900,
      expires_at: expiresAt,
      instructions: isBotInitiated
        ? `Enter code ${code} in your Proxmox Panel Profile settings within 15 minutes to link your account.`
        : `Run /link code:${code} in Discord within 15 minutes.`
    });
  } catch (e) {
    next(e);
  }
});

app.post("/api/identity/verify-link", requireAuth, (req, res, next) => {
  try {
    cleanupExpiredLinkCodes();
    const rawCode = String(req.body.code || "").trim().toUpperCase();
    if (!rawCode) return res.status(400).json({ error: "Link code is required." });

    const codeRow = db.prepare(`
      SELECT * FROM identity_link_codes
      WHERE code = ? AND used = 0 AND expires_at > CURRENT_TIMESTAMP
    `).get(rawCode);

    if (!codeRow) {
      audit(req.user?.id || null, "identity.link_failed", `Failed link attempt with invalid or expired code "${rawCode}"`, req);
      return res.status(400).json({ error: "Invalid, expired, or already used linking code. Please generate a new code and try again." });
    }

    let targetUserId;
    let provider = codeRow.provider;
    let providerUserId;
    let providerUsername = "";
    let providerEmail = "";
    let providerAvatar = "";

    if (codeRow.initiated_by === "panel") {
      targetUserId = codeRow.user_id;
      providerUserId = String(req.body.provider_user_id || "").trim();
      providerUsername = String(req.body.provider_username || "").trim();
      providerEmail = String(req.body.provider_email || "").trim();
      providerAvatar = String(req.body.provider_avatar || "").trim();

      if (!providerUserId) {
        return res.status(400).json({ error: "Missing 'provider_user_id' (e.g. Discord user Snowflake ID)." });
      }
    } else {
      targetUserId = req.user.id;
      providerUserId = codeRow.provider_user_id;
      providerUsername = codeRow.provider_username;
      providerEmail = codeRow.provider_email || "";
      providerAvatar = codeRow.provider_avatar || "";
    }

    // STRICT DUPLICATE PREVENTION:
    const existingOtherUser = db.prepare(`
      SELECT ui.*, u.username
      FROM user_identities ui
      JOIN users u ON ui.user_id = u.id
      WHERE ui.provider = ? AND ui.provider_user_id = ?
    `).get(provider, providerUserId);

    if (existingOtherUser && existingOtherUser.user_id !== targetUserId) {
      audit(targetUserId, "identity.link_duplicate_blocked", `Blocked attempt to link already claimed ${provider} account (${providerUserId}) of @${existingOtherUser.username}`, req);
      return res.status(409).json({
        error: `Security Check Failed: This ${provider} account (${providerUsername || providerUserId}) is already bound to another panel account (@${existingOtherUser.username}). Duplicate linking is strictly prohibited.`
      });
    }

    const clientIp = (req.headers["x-forwarded-for"]?.split(",")[0] || req.ip || req.socket.remoteAddress || "").trim();

    // Remove any previous link for this specific provider on this user
    db.prepare("DELETE FROM user_identities WHERE user_id = ? AND provider = ?").run(targetUserId, provider);

    const metadata = JSON.stringify({
      linked_via: "code_verification",
      initiated_by: codeRow.initiated_by,
      actor_ip: clientIp,
      verified_at: new Date().toISOString()
    });

    db.prepare(`
      INSERT INTO user_identities (
        user_id, provider, provider_user_id, provider_username, provider_email, provider_avatar, metadata, linked_by_ip
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(targetUserId, provider, providerUserId, providerUsername, providerEmail, providerAvatar, metadata, clientIp);

    if (provider === "discord") {
      db.prepare(`
        UPDATE users
        SET discord_id = ?, discord_username = ?, discord_avatar = ?
        WHERE id = ?
      `).run(providerUserId, providerUsername, providerAvatar, targetUserId);
    }

    db.prepare("UPDATE identity_link_codes SET used = 1 WHERE id = ?").run(codeRow.id);

    const targetUser = db.prepare("SELECT * FROM users WHERE id = ?").get(targetUserId);

    audit(targetUserId, "identity.linked", `Successfully linked ${provider} account (${providerUsername || providerUserId})`, req);

    io.emit("identity:linked", {
      user_id: targetUserId,
      permanent_id: targetUser.uuid,
      provider,
      provider_user_id: providerUserId,
      provider_username: providerUsername
    });

    res.json({
      ok: true,
      message: `Account successfully linked with ${provider}!`,
      permanent_id: targetUser.uuid,
      user: safeUser(targetUser),
      identity: {
        provider,
        provider_user_id: providerUserId,
        provider_username: providerUsername,
        linked_at: new Date().toISOString()
      }
    });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) {
      return res.status(409).json({ error: "Duplicate identity constraint: This account is already linked." });
    }
    next(e);
  }
});

app.post("/api/identity/unlink", requireAuth, (req, res, next) => {
  try {
    const provider = String(req.body.provider || "discord").toLowerCase().trim();
    let targetUserId = req.user.id;

    if (req.body.user_id && req.user.role === "admin") {
      targetUserId = Number(req.body.user_id);
    }

    const existing = db.prepare("SELECT * FROM user_identities WHERE user_id = ? AND provider = ?").get(targetUserId, provider);
    if (!existing) {
      return res.status(404).json({ error: `No linked ${provider} identity found for this user.` });
    }

    if (provider === "discord") {
      const u = db.prepare("SELECT two_factor_enabled FROM users WHERE id = ?").get(targetUserId);
      if (u && u.two_factor_enabled) {
        return res.status(400).json({ error: "Please disable Two-Factor Authentication before unlinking your Discord account to prevent account lockout." });
      }
      db.prepare("UPDATE users SET discord_id = NULL, discord_username = NULL, discord_avatar = NULL WHERE id = ?").run(targetUserId);
    }

    db.prepare("DELETE FROM user_identities WHERE id = ?").run(existing.id);

    audit(targetUserId, "identity.unlinked", `Unlinked ${provider} identity (${existing.provider_username || existing.provider_user_id})`, req);

    io.emit("identity:unlinked", {
      user_id: targetUserId,
      provider
    });

    res.json({
      ok: true,
      message: `Successfully unlinked ${provider} account.`
    });
  } catch (e) {
    next(e);
  }
});

app.get("/api/admin/users/:id/identities", requireAuth, requireAdmin, (req, res, next) => {
  try {
    const userId = Number(req.params.id);
    const identities = db.prepare("SELECT * FROM user_identities WHERE user_id = ? ORDER BY id ASC").all(userId);
    res.json({ ok: true, user_id: userId, identities });
  } catch (e) {
    next(e);
  }
});

app.post("/api/admin/users/:id/identities/link", requireAuth, requireAdmin, (req, res, next) => {
  try {
    const userId = Number(req.params.id);
    const provider = String(req.body.provider || "discord").toLowerCase().trim();
    const providerUserId = validateString(req.body.provider_user_id, "Provider User ID", 64);
    const providerUsername = String(req.body.provider_username || "").trim();

    const existing = db.prepare("SELECT ui.*, u.username FROM user_identities ui JOIN users u ON ui.user_id = u.id WHERE ui.provider = ? AND ui.provider_user_id = ?").get(provider, providerUserId);
    if (existing && existing.user_id !== userId) {
      return res.status(409).json({ error: `This ${provider} ID is already mapped to user @${existing.username}.` });
    }

    db.prepare("DELETE FROM user_identities WHERE user_id = ? AND provider = ?").run(userId, provider);

    const clientIp = (req.headers["x-forwarded-for"]?.split(",")[0] || req.ip || req.socket.remoteAddress || "").trim();
    db.prepare(`
      INSERT INTO user_identities (user_id, provider, provider_user_id, provider_username, metadata, linked_by_ip)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(userId, provider, providerUserId, providerUsername, JSON.stringify({ linked_by_admin: req.user.username }), clientIp);

    audit(userId, "identity.admin_linked", `Admin ${req.user.username} manually linked ${provider}:${providerUserId} (${providerUsername})`, req);

    io.emit("identity:linked", { user_id: userId, provider, provider_user_id: providerUserId, provider_username: providerUsername });

    res.json({ ok: true, message: `Successfully linked ${provider} identity.` });
  } catch (e) {
    next(e);
  }
});


// ============================================================================
// PTERODACTYL-STYLE REST API (DISCORD BOT, WHMCS & EXTERNAL INTEGRATIONS)
// Directly queries users and their assigned VPS instances by email or ID
// ============================================================================

function getEnrichedUserServers(userId) {
  const servers = db.prepare(`
    SELECT s.id, s.vmid, s.name, s.type, s.pve_node, s.node_id, s.is_suspended, s.suspended_at, s.suspend_reason,
           s.expires_at, s.duration_days, s.auto_renew, s.expired_at, s.last_renewed_at, s.created_at, n.name AS node_name
    FROM servers s
    LEFT JOIN nodes n ON n.id = s.node_id
    WHERE s.user_id = ?
    ORDER BY s.id DESC
  `).all(userId);

  return servers.map(s => {
    const live = serverLiveStatsMap.get(s.id) || {};
    const exp = enrichServerExpiry(s);
    return {
      id: s.id,
      vmid: s.vmid,
      name: s.name,
      node: s.node_name || s.pve_node || "default",
      node_id: s.node_id,
      type: s.type,
      status: s.is_suspended ? "suspended" : (live.status || "unknown"),
      uptime: live.uptime || 0,
      cpu_usage: live.cpu !== undefined ? live.cpu : null,
      mem_usage: live.mem !== undefined ? live.mem : null,
      ip: live.ip || null,
      is_suspended: Boolean(s.is_suspended),
      suspended_at: s.suspended_at || null,
      suspend_reason: s.suspend_reason || null,
      expires_at: exp.expires_at,
      duration_days: exp.duration_days,
      is_expired: exp.is_expired,
      days_left: exp.days_left,
      hours_left: exp.hours_left,
      expiry_status: exp.expiry_status,
      last_renewed_at: s.last_renewed_at || null,
      created_at: s.created_at
    };
  });
}

// 1. Direct Email Lookup: GET /api/users/email/:email
// Designed specifically for Discord Bots and billing panels querying by email!
app.get("/api/users/email/:email", requireAuth, (req, res, next) => {
  try {
    const email = String(req.params.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ ok: false, error: "Email parameter is required." });

    const user = db.prepare(`
      SELECT id, uuid, username, email, role, active, created_at, avatar_url
      FROM users
      WHERE LOWER(email) = ?
    `).get(email);

    if (!user) {
      return res.status(404).json({ ok: false, found: false, error: `No user found with email: ${email}` });
    }

    if (!req.apiKey && req.user.role !== "admin" && user.id !== req.user.id) {
      return res.status(403).json({ error: "Access denied." });
    }

    const servers = getEnrichedUserServers(user.id);
    audit(user.id, "api.user_lookup_email", `User & VPS queried via email (${email}) by ${req.apiKey ? 'API Key: ' + req.apiKey.name : req.user.username}`, req);

    res.json({
      ok: true,
      found: true,
      user: safeUser(user),
      server_count: servers.length,
      servers
    });
  } catch (e) {
    next(e);
  }
});

// 2. Query Lookup (by ?email=... or ?username=... or ?id=...): GET /api/users/lookup
app.get("/api/users/lookup", requireAuth, (req, res, next) => {
  try {
    const email = req.query.email ? String(req.query.email).trim().toLowerCase() : null;
    const username = req.query.username ? String(req.query.username).trim().toLowerCase() : null;
    const userId = req.query.id ? Number(req.query.id) : null;

    if (!email && !username && !userId) {
      return res.status(400).json({ ok: false, error: "Please provide ?email=, ?username=, or ?id= query parameter." });
    }

    let user = null;
    if (email) {
      user = db.prepare("SELECT id, uuid, username, email, role, active, created_at, avatar_url FROM users WHERE LOWER(email) = ?").get(email);
    } else if (username) {
      user = db.prepare("SELECT id, uuid, username, email, role, active, created_at, avatar_url FROM users WHERE LOWER(username) = ?").get(username);
    } else if (userId) {
      user = db.prepare("SELECT id, uuid, username, email, role, active, created_at, avatar_url FROM users WHERE id = ?").get(userId);
    }

    if (!user) {
      return res.status(404).json({ ok: false, found: false, error: "User not found." });
    }

    if (!req.apiKey && req.user.role !== "admin" && user.id !== req.user.id) {
      return res.status(403).json({ error: "Access denied." });
    }

    const servers = getEnrichedUserServers(user.id);
    audit(user.id, "api.user_lookup", `Queried user @${user.username} by ${req.apiKey ? 'API Key: ' + req.apiKey.name : req.user.username}`, req);

    res.json({
      ok: true,
      found: true,
      user: safeUser(user),
      server_count: servers.length,
      servers
    });
  } catch (e) {
    next(e);
  }
});

// 3. Pterodactyl-Compatible Application Users API: GET /api/application/users
app.get("/api/application/users", requireAuth, (req, res, next) => {
  try {
    if (!req.apiKey && req.user.role !== "admin") {
      return res.status(403).json({ error: "Administrator permission required to view application users." });
    }
    const filterEmail = (req.query?.filter?.email || req.query["filter[email]"] || req.query.email || "").toString().trim().toLowerCase();
    const filterUsername = (req.query?.filter?.username || req.query["filter[username]"] || req.query.username || "").toString().trim().toLowerCase();
    const search = (req.query.search || "").toString().trim().toLowerCase();

    let query = "SELECT id, uuid, username, email, role, active, created_at FROM users WHERE 1=1";
    const params = [];

    if (filterEmail) {
      query += " AND LOWER(email) = ?";
      params.push(filterEmail);
    }
    if (filterUsername) {
      query += " AND LOWER(username) = ?";
      params.push(filterUsername);
    }
    if (search) {
      query += " AND (LOWER(email) LIKE ? OR LOWER(username) LIKE ?)";
      params.push(`%${search}%`, `%${search}%`);
    }

    query += " ORDER BY id ASC";
    const users = db.prepare(query).all(...params);

    const data = users.map(u => {
      const servers = getEnrichedUserServers(u.id);
      return {
        object: "user",
        attributes: {
          id: u.id,
          uuid: u.uuid,
          username: u.username,
          email: u.email,
          role: u.role,
          root_admin: u.role === "admin",
          active: Boolean(u.active),
          created_at: u.created_at,
          server_count: servers.length,
          servers
        }
      };
    });

    res.json({
      object: "list",
      data,
      users: users.map(u => ({ ...safeUser(u), servers: getEnrichedUserServers(u.id) })),
      meta: {
        pagination: {
          total: users.length,
          count: users.length,
          per_page: users.length,
          current_page: 1,
          total_pages: 1
        }
      },
      ok: true
    });
  } catch (e) {
    next(e);
  }
});

// 4. Pterodactyl-Compatible Single User API: GET /api/application/users/:id
app.get("/api/application/users/:id", requireAuth, (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!req.apiKey && req.user.role !== "admin" && id !== req.user.id) {
      return res.status(403).json({ error: "Access denied." });
    }
    const u = db.prepare("SELECT id, uuid, username, email, role, active, created_at FROM users WHERE id = ?").get(id);
    if (!u) return res.status(404).json({ error: "User not found." });

    const servers = getEnrichedUserServers(u.id);
    res.json({
      object: "user",
      attributes: {
        id: u.id,
        uuid: u.uuid,
        username: u.username,
        email: u.email,
        role: u.role,
        root_admin: u.role === "admin",
        active: Boolean(u.active),
        created_at: u.created_at,
        server_count: servers.length,
        servers
      },
      user: { ...safeUser(u), servers },
      ok: true
    });
  } catch (e) {
    next(e);
  }
});

// 5. Get Servers of a User: GET /api/users/:id/servers
app.get("/api/users/:id/servers", requireAuth, (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const u = db.prepare("SELECT id, username, email FROM users WHERE id = ?").get(id);
    if (!u) return res.status(404).json({ error: "User not found." });

    if (!req.apiKey && req.user.role !== "admin" && u.id !== req.user.id) {
      return res.status(403).json({ error: "Access denied." });
    }

    const servers = getEnrichedUserServers(u.id);
    res.json({
      ok: true,
      user_id: u.id,
      username: u.username,
      email: u.email,
      server_count: servers.length,
      servers
    });
  } catch (e) {
    next(e);
  }
});

// 6. Application All Servers API: GET /api/application/servers
app.get("/api/application/servers", requireAuth, (req, res, next) => {
  try {
    if (!req.apiKey && req.user.role !== "admin") {
      return res.status(403).json({ error: "Administrator permission required to view all cluster servers." });
    }
    const allServers = db.prepare(`
      SELECT s.id, s.vmid, s.name, s.type, s.pve_node, s.node_id, s.is_suspended, s.suspended_at, s.suspend_reason,
             s.expires_at, s.duration_days, s.auto_renew, s.expired_at, s.last_renewed_at, s.created_at,
             u.id AS user_id, u.username, u.email, n.name AS node_name
      FROM servers s
      LEFT JOIN users u ON u.id = s.user_id
      LEFT JOIN nodes n ON n.id = s.node_id
      ORDER BY s.id DESC
    `).all();

    const data = allServers.map(s => {
      const live = serverLiveStatsMap.get(s.id) || {};
      const exp = enrichServerExpiry(s);
      return {
        id: s.id,
        vmid: s.vmid,
        name: s.name,
        node: s.node_name || s.pve_node || "default",
        type: s.type,
        status: s.is_suspended ? "suspended" : (live.status || "unknown"),
        uptime: live.uptime || 0,
        cpu_usage: live.cpu !== undefined ? live.cpu : null,
        mem_usage: live.mem !== undefined ? live.mem : null,
        ip: live.ip || null,
        is_suspended: Boolean(s.is_suspended),
        suspended_at: s.suspended_at || null,
        suspend_reason: s.suspend_reason || null,
        expires_at: exp.expires_at,
        duration_days: exp.duration_days,
        is_expired: exp.is_expired,
        days_left: exp.days_left,
        hours_left: exp.hours_left,
        expiry_status: exp.expiry_status,
        last_renewed_at: s.last_renewed_at || null,
        user: {
          id: s.user_id,
          username: s.username,
          email: s.email
        }
      };
    });

    res.json({
      ok: true,
      total: data.length,
      data
    });
  } catch (e) {
    next(e);
  }
});

// 7. Pterodactyl-Compatible Power Action Endpoint: POST /api/servers/:id/power
app.post("/api/servers/:id/power", requireAuth, async (req, res, next) => {
  try {
    const action = (req.body.action || req.body.signal || "").toLowerCase().trim();
    if (!action) return res.status(400).json({ error: "Missing action or signal in request body (e.g. 'start', 'stop', 'restart')." });

    const allowedActions = {
      start: "/status/start",
      stop: "/status/stop",
      kill: "/status/stop",
      restart: "/status/reboot",
      reboot: "/status/reboot",
      shutdown: "/status/shutdown",
      reset: "/status/reset"
    };

    if (!allowedActions[action]) {
      return res.status(400).json({
        error: `Unsupported power signal '${action}'. Allowed signals: start, stop, restart, reboot, shutdown, reset, kill.`
      });
    }

    const server = ownedServer(req, Number(req.params.id));
    if (!server) return res.status(404).json({ error: "Server not found." });

    if (server.is_suspended) {
      return res.status(403).json({
        error: `VPS #${server.vmid} is currently SUSPENDED. Power operations are blocked until unsuspended.`,
        is_suspended: true,
        suspended: true
      });
    }

    const node = getNode(server.node_id);
    await ensureServerPveNode(server, node);
    const suffix = allowedActions[action];
    const upid = await pve(node, "POST", serverEndpoint(server, suffix));
    audit(req.user.id, `vps.power_${action}`, `Power signal '${action}' on VMID ${server.vmid} via API`, req);
    notifyVpsChanged(server.id, action);

    res.json({
      ok: true,
      message: `Signal '${action}' sent to VMID ${server.vmid}`,
      action,
      upid
    });
  } catch (e) {
    if (e.message && (e.message.includes("not found") || e.message.includes("Access denied"))) {
      return res.status(e.status || 404).json({ error: e.message });
    }
    next(e);
  }
});

app.get("*", (req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ error: "API endpoint not found." });
  }
  if (req.path.includes(".") && !req.path.endsWith(".html")) {
    return res.status(404).type("text/plain").send("Not Found");
  }

  try {
    const rawHtml = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
    const s = getSettings();
    const siteName = s.site_name || "ALPM";
    const siteTitle = `${siteName} — VPS Control Panel`;
    const siteDesc = s.seo_description || s.site_description || "Next-Generation Proxmox VE VPS Cloud Management Platform";
    const ogImg = s.og_image || s.site_icon || "";
    const iconImg = s.site_icon || "";
    const favIcon = s.site_favicon || iconImg;
    const initial = (siteName.trim()[0] || "A").toUpperCase();
    const brandHtml = iconImg
      ? `<img class="brand-logo-img" src="${iconImg}" alt="${siteName}"><span>${siteName}</span>`
      : `<span class="brand-mark">${initial}</span><span>${siteName}</span>`;

    let html = rawHtml
      .replace(/<title>[\s\S]*?<\/title>/i, `<title>${siteTitle}</title>`)
      .replace(/<meta name="description"[^>]*>/i, `<meta name="description" content="${siteDesc}">`)
      .replace(/<meta property="og:title"[^>]*>/i, `<meta property="og:title" content="${siteTitle}">`)
      .replace(/<meta property="og:description"[^>]*>/i, `<meta property="og:description" content="${siteDesc}">`)
      .replace(/<meta property="og:image"[^>]*>/i, `<meta property="og:image" content="${ogImg}">`)
      .replace(/<link rel="icon"[^>]*>/i, favIcon ? `<link rel="icon" href="${favIcon}">` : '<link rel="icon" href="data:,">')
      .replace(/<div class="brand"><span class="brand-mark">[\s\S]*?<\/div>/i, `<div class="brand">${brandHtml}</div>`);

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.send(html);
  } catch (err) {
    res.sendFile(path.join(__dirname, "index.html"));
  }
});

app.use((err, req, res, next) => {
  const status = Number(err.status) || 500;
  if (err.isNodeDown) {
    console.warn(`[${new Date().toISOString()}] [Proxmox Node Alert]: ${err.message}`);
  } else if (status >= 500) {
    console.error(`[${new Date().toISOString()}]`, err);
  }

  const clientMessage = (status >= 500 && process.env.NODE_ENV === "production")
    ? "An internal server error occurred."
    : (err.message || "An unexpected error occurred.");

  res.status(status).json({
    error: clientMessage,
    is_node_down: !!err.isNodeDown,
    node_name: err.nodeName || null,
    node_host: err.nodeHost || null,
    node_id: err.nodeId || null,
    reason: err.reason || null,
    details: status < 500 ? (err.originalMessage || null) : null
  });
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
  if (!targetSocket || !targetSocket.userId) return;
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
    if (targetSocket.userRole !== "admin") {
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
  const row = db.prepare("SELECT user_id FROM servers WHERE id=?").get(serverId);
  const payload = { serverId, action, timestamp: Date.now() };
  io.to("admins").emit("vps:status_changed", payload);
  if (row && row.user_id) {
    io.to(`user_${row.user_id}`).emit("vps:status_changed", payload);
  }
  io.to(`vps_${serverId}`).emit("vps:status_changed", payload);
  setTimeout(pollLiveMetrics, 300);
  setTimeout(pollLiveMetrics, 1400);
}

function authenticateSocket(socket) {
  const req = socket.request;
  let sessionUserId = req && req.session && req.session.user ? req.session.user.id : null;
  if (!sessionUserId) {
    const token = socket.handshake?.auth?.token || socket.handshake?.query?.token || socket.handshake?.query?.api_key;
    if (token && typeof token === "string" && token.startsWith("atyro_live_") && token.length >= 40) {
      const keyHash = crypto.createHash("sha256").update(token.trim()).digest("hex");
      const key = db.prepare("SELECT user_id, active, key_hash FROM api_keys WHERE key_hash = ?").get(keyHash);
      if (key && key.active) {
        const calcBuf = Buffer.from(keyHash, "hex");
        const dbBuf = Buffer.from(key.key_hash, "hex");
        if (calcBuf.length === dbBuf.length && crypto.timingSafeEqual(calcBuf, dbBuf)) {
          sessionUserId = key.user_id;
        }
      }
    }
  }
  if (!sessionUserId) return null;

  const current = db.prepare("SELECT id, username, email, role, active FROM users WHERE id=?").get(sessionUserId);
  if (!current || !current.active) return null;

  socket.userId = current.id;
  socket.userRole = current.role;
  socket.username = current.username;
  return current;
}

function setupSocketIO() {
  io.on("connection", (socket) => {
    const user = authenticateSocket(socket);
    if (user) {
      socket.join(`user_${user.id}`);
      if (user.role === "admin") socket.join("admins");
      socket.join("authenticated");
    }

    socket.on("auth:sync", () => {
      // Re-verify strictly from server-side database session
      const refreshedUser = authenticateSocket(socket);
      if (refreshedUser) {
        socket.join(`user_${refreshedUser.id}`);
        if (refreshedUser.role === "admin") socket.join("admins");
        socket.join("authenticated");
        sendImmediateBatchStats(socket);
      }
    });

    socket.on("subscribe_vps", ({ id }) => {
      const vpsId = Number(id);
      if (!vpsId || isNaN(vpsId)) return;
      if (!socket.userId) return; // Unauthenticated clients cannot subscribe

      // Authorization check: User must be admin or the assigned owner of this VPS
      const server = db.prepare("SELECT id, user_id FROM servers WHERE id=?").get(vpsId);
      if (!server) return;
      if (socket.userRole !== "admin" && server.user_id !== socket.userId) {
        return; // Denied: Not authorized to view or subscribe to this VPS
      }

      socket.join(`vps_${vpsId}`);
      sendSingleVpsStats(vpsId, socket);
    });

    socket.on("unsubscribe_vps", ({ id }) => {
      const vpsId = Number(id);
      if (vpsId) {
        socket.leave(`vps_${vpsId}`);
      }
    });

    socket.on("request_sync", () => {
      if (socket.userId) {
        sendImmediateBatchStats(socket);
      }
    });
  });

  setInterval(pollLiveMetrics, 3000);
  setInterval(pollClusterTasks, 5000);
  setInterval(checkExpiredServers, 30000);
  setTimeout(checkExpiredServers, 2000);
}

// Background Auto-Suspension Worker for Expired VPS Instances
let isCheckingExpired = false;
async function checkExpiredServers() {
  if (isCheckingExpired) return;
  isCheckingExpired = true;
  try {
    const nowIso = new Date().toISOString();
    const expiredServers = db.prepare(`
      SELECT s.*, n.name AS node_name, n.host, n.port, n.token_id, n.token_secret_enc, n.tls_verify, n.enabled
      FROM servers s
      JOIN nodes n ON n.id = s.node_id
      WHERE s.expires_at IS NOT NULL
        AND s.expires_at != ''
        AND s.expires_at <= ?
        AND s.is_suspended = 0
    `).all(nowIso);

    if (expiredServers.length > 0) {
      console.log(`[Expiry Worker] Found ${expiredServers.length} expired VPS instance(s) to automatically suspend.`);
    }

    for (const s of expiredServers) {
      try {
        const reason = `Plan expired on ${new Date(s.expires_at).toLocaleString()}`;
        let poweredOff = false;

        // Gracefully attempt to shutdown/stop VM on Proxmox VE
        try {
          const node = getNode(s.node_id);
          await ensureServerPveNode(s, node);
          const st = await pve(node, "GET", serverEndpoint(s, "/status/current"));
          if (st && st.status === "running") {
            try {
              await pve(node, "POST", serverEndpoint(s, "/status/shutdown"));
            } catch (_) {
              await pve(node, "POST", serverEndpoint(s, "/status/stop"));
            }
            poweredOff = true;
          }
        } catch (pveErr) {
          console.warn(`[Expiry Worker Notice] Proxmox stop notice for VM ${s.vmid}:`, pveErr.message);
        }

        db.prepare(`
          UPDATE servers
          SET is_suspended = 1,
              suspended_at = CURRENT_TIMESTAMP,
              suspend_reason = ?,
              expired_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).run(reason, s.id);

        audit(1, "server_auto_suspend_expired", `VPS #${s.id} (VMID ${s.vmid}) automatically suspended due to plan expiration (${s.expires_at}). VM powered off: ${poweredOff}`, null);
        notifyVpsChanged(s.id, "suspend");

        if (typeof io !== "undefined" && io) {
          io.emit("vps:suspended", {
            id: s.id,
            vmid: s.vmid,
            is_suspended: 1,
            reason,
            is_expired: 1,
            expired_at: nowIso
          });
        }
        console.log(`[Expiry Worker] Successfully auto-suspended expired VPS #${s.id} (VMID ${s.vmid}).`);
      } catch (itemErr) {
        console.error(`[Expiry Worker] Failed auto-suspending VPS #${s.id}:`, itemErr.message);
      }
    }
  } catch (err) {
    console.error("[Expiry Worker Error]:", err.message);
  } finally {
    isCheckingExpired = false;
  }
}

function setupConsoleWebSocket() {
  const wssConsole = new WebSocket.Server({ noServer: true });

  server.on("upgrade", (req, socket, head) => {
    try {
      const parsed = new URL(req.url, `http://${req.headers.host || "localhost"}`);
      if (parsed.pathname === "/ws/console") {
        wssConsole.handleUpgrade(req, socket, head, (ws) => {
          wssConsole.emit("connection", ws, req);
        });
      }
    } catch (err) {
      console.error("[Console Bridge] Upgrade error:", err.message);
    }
  });

  wssConsole.on("connection", (clientWs, req) => {
    try {
      const parsed = new URL(req.url, `http://${req.headers.host || "localhost"}`);
      const sessionId = parsed.searchParams.get("session");

      if (!sessionId || !activeConsoleSessions.has(sessionId)) {
        clientWs.send(JSON.stringify({ type: "error", message: "Console session invalid or expired. Please retry." }));
        clientWs.close(4401, "Unauthorized or expired session");
        return;
      }

      const sessionData = activeConsoleSessions.get(sessionId);
      activeConsoleSessions.delete(sessionId);

      const { server: vps, node, pveNode, pveData } = sessionData;
      const tokenSecret = decrypt(node.token_secret_enc);
      const pveWsUrl = `wss://${node.host}:${node.port}/api2/json/nodes/${encodeURIComponent(pveNode)}/${vps.type}/${vps.vmid}/vncwebsocket?port=${encodeURIComponent(pveData.port)}&vncticket=${encodeURIComponent(pveData.ticket)}`;

      const pveWs = new WebSocket(pveWsUrl, {
        headers: {
          Authorization: `PVEAPIToken=${node.token_id}=${tokenSecret}`
        },
        rejectUnauthorized: Boolean(node.tls_verify)
      });

      let handshaken = false;
      let keepAliveTimer = null;
      const earlyQueue = [];

      pveWs.on("open", () => {
        // Handshake: user:ticket\n
        pveWs.send(`${pveData.user}:${pveData.ticket}\n`);

        // Send keepalive ping to Proxmox every 3 seconds to keep TTY connection alive
        keepAliveTimer = setInterval(() => {
          if (pveWs.readyState === WebSocket.OPEN && handshaken) {
            try { pveWs.send("2"); } catch {}
          }
        }, 3000);
      });

      pveWs.on("message", (msg) => {
        const str = msg.toString("utf8");
        if (!handshaken) {
          if (str.trim() === "OK") {
            handshaken = true;
            if (clientWs.readyState === WebSocket.OPEN) {
              clientWs.send(JSON.stringify({ type: "status", status: "connected" }));
            }
            // Flush buffered early messages (such as early fit/resize or early keystrokes)
            while (earlyQueue.length > 0) {
              const item = earlyQueue.shift();
              try {
                if (pveWs.readyState === WebSocket.OPEN) pveWs.send(item);
              } catch (_) {}
            }
            return;
          }
        }
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.send(JSON.stringify({ type: "data", data: str }));
        }
      });

      pveWs.on("error", (err) => {
        console.error(`[Console Bridge] Proxmox WS error for VM ${vps.vmid}:`, err.message);
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.send(JSON.stringify({ type: "error", message: `Proxmox connection error: ${err.message}` }));
        }
      });

      pveWs.on("close", (code, reason) => {
        if (keepAliveTimer) clearInterval(keepAliveTimer);
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.send(JSON.stringify({ type: "status", status: "disconnected" }));
          clientWs.close();
        }
      });

      clientWs.on("message", (raw) => {
        try {
          const msg = JSON.parse(raw.toString("utf8"));
          if (!pveWs) return;

          let payload = null;
          if (msg.type === "input" && typeof msg.data === "string") {
            payload = `0:${Buffer.byteLength(msg.data, "utf8")}:${msg.data}`;
          } else if (msg.type === "resize") {
            const cols = Math.max(10, Math.min(500, Number(msg.cols) || 80));
            const rows = Math.max(5, Math.min(200, Number(msg.rows) || 24));
            payload = `1:${cols}:${rows}:`;
          } else if (msg.type === "ping") {
            if (handshaken && pveWs.readyState === WebSocket.OPEN) {
              pveWs.send("2");
            }
            if (clientWs.readyState === WebSocket.OPEN) {
              clientWs.send(JSON.stringify({ type: "pong" }));
            }
            return;
          }

          if (payload) {
            if (!handshaken || pveWs.readyState !== WebSocket.OPEN) {
              earlyQueue.push(payload);
            } else {
              pveWs.send(payload);
            }
          }
        } catch (err) {
          console.warn("[Console Bridge] Client message error:", err.message);
        }
      });

      const cleanup = () => {
        if (keepAliveTimer) clearInterval(keepAliveTimer);
        if (pveWs && pveWs.readyState === WebSocket.OPEN) {
          try { pveWs.close(); } catch {}
        }
      };

      clientWs.on("close", cleanup);
      clientWs.on("error", cleanup);

    } catch (err) {
      console.error("[Console Bridge] Connection initialization error:", err);
      try {
        clientWs.send(JSON.stringify({ type: "error", message: err.message }));
        clientWs.close(1011, "Internal server error");
      } catch {}
    }
  });
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
    try {
      if (!fs.existsSync(SETUP_LOCK_FILE)) {
        fs.writeFileSync(SETUP_LOCK_FILE, JSON.stringify({ completed_at: new Date().toISOString(), locked: true }));
      }
    } catch {}
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
setupConsoleWebSocket();

bootstrapAdmin().then(() => {
  server.listen(PORT, HOST, () => console.log(`Atyro VPS Panel listening on http://${HOST}:${PORT}`));
}).catch(err => { console.error("Bootstrap failed:", err); process.exit(1); });
