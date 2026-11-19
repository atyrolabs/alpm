# ALPM — Proxmox VPS Management Panel

<p align="center">
  <img src="https://img.shields.io/badge/ALPM-v2.1.0-orange?style=for-the-badge" alt="ALPM Version">
  <img src="https://img.shields.io/badge/Developer-Atyro%20Labs-white?style=for-the-badge" alt="Atyro Labs">
  <img src="https://img.shields.io/badge/Platform-Proxmox%20VE%207%20%2F%208-orange?style=for-the-badge" alt="Proxmox VE">
  <img src="https://img.shields.io/badge/Node.js-20%2B-green?style=for-the-badge" alt="Node.js">
  <img src="https://img.shields.io/badge/Discord%202FA-Enabled-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord 2FA">
  <img src="https://img.shields.io/badge/REST%20API-v1-blue?style=for-the-badge" alt="REST API">
</p>

<p align="center">
  <b>A powerful, modern, self-hosted Proxmox VE management platform designed to simplify VPS administration, virtualization management, automated provisioning, and cloud infrastructure operations.</b>
</p>

<p align="center">
  <a href="https://github.com/atyrolabs/alpm">GitHub Repository</a> •
  <a href="https://github.com/atyrolabs">Atyro Labs</a> •
  <a href="ALPM-API_DOCS.md">API Documentation</a> •
  <a href="https://github.com/atyrolabs/alpm/issues">Report Issues</a>
</p>

---

## 🚀 Introduction

**ALPM (Atyro Labs Proxmox Management)** is a next-generation Proxmox VPS management panel developed by **Atyro Labs**.

Built on a unified **Node.js, Express.js, SQLite, and Socket.IO** architecture communicating directly with the official Proxmox VE REST API, ALPM delivers a high-performance, single-page control panel for provisioning, managing, and monitoring virtual machines (QEMU/KVM) and containers (LXC) across multiple Proxmox clusters.

ALPM is built for hosting providers, system administrators, and infrastructure operators who need an intuitive, fast, and secure alternative to the default Proxmox web interface.

### ✨ Highlights

- **All-In-One Unified Architecture**: Consolidated backend with zero external script bloat; zero build step required.
- **Multi-Node Cluster Management**: Connect multiple physical Proxmox VE nodes with encrypted credentials.
- **Full QEMU & LXC Lifecycle**: Start, stop, graceful shutdown, reset, reinstall OS, clone, edit specs, resize disks, and assign users.
- **Discord 2FA & Bot Integration**: Native Two-Factor Authentication via Discord Bot DM OTPs, OAuth2 account linking, and single-use backup recovery codes.
- **Public REST API & API Keys**: Programmatic administration via Bearer token API keys with granular scopes and CIDR IP whitelisting.
- **VPS Expiration & Auto-Lifecycle**: Customizable validity periods (7 days to Lifetime) with automated suspension upon expiration and renewal flows.
- **Dedicated Template IP Pools**: Pre-configured static IPv4/IPv6 address pools assigned automatically during provisioning.
- **Interactive Browser Terminal**: High-performance xterm.js Web-based console powered by Proxmox terminal proxy WebSockets with deduplicated clipboard paste.
- **Real-Time Infrastructure Telemetry**: Live CPU, RAM, disk I/O, network traffic graphs, and dynamic Proxmox node health monitoring.
- **Multi-Device Responsive Design**: Fully responsive interface tailored for smartphones, tablets, and wide desktop screens.

---

## ⚡ Features

### 🖥️ Virtual Machine & Container Management
Manage all your compute instances directly from the ALPM dashboard:
- **QEMU/KVM & LXC Support**: Native provisioning and management for both full virtual machines and lightweight containers.
- **Power Operations**: Instant start, graceful ACPI shutdown, forced stop, reboot, and hard reset.
- **Real-time Live Specifications Editor**:
  - CPU cores, sockets, CPU type (`host`, `kvm64`, `qemu64`), and vCPU hotplug limits.
  - RAM allocation and dynamic memory ballooning minimums.
  - Disk I/O throttling (read/write MB/s and IOPS limits) and online disk storage expansion.
  - Network interface configuration: bridge selection (`vmbr0`), VLAN tags, MTU, rate limiting, and MAC address assignments.
- **Proxmox Hardware Auto-Detection**: Real-time detection of physical Proxmox storage pools (`local-lvm`, `ceph`, `zfs`), available ISOs, container templates, and network bridges without hardcoded values.
- **One-Click OS Reinstallation**: Reinstall QEMU and LXC instances from clean templates or cloud-init with custom root credentials.
- **Cloning & Duplication**: Instant linked and full clones of existing virtual instances.
- **Interactive Proxmox Raw Configuration**: Inspect the exact underlying Proxmox configuration file (`/etc/pve/qemu-server/<vmid>.conf` or `/etc/pve/lxc/<vmid>.conf`).

### 🔐 Discord Two-Factor Authentication (2FA) & Bot Integration
Built-in Discord security engine for enterprise-grade account protection:
- **Discord Bot DM OTPs**: Deliver single-use 6-digit numeric verification codes directly to the user's Discord Direct Messages on sign-in, password reset, or sensitive administrative actions.
- **OAuth2 Account Linking**: Users connect their Discord account directly within **My Profile** using official Discord OAuth2 authorization.
- **Hashed Backup Recovery Codes**: Generates 10 single-use, cryptographically hashed backup codes (`XXXX-XXXX-XXXX`) for emergency account access when Discord is unavailable.
- **Password Reset via Discord**: Users can reset forgotten passwords by verifying an OTP sent to their linked Discord DM.
- **Discord Bot Health Checker**: Live monitoring of Discord Bot status, bot ping, username tag, and API permissions directly inside the Admin Security panel (`/api/admin/security/discord-bot-status`).

### 🔑 API Keys & Integrations (REST API)
A full-featured developer API engine enabling automated provisioning and external billing system integration:
- **Bearer Token Authentication**: Secure requests using standard `Authorization: Bearer atyro_live_...` headers.
- **AES-256-GCM Token Encryption**: API tokens are encrypted in the database at rest and decrypted on-demand.
- **Granular Permission Scopes**:
  - `*` — Unrestricted full administrative access.
  - `vps:*`, `vps:read`, `vps:write`, `vps:actions` — VPS controls.
  - `templates:*`, `templates:read`, `templates:deploy` — Template provisioning.
  - `nodes:*`, `nodes:read` — Proxmox node infrastructure.
  - `users:*`, `users:read`, `users:manage` — User account administration.
  - `monitoring:read`, `logs:read` — Metrics and audit log streams.
- **IP & CIDR Whitelisting**: Restrict each API key to specific IPv4/IPv6 addresses or subnets (`0.0.0.0/0` for unrestricted).
- **In-Panel cURL Documentation**: Interactive endpoint browser with one-click copyable cURL commands. See [ALPM-API_DOCS.md](ALPM-API_DOCS.md) for full documentation.

### ⏳ VPS Expiration & Lifecycle Management
- **Configurable Durations**: Assign lifespan periods (7 Days, 14 Days, 30 Days, 60 Days, 90 Days, 1 Year, or Lifetime).
- **Automated Suspension**: Instances automatically enter a suspended state upon reaching their expiry timestamp, protecting compute and storage resources.
- **Renewal & Extension Modals**: Extend or renew VPS duration at any time with custom date selection.
- **Visual Status Badges**: Real-time remaining validity tags (`6d left`, `Expired`, `Lifetime`) displayed on dashboard cards and management pages.

### 🌐 Dedicated IP Pool System
- **Template IP Pools**: Attach static IPv4 and IPv6 IP pools to specific VM templates.
- **Automatic IP Provisioning**: Automatically leases and configures static IP addresses, gateways, netmasks, and DNS servers during instance creation.
- **IP Release on Deletion**: Safely recycles and reclaims IP addresses when instances are terminated or reassigned.

### 💻 Web-Based VPS Terminal Console
- **Interactive xterm.js Terminal**: Full-featured web console directly in the browser.
- **Proxmox VNC/Terminal Proxy**: Direct WebSocket communication with Proxmox VE terminal endpoints (xterm.js / noVNC / serial terminal).
- **Clipboard Paste Deduplication**: 300ms deduplication buffer preventing duplicate text paste on modern browsers and mobile keyboards.
- **Dynamic Fit & Resize**: Automatically syncs terminal dimensions (`cols`/`rows`) with the browser window on resize.

### 📈 Infrastructure Monitoring & Health Alerts
- **Live WebSocket Telemetry**: Stream physical CPU load, memory utilization, disk usage, and network traffic without continuous HTTP polling.
- **Historical Performance Graphs**: Visual RRD charts spanning Hour, Day, Week, Month, and Year periods.
- **Dynamic Node Health Monitoring**:
  - Real-time detection of Proxmox node timeouts (15s threshold) and connection dropouts.
  - Immediate alert banner with interactive **Retry Node** and **✕ Dismiss & Mute** actions.
  - 1500ms universal toast deduplication guard preventing spam notifications.
  - Auto-recovery detection when physical nodes restore connectivity.

### 📱 Multi-Device & Mobile Responsiveness
- **Universal Device Optimization**: Tested and optimized for smartphones, tablets, laptops, and ultra-wide desktop monitors.
- **Adaptive Drawer Navigation**: Sliding navigation drawer on mobile with swipe containment and auto-closing on route navigation.
- **Horizontal Scroll Protection**: Responsive data tables with `overscroll-behavior-x: contain` and zero layout breaking.
- **iOS Viewport Optimization**: Input font sizing configured to prevent unwanted zoom on Apple Safari.

### 🎨 Custom Branding & Customization
- **Dynamic Logo & Favicon**: Upload custom PNG/SVG logos or configure remote image URLs with instant live preview.
- **Clean Aesthetic**: Seamless sidebar logo integration with borderless brand presentation.
- **Custom Site Metadata**: Configure site title, meta description, Open Graph preview image, and SEO tags.
- **Background Media**: Custom login and dashboard background wallpapers or video loops with adjustable opacity and blur.

---

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| **Runtime** | Node.js (v20+) | High-performance asynchronous JavaScript engine |
| **Backend Framework** | Express.js 4 | REST API routing and middleware pipeline |
| **Database** | SQLite 3 via `better-sqlite3` | Fast, file-based embedded SQL engine in WAL mode |
| **Session Store** | `connect-sqlite3` | Persistent SQLite session management with `SameSite=Lax` |
| **Virtualization API** | Proxmox VE REST API v2 | Direct HTTPS management of QEMU VMs and LXC containers |
| **Real-Time Stream** | Socket.IO & `ws` | Real-time telemetry, node alerts, and terminal proxying |
| **Terminal Emulator** | `xterm.js` & `xterm-addon-fit` | Browser-based terminal with resizing and clipboard deduplication |
| **Security & Crypto** | Node.js `crypto` & `bcryptjs` | AES-256-GCM encryption, HMAC-SHA256 signatures, bcrypt hashing |
| **HTTP Security** | `helmet` & `express-rate-limit` | Content Security Policy, XSS protection, and brute-force mitigation |
| **Frontend** | Vanilla JavaScript, HTML5, CSS3 | Single-page application with zero compilation or build step |

---

## 📋 Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| **Operating System** | Ubuntu 22.04 / 24.04, Debian 12 / 13 | Ubuntu 24.04 LTS or Debian 12 |
| **Node.js** | Node.js 20.x LTS | Node.js 22.x LTS |
| **Memory (RAM)** | 512 MB | 1 GB or more |
| **Disk Space** | 1 GB free | 5 GB free (for logs and backups) |
| **Proxmox VE** | Proxmox VE 7.4+ | Proxmox VE 8.1+ |
| **Network** | Network route to Proxmox port `8006` | Low-latency private network / VPN |

---

## 📥 Installation & Setup

### Step 1 — Update Server & Install Prerequisites
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget openssl ca-certificates build-essential python3
```

### Step 2 — Install Node.js (v20 or v22 LTS)
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
node -v && npm -v
```

### Step 3 — Clone the Repository
```bash
git clone https://github.com/atyrolabs/alpm.git
cd alpm
```

### Step 4 — Install Dependencies
```bash
npm install
```

### Step 5 — Configure Environment Variables
Copy the template configuration:
```bash
cp .env.example .env
```

Generate two secure 64-character hexadecimal keys:
```bash
openssl rand -hex 32
openssl rand -hex 32
```

Edit your `.env` file:
```bash
nano .env
```

Set the values:
```env
PORT=3000
HOST=0.0.0.0
NODE_ENV=production

DB_PATH=./data/atyro.sqlite

# Paste the generated 64-character secrets below
SESSION_SECRET=YOUR_FIRST_64_CHAR_HEX_SECRET
ENCRYPTION_KEY=YOUR_SECOND_DIFFERENT_64_CHAR_HEX_SECRET

COOKIE_SECURE=false
TRUST_PROXY=0

# Discord Bot & 2FA Configuration (Optional but recommended)
DISCORD_BOT_TOKEN=YOUR_DISCORD_BOT_TOKEN
DISCORD_CLIENT_ID=YOUR_DISCORD_CLIENT_ID
DISCORD_CLIENT_SECRET=YOUR_DISCORD_CLIENT_SECRET
DISCORD_REDIRECT_URI=http://YOUR_SERVER_IP:3000/api/auth/discord/callback
DISCORD_2FA_ENABLED=true
```

> [!IMPORTANT]
> **Keep your `ENCRYPTION_KEY` backed up securely!** Stored Proxmox API credentials and API keys are encrypted using this key. Losing it will prevent previously saved credentials from being decrypted.

### Step 6 — Start the Application
Run directly:
```bash
npm start
```

Or run in background with PM2:
```bash
npm install -g pm2
pm2 start app.js --name alpm
pm2 save
pm2 startup
```

### Step 7 — Access the Dashboard
Open your web browser and navigate to:
```text
http://YOUR_SERVER_IP:3000
```
On your first visit, the panel will prompt you to complete initial administrator setup.

---

## ⚙️ Environment Variables Reference

| Variable | Required | Default | Description |
|---|:---:|---|---|
| `PORT` | No | `3000` | The TCP port ALPM listens on. |
| `HOST` | No | `0.0.0.0` | Network interface to bind (`0.0.0.0` for all interfaces, `127.0.0.1` for localhost). |
| `NODE_ENV` | No | `production` | Set to `production` or `development`. |
| `DB_PATH` | No | `./data/atyro.sqlite` | File path to the SQLite database. |
| `SESSION_SECRET` | **Yes** | — | Cryptographic secret used to sign session cookies and OAuth state tokens (min. 32 chars). |
| `ENCRYPTION_KEY` | **Yes** | — | AES-256-GCM master key used to encrypt Proxmox token secrets and API keys at rest. |
| `COOKIE_SECURE` | No | `false` | Set to `true` when serving over HTTPS/TLS so session cookies require HTTPS. |
| `TRUST_PROXY` | No | `0` | Set to `1` (or your proxy IP) when behind Nginx, Caddy, or Cloudflare. |
| `DISCORD_BOT_TOKEN` | No | — | Discord Bot Token from Discord Developer Portal for sending 2FA OTP DMs. |
| `DISCORD_CLIENT_ID` | No | — | OAuth2 Client ID from Discord Developer Portal. |
| `DISCORD_CLIENT_SECRET` | No | — | OAuth2 Client Secret from Discord Developer Portal. |
| `DISCORD_REDIRECT_URI` | No | `http://localhost:3000/api/auth/discord/callback` | OAuth2 redirect URL (must match the Redirects in Discord Developer Portal). |
| `DISCORD_2FA_ENABLED` | No | `true` | Enables or disables Discord Two-Factor Authentication features. |

---

## 🤖 Discord Bot & OAuth2 Setup Guide

To enable Discord 2FA and OAuth2 linking:

1. Visit the [Discord Developer Portal](https://discord.com/developers/applications) and click **New Application**.
2. **Bot Setup**:
   - Go to **Bot** in the left sidebar.
   - Click **Reset Token** to copy your `DISCORD_BOT_TOKEN`.
   - Under **Privileged Gateway Intents**, enable **Server Members Intent** and **Message Content Intent**.
   - Invite the bot to your Discord community server using the URL Generator (**OAuth2** &rarr; **URL Generator** &rarr; Select `bot` with `Send Messages` and `Embed Links` permissions).
3. **OAuth2 Setup**:
   - Go to **OAuth2** &rarr; **General**.
   - Copy your **Client ID** (`DISCORD_CLIENT_ID`) and **Client Secret** (`DISCORD_CLIENT_SECRET`).
   - Under **Redirects**, add your callback URL:
     ```text
     http://YOUR_SERVER_IP:3000/api/auth/discord/callback
     ```
     *(If using a custom domain with SSL: `https://panel.yourdomain.com/api/auth/discord/callback`)*
4. Paste the credentials into your `.env` file and restart the panel (`pm2 restart alpm`).
5. Verify connectivity under **Admin** &rarr; **Settings** or test with `GET /api/admin/security/discord-bot-status`.

---

## 📖 REST API Documentation

ALPM provides a comprehensive RESTful API for automated provisioning, server monitoring, and integration with third-party billing platforms (WHMCS, Blesta, payment gateways, custom bots).

### Authentication
Include your secret API key with every request in the `Authorization` header:
```http
Authorization: Bearer atyro_live_a073...ac22
```

### Example Requests

#### Get Infrastructure Overview
```bash
curl -X GET "http://localhost:3000/api/overview" \
  -H "Authorization: Bearer atyro_live_..."
```

#### List Virtual Servers
```bash
curl -X GET "http://localhost:3000/api/servers" \
  -H "Authorization: Bearer atyro_live_..."
```

#### Perform VPS Power Action
```bash
curl -X POST "http://localhost:3000/api/servers/12/action" \
  -H "Authorization: Bearer atyro_live_..." \
  -H "Content-Type: application/json" \
  -d '{"action": "start"}'
```

For the complete API documentation with all request/response schemas, scopes, and error codes, refer to:
👉 **[ALPM-API_DOCS.md](ALPM-API_DOCS.md)**

---

## 📁 Project Directory Layout

```text
alpm/
├── app.js                    # Core backend server (Express, Proxmox client, Discord 2FA/OAuth2, WebSockets)
├── index.html                # Modern single-page frontend (HTML5, responsive CSS, client controllers)
├── package.json              # Project dependencies and npm scripts
├── package-lock.json         # Dependency lockfile
├── .env                      # Active server configuration (ignored in git)
├── .env.example              # Template environment configuration
├── ALPM-API_DOCS.md          # Comprehensive REST API reference guide
├── README.md                 # Project documentation
│
└── data/                     # Automatic persistent application storage
    ├── atyro.sqlite          # Primary SQLite database (users, nodes, servers, api_keys, identities, etc.)
    ├── sessions.sqlite       # Session store
    └── uploads/              # Custom brand logo files and user avatars
```

---

## 🔒 Security Best Practices

1. **Use Reverse Proxy with HTTPS**: Always deploy behind Nginx or Caddy with automated Let's Encrypt certificates (`COOKIE_SECURE=true`).
2. **Proxmox API Token Scoping**: In Proxmox VE Datacenter Permissions, assign API tokens only the required roles (e.g. `PVEVMAdmin`, `PVEAuditor`, `Datastore.AllocateSpace`) rather than cluster-wide `Administrator`.
3. **Keep Encryption Key Safe**: Never commit `.env` or encryption secrets to version control.
4. **Regular Database Backups**: Back up `data/atyro.sqlite` regularly:
   ```bash
   sqlite3 data/atyro.sqlite ".backup 'backup_$(date +%F).sqlite'"
   ```

---

## 🐛 Troubleshooting & FAQ

<details>
<summary><b>Q: Proxmox node shows "CONNECTION TIMEOUT (15s)"</b></summary>
<br>
Verify that the ALPM server can reach the Proxmox node's IP on port <code>8006</code>:

```bash
curl -k https://PROXMOX_NODE_IP:8006/api2/json
```
If this fails, check your Proxmox firewall (`pve-firewall`), network routes, or TLS certificate verification settings.
</details>

<details>
<summary><b>Q: Discord 2FA says "Cannot send Discord DM to this account" (Error 50007)</b></summary>
<br>
Discord requires that the user and the bot share at least one mutual server and that the user's Discord privacy settings allow Direct Messages from server members.
</details>

<details>
<summary><b>Q: Discord link returns "invalid_oauth_state"</b></summary>
<br>
Verify that your <code>DISCORD_REDIRECT_URI</code> in <code>.env</code> matches the exact URL configured under <b>Redirects</b> in the Discord Developer Portal, and confirm that your session cookie policy is set to <code>SameSite: Lax</code> (standard in ALPM v2.1+).
</details>

---

## 📜 License

ALPM is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>Developed & Maintained with ❤️ by Atyro Labs</b><br>
  <sub>Next-Generation Cloud & Virtualization Management Infrastructure</sub><br><br>
  <a href="https://github.com/atyrolabs/alpm">⭐ Star ALPM on GitHub</a>
</p>
