# ALPM — Proxmox VPS Management Panel

<p align="center">
  <img src="https://img.shields.io/badge/ALPM-v1.0.0-orange?style=for-the-badge" alt="ALPM Version">
  <img src="https://img.shields.io/badge/Developer-Atyro%20Labs-white?style=for-the-badge" alt="Atyro Labs">
  <img src="https://img.shields.io/badge/Platform-Proxmox%20VE-orange?style=for-the-badge" alt="Proxmox VE">
  <img src="https://img.shields.io/badge/Node.js-20%2B-green?style=for-the-badge" alt="Node.js">
</p>

<p align="center">
  <b>A powerful, modern and feature-rich Proxmox VE management platform designed to simplify VPS administration, virtualization management and cloud infrastructure operations.</b>
</p>

<p align="center">
  <a href="https://github.com/atyrolabs/alpm">GitHub Repository</a> •
  <a href="https://github.com/atyrolabs">Atyro Labs</a> •
  <a href="https://github.com/atyrolabs/alpm/issues">Report Issues</a>
</p>

---

## 🚀 Introduction

**ALPM (Atyro Labs Proxmox Management)** is a next-generation Proxmox VPS management panel developed by **Atyro Labs**.

Built with Node.js, Express.js, SQLite and the official Proxmox VE API, ALPM provides a centralized platform for managing virtual machines, LXC containers, Proxmox nodes, users and VPS resources through a modern web interface.

ALPM is designed for hosting providers, infrastructure administrators and virtualization enthusiasts who need a convenient way to manage their Proxmox infrastructure without constantly working through the Proxmox command line.

Inspired by modern VPS management platforms, ALPM brings together essential virtualization management capabilities, administration tools and real-time monitoring in one place.

### ✨ Why ALPM?

- Centralized multi-node Proxmox management.
- Complete VPS management experience.
- Modern and responsive dashboard.
- Real-time VPS resource monitoring.
- Integrated web-based terminal console.
- Advanced administrator controls.
- Secure user authentication and access management.
- Automated communication with Proxmox VE API.

## ⚡ Features

### 🖥️ VPS Management

Manage your virtual machines and containers directly from the ALPM dashboard.

- Create and manage QEMU virtual machines.
- Create and manage LXC containers.
- Start, stop and restart VPS instances.
- Graceful shutdown and reset operations.
- View VPS status and configuration.
- Monitor CPU, RAM, storage and uptime.
- Modify VPS configuration and specifications.
- Expand virtual disk storage.
- Reinstall supported VPS environments.
- Clone existing virtual machines and containers.
- Assign VPS instances to panel users.

### 📊 Real-Time Monitoring

Monitor your infrastructure with live resource information.

- Real-time CPU utilization.
- RAM usage and available memory.
- VPS uptime and current status.
- Disk utilization and storage information.
- Historical resource graphs.
- Hourly, daily, weekly, monthly and yearly monitoring.
- Automatic resource synchronization.

### 💻 Web-Based VPS Console

Access your VPS terminal directly through your browser.

- Integrated xterm.js terminal.
- Proxmox terminal proxy integration.
- WebSocket-based communication.
- Interactive terminal input and output.
- Terminal resizing support.
- Connection status monitoring.
- Authenticated console sessions.

### 💾 Backup Management

Manage VPS backups through Proxmox VE.

- Create VPS backups.
- Browse available backups.
- Select backup storage.
- Support for snapshot, suspend and stop backup modes.
- ZSTD and GZIP compression options.
- Restore existing backups.
- Delete unwanted backup archives.

### 📸 Snapshot Management

Protect your VPS configurations with snapshots.

- Create snapshots.
- View existing snapshots.
- Roll back to previous snapshots.
- Manage snapshot operations through the dashboard.

### 🌐 Multi-Node Management

Connect and manage multiple Proxmox VE nodes from a single panel.

- Register multiple Proxmox nodes.
- Configure node hostname and API port.
- Connect using Proxmox API tokens.
- Test node connectivity.
- Enable or disable nodes.
- Edit node configurations.
- Monitor node hardware information.
- View node CPU and memory information.
- Monitor network and storage information.
- Discover virtual machines and containers.
- View node resource information.

### 👑 Advanced Administration

ALPM provides dedicated administrator functionality for managing the entire panel.

**User Management**
- Create user accounts.
- Edit usernames and email addresses.
- Change user passwords.
- Manage administrator and standard-user roles.
- Activate or deactivate accounts.
- Delete user accounts.
- Assign VPS instances to users.

**VPS Administration**
- Create QEMU virtual machines.
- Create LXC containers.
- Configure VPS resources.
- Select Proxmox nodes and storage.
- Provision from supported templates.
- Configure ISO-based provisioning.
- Assign VPS instances to users.
- Clone existing VPS instances.
- Edit VPS specifications.
- Manage VPS assignments.

**Node Administration**
- Add Proxmox nodes.
- Edit node information.
- Test API connections.
- Enable or disable nodes.
- View node information.
- Remove nodes when no VPS assignments remain.

### 🎨 Panel Customization

Customize the panel's appearance and branding.

- Change website name.
- Update website description.
- Configure SEO metadata.
- Customize website icon.
- Configure favicon.
- Set Open Graph preview images.
- Configure background images or videos.
- Adjust background opacity and blur.
- Enable or disable public registration.

### 🔐 Security & Activity Logs

Security and access control are important parts of ALPM.

- Session-based authentication.
- Password hashing with bcrypt.
- Encrypted Proxmox API token secrets.
- AES-256-GCM encryption for stored node credentials.
- HTTP security headers using Helmet.
- Login rate limiting.
- API rate limiting.
- CSRF protection.
- Authenticated API endpoints.
- Administrator-only management endpoints.
- User-specific VPS access restrictions.
- Audit logs for administrative activities.
- SQLite-backed session storage.

---

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Node.js | JavaScript runtime |
| Express.js | Backend framework |
| SQLite | Database |
| better-sqlite3 | Database integration |
| Proxmox VE API | Virtualization management |
| Socket.IO | Real-time communication |
| WebSockets | Live console communication |
| xterm.js | Browser terminal |
| Axios | HTTP requests |
| bcryptjs | Password hashing |
| Helmet | HTTP security headers |
| express-session | Session management |
| dotenv | Environment configuration |
| HTML5 | Frontend structure |
| CSS3 | Frontend styling |
| JavaScript | Frontend interactions |

---

## 📋 Requirements

Before installing ALPM, make sure your server meets the following requirements:

| Requirement | Recommended |
|---|---|
| Operating System | Ubuntu 22.04 / 24.04 or Debian 12 / 13 |
| Node.js | 20 or newer |
| npm | Compatible with installed Node.js |
| RAM | 1 GB minimum recommended |
| Storage | 2 GB available |
| Database | SQLite |
| Virtualization Platform | Proxmox VE |
| Network | Access to Proxmox API port 8006 |

**Important:** The ALPM application server must be able to communicate with your Proxmox VE nodes over the network.

---

## 📥 Installation

### Step 1 — Update Your Server

```bash
apt update && apt upgrade -y
```

### Step 2 — Install Required Packages

```bash
apt install -y git curl wget openssl ca-certificates build-essential python3
```

### Step 3 — Install Node.js

Install Node.js 20 or newer using your preferred official Node.js installation method.

Verify the installation:

```bash
node -v && npm -v
```

### Step 4 — Clone ALPM

```bash
git clone https://github.com/atyrolabs/alpm.git
```

Navigate into the project directory:

```bash
cd alpm
```

### Step 5 — Install Dependencies

```bash
npm install
```

### Step 6 — Configure Environment Variables

Create your environment configuration:

```bash
cp test.env .env
```

Generate two separate secure secrets:

```bash
openssl rand -hex 32
```

Run the command again to generate the second secret.

Edit your environment file:

```bash
nano .env
```

Configure the following values:

```env
PORT=3000
HOST=0.0.0.0
NODE_ENV=production

DB_PATH=./data/atyro.sqlite

SESSION_SECRET=YOUR_64_CHARACTER_RANDOM_SECRET
ENCRYPTION_KEY=YOUR_DIFFERENT_64_CHARACTER_RANDOM_SECRET

COOKIE_SECURE=false
TRUST_PROXY=0
```

**Environment configuration:**

| Variable | Description |
|---|---|
| PORT | Application listening port |
| HOST | Application bind address |
| NODE_ENV | Application environment |
| DB_PATH | SQLite database location |
| SESSION_SECRET | Session encryption secret |
| ENCRYPTION_KEY | Proxmox credential encryption key |
| COOKIE_SECURE | Secure cookie setting |
| TRUST_PROXY | Trusted reverse proxy configuration |

For production deployments behind HTTPS, configure `COOKIE_SECURE=true` and set `TRUST_PROXY` to match your reverse proxy topology.

**Important:** Never share your `.env` file, encryption keys or Proxmox API credentials. Keep secure backups of your encryption key because existing encrypted node credentials depend on it.

### Step 7 — Start ALPM

```bash
npm start
```

The application will start on the configured host and port.

### Step 8 — Access Your Dashboard

Open your browser:

```text
http://YOUR_SERVER_IP:3000
```

On the first startup, ALPM will guide you through creating your initial administrator account.

After administrator setup, log in to access the dashboard.

---

## 🔗 Proxmox VE Integration

ALPM communicates directly with Proxmox VE through its API.

### Connecting a Proxmox Node

1. Log in to ALPM as an administrator.
2. Open the node management section.
3. Add a new Proxmox node.
4. Enter the Proxmox node information.
5. Provide your Proxmox API token ID.
6. Enter the corresponding API token secret.
7. Configure TLS certificate verification.
8. Test the connection.
9. Save the node configuration.

### Proxmox API Information

| Configuration | Default |
|---|---|
| Proxmox API Protocol | HTTPS |
| Proxmox API Port | 8006 |
| API Endpoint | `/api2/json` |
| Authentication | Proxmox API Token |
| Default TLS Verification | Enabled |

Example API endpoint:

```text
https://YOUR_PROXMOX_IP:8006/api2/json
```

### API Permissions

The API token must have the permissions required for the operations you intend to perform.

ALPM uses Proxmox permissions for VM management, node monitoring, storage operations and provisioning.

Some operations require additional privileges, including `Datastore.AllocateSpace`.

Configure appropriate ACL permissions in:

```text
Proxmox VE → Datacenter → Permissions
```

Use the minimum permissions necessary for your deployment and avoid unnecessarily granting broad administrative access.

---

## 📁 Project Structure

```text
alpm/
│
├── app.js
│   └── Main application server
│
├── index.html
│   └── Frontend dashboard and interface
│
├── package.json
│   └── Project metadata and dependencies
│
├── package-lock.json
│   └── Dependency lockfile (generated by npm)
│
├── test.env
│   └── Example environment configuration
│
├── LICENSE
│   └── Project license
│
├── .env
│   └── Private environment configuration
│
└── data/
    ├── atyro.sqlite
    ├── sessions.sqlite
    └── uploads/
        └── avatars/
```

The `data` directory and database files are generated automatically when the application initializes.

---

## ⚙️ Running in Production

For a simple production deployment, you can use PM2 to keep ALPM running.

Install PM2:

```bash
npm install -g pm2
```

Start ALPM:

```bash
pm2 start app.js --name alpm
```

Save the process list:

```bash
pm2 save
```

Configure automatic startup:

```bash
pm2 startup
```

Run the additional command printed by PM2 to enable startup on boot.

### Useful PM2 Commands

| Command | Description |
|---|---|
| `pm2 status` | View application status |
| `pm2 logs alpm` | View application logs |
| `pm2 restart alpm` | Restart ALPM |
| `pm2 stop alpm` | Stop ALPM |
| `pm2 reload alpm` | Reload application |
| `pm2 delete alpm` | Remove PM2 process |

For public deployments, use HTTPS through a properly configured reverse proxy and restrict access to the application and Proxmox management interfaces.

---

## 🔒 Security Recommendations

Before exposing ALPM to the public internet:

- Use HTTPS with a valid TLS certificate.
- Generate unique, strong environment secrets.
- Keep `.env` private.
- Never expose Proxmox API token secrets.
- Keep TLS certificate verification enabled.
- Use appropriately restricted Proxmox API permissions.
- Use strong administrator passwords.
- Disable public registration if it is not required.
- Regularly update Node.js dependencies.
- Back up your SQLite database.
- Protect your database, session files and uploads directory.
- Restrict network access to Proxmox management ports.
- Never commit private credentials to GitHub.

**Database and encryption backups:** Store backups of the SQLite database and the matching encryption key securely. Losing the encryption key can prevent previously stored Proxmox credentials from being decrypted.

---

## 🐛 Troubleshooting

### Application Does Not Start

Check Node.js and npm:

```bash
node -v && npm -v
```

Reinstall dependencies:

```bash
npm install
```

### Port Already in Use

Change the `PORT` variable in your `.env` file to an available port.

### Proxmox Connection Failed

Check:

- Proxmox server IP or hostname.
- API port 8006.
- Network connectivity.
- API token ID and secret.
- TLS certificate validity.
- Proxmox API token permissions.

### Database Error

Check that the application has permission to write to the configured database directory.

### VPS Operations Fail

Check the Proxmox API task logs and confirm that the configured API token has the necessary permissions for the requested operation.

---

## 🗺️ Development & Contributions

ALPM is developed by Atyro Labs.

Contributions, suggestions, bug reports and feature requests are welcome.

If you discover a problem or have an idea to improve ALPM:

1. Check the existing GitHub issues.
2. Open a new issue describing the problem.
3. Include relevant error messages and reproduction steps.
4. Submit improvements through a pull request.

Please avoid including passwords, API tokens, private IP information or other sensitive infrastructure details in public issues.

### GitHub Repository

https://github.com/atyrolabs/alpm

### Report a Bug

https://github.com/atyrolabs/alpm/issues

---

## 📜 License

ALPM is distributed under the license included in the repository.

See the [LICENSE](LICENSE) file for the applicable terms and conditions.

---

## ❤️ Credits & Development

**Developed and maintained by Atyro Labs**

ALPM is built to make Proxmox VPS management simpler, more accessible and more efficient.

We aim to provide hosting providers and infrastructure administrators with a modern, centralized virtualization management experience.

<p align="center">
  <b>ALPM v1.0.0</b>
  <br>
  <b>Powered by Atyro Labs</b>
  <br><br>
  <a href="https://github.com/atyrolabs/alpm">⭐ Star the Repository</a>
  <br>
  <sub>Build. Manage. Scale.</sub>
</p>
