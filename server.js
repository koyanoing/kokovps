'use strict';
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { execFile, spawn } = require('child_process');
const { Pool } = require('pg');
const { WebSocketServer } = require('ws');

/* ---------- config ---------- */
const num = (v, d) => { const n = parseFloat(v); return Number.isFinite(n) && n > 0 ? n : d; };
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET is not set. Logins and saved SSH passwords will break on every redeploy. Set it in Variables.');
}
const KEY = crypto.createHash('sha256').update(SECRET).digest();

const HAS_VOLUME = !!process.env.RAILWAY_VOLUME_MOUNT_PATH;
const VOL = process.env.RAILWAY_VOLUME_MOUNT_PATH || '/data';
const HOME_BASE = VOL + '/home';
const SSH_HOST = process.env.SSH_HOST || '';
const SSH_PUBLIC_PORT = parseInt(process.env.SSH_PUBLIC_PORT || '', 10) || null;
const TOTAL = { cpu: num(process.env.TOTAL_CPU, 8), ram: num(process.env.TOTAL_RAM_GB, 8), disk: num(process.env.TOTAL_DISK_GB, 20) };
const OVERCOMMIT = Math.max(1, num(process.env.OVERCOMMIT, 1));
const UID_BASE = 10000, GID = 10000;
const CAN_MANAGE = typeof process.getuid === 'function' && process.getuid() === 0 && fs.existsSync('/usr/sbin/useradd');

const PLANS = {
  nano: { name: 'Nano', cpu: 0.5, ram: 0.5, disk: 2, nproc: 100, price: 2 },
  small: { name: 'Small', cpu: 1, ram: 1, disk: 5, nproc: 200, price: 4 },
  medium: { name: 'Medium', cpu: 2, ram: 2, disk: 10, nproc: 400, price: 8 },
  large: { name: 'Large', cpu: 4, ram: 4, disk: 20, nproc: 800, price: 16 }
};
const NAME_RE = /^[a-z][a-z0-9-]{1,23}$/;
const EMAIL_RE = /^\S+@\S+\.\S+$/;
const RESERVED = new Set(['root', 'admin', 'administrator', 'node', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 'news',
  'uucp', 'proxy', 'www-data', 'backup', 'list', 'irc', 'nobody', 'sshd', 'postgres', 'ubuntu', 'debian', 'dockyard', 'user', 'test']);

class HttpError extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}

/* ---------- database ---------- */
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function initDb() {
  for (let n = 0; n < 15; n++) {
    try { await pool.query('SELECT 1'); break; }
    catch (e) { if (n === 14) throw e; console.log('Waiting for database...'); await new Promise(r => setTimeout(r, 2000)); }
  }
  await pool.query(`CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
    pw TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer', created_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS servers(
    id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, owner_id INT NOT NULL REFERENCES users(id),
    plan TEXT NOT NULL, uid INT NOT NULL DEFAULT 0, pass TEXT NOT NULL, suspended BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS events(
    id SERIAL PRIMARY KEY, at TIMESTAMPTZ DEFAULT now(), msg TEXT NOT NULL)`);

  const { rows } = await pool.query("SELECT 1 FROM users WHERE role='admin' LIMIT 1");
  if (!rows.length) {
    const email = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
    const pw = process.env.ADMIN_PASSWORD || '';
    if (EMAIL_RE.test(email) && pw.length >= 8) {
      await pool.query('INSERT INTO users(name,email,pw,role) VALUES($1,$2,$3,$4)', ['Admin', email, hashPw(pw), 'admin']);
      console.log('Admin account created for ' + email);
    } else {
      console.warn('No admin exists. Set ADMIN_EMAIL and ADMIN_PASSWORD (8+ characters) and redeploy.');
    }
  }
}
const ev = msg => pool.query('INSERT INTO events(msg) VALUES($1)', [msg]).catch(() => {});

/* ---------- crypto helpers ---------- */
function hashPw(p) {
  const s = crypto.randomBytes(16);
  return s.toString('hex') + ':' + crypto.scryptSync(p, s, 64).toString('hex');
}
function checkPw(p, stored) {
  const [s, h] = String(stored).split(':');
  if (!s || !h) return false;
  const x = crypto.scryptSync(p, Buffer.from(s, 'hex'), 64);
  const y = Buffer.from(h, 'hex');
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function enc(t) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const e = Buffer.concat([c.update(t, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), e].map(b => b.toString('base64')).join('.');
}
function dec(t) {
  try {
    const [iv, tag, e] = String(t).split('.').map(x => Buffer.from(x, 'base64'));
    const d = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(e), d.final()]).toString('utf8');
  } catch { return ''; }
}
function genPass() {
  const a = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
  return Array.from({ length: 16 }, () => a[crypto.randomInt(a.length)]).join('');
}
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('base64url');
function makeCookie(uid) {
  const p = Buffer.from(JSON.stringify({ u: uid, e: Date.now() + 7 * 864e5 })).toString('base64url');
  return p + '.' + sign(p);
}
function readCookie(req) {
  const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const [p, s] = m[1].split('.');
  if (!p || !s) return null;
  const a = Buffer.from(sign(p)), b = Buffer.from(s);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const o = JSON.parse(Buffer.from(p, 'base64url').toString());
    return o.e > Date.now() ? o.u : null;
  } catch { return null; }
}

/* ---------- system helpers (run as root inside the Docker image) ---------- */
function run(cmd, args, input) {
  return new Promise((resolve, reject) => {
    const c = execFile(cmd, args, { timeout: 30000 }, (e, so, se) =>
      e ? reject(new Error((String(se || e.message || '')).trim() || 'command failed')) : resolve(String(so)));
    if (c.stdin) c.stdin.end(input || '');
  });
}
let chain = Promise.resolve();
const serial = fn => { const r = chain.then(() => fn()); chain = r.catch(() => {}); return r; };

function needSystem() {
  if (!CAN_MANAGE) throw new HttpError(500, 'This panel is not running as root inside the Docker image, so it cannot manage Linux accounts. Deploy with the included Dockerfile.');
}
async function userExists(name) { try { await run('getent', ['passwd', name]); return true; } catch { return false; } }

async function ensureUser(a) {
  const home = HOME_BASE + '/' + a.name;
  if (!(await userExists(a.name))) {
    await run('useradd', ['-d', home, '-m', '-u', String(a.uid), '-g', 'dockyard', '-s', '/bin/bash', a.name]);
  }
  await run('chpasswd', [], a.name + ':' + dec(a.pass) + '\n');
  await run('chown', [a.uid + ':' + GID, home]);
  await run('chmod', ['700', home]);
  await setLock(a.name, a.suspended);
}
async function setLock(name, lock) {
  if (lock) await run('usermod', ['-L', '-e', '1', name]);
  else await run('usermod', ['-U', '-e', '', name]);
}
async function syncLimits() {
  const { rows } = await pool.query('SELECT name, plan FROM servers ORDER BY id');
  const lines = ['# generated by Dockyard'];
  for (const a of rows) {
    const p = PLANS[a.plan]; if (!p) continue;
    lines.push(`${a.name} hard nproc ${p.nproc}`, `${a.name} hard nofile 4096`,
      `${a.name} hard data ${Math.round(p.ram * 1024 * 1024 * 2)}`, `${a.name} hard maxlogins 4`);
  }
  await fs.promises.mkdir('/etc/security/limits.d', { recursive: true });
  await fs.promises.writeFile('/etc/security/limits.d/dockyard.conf', lines.join('\n') + '\n');
}
async function bootSync() {
  if (!CAN_MANAGE) { console.warn('Not running as root: account management is disabled.'); return; }
  await fs.promises.mkdir(HOME_BASE, { recursive: true });
  try { await run('getent', ['group', 'dockyard']); } catch { await run('groupadd', ['-g', String(GID), 'dockyard']); }
  const { rows } = await pool.query('SELECT * FROM servers ORDER BY id');
  for (const a of rows) {
    try { await ensureUser(a); } catch (e) { console.error('Could not restore account ' + a.name + ': ' + e.message); }
  }
  await syncLimits();
  console.log('Restored ' + rows.length + ' account(s).');
}

/* ---------- live usage + limit enforcement ---------- */
let acctByUid = new Map();
async function refreshAccounts() {
  const { rows } = await pool.query('SELECT id,name,uid,plan,suspended FROM servers');
  acctByUid = new Map(rows.map(r => [r.uid, r]));
}
function scan() {
  const list = [];
  let pids = [];
  try { pids = fs.readdirSync('/proc'); } catch { return list; }
  for (const pid of pids) {
    if (!/^\d+$/.test(pid)) continue;
    try {
      const st = fs.readFileSync('/proc/' + pid + '/stat', 'utf8');
      const f = st.slice(st.lastIndexOf(')') + 2).split(' ');
      const ticks = (+f[11]) + (+f[12]);
      const s = fs.readFileSync('/proc/' + pid + '/status', 'utf8');
      const uid = +((/^Uid:\s+(\d+)/m.exec(s) || [])[1]);
      const rss = +((/^VmRSS:\s+(\d+)/m.exec(s) || [])[1] || 0);
      const comm = (/^Name:\s+(.+)$/m.exec(s) || [])[1] || '?';
      list.push({ pid: +pid, uid, ticks, rss, comm });
    } catch { /* process ended */ }
  }
  return list;
}
let prevTicks = new Map(), prevT = 0;
let usage = new Map(), procsByUid = new Map();
const diskKB = new Map(), overDisk = new Set();
const cpuStrikes = new Map(), killedAt = new Map();

function sample() {
  const now = Date.now(), list = scan(), dt = prevT ? (now - prevT) / 1000 : 0;
  const u = new Map(), by = new Map();
  for (const p of list) {
    const d = prevTicks.has(p.pid) ? p.ticks - prevTicks.get(p.pid) : 0;
    p.cpu = dt > 0 ? Math.max(0, d) / 100 / dt : 0;
    if (p.uid < UID_BASE) continue;
    const x = u.get(p.uid) || { cpu: 0, rss: 0 };
    x.cpu += p.cpu; x.rss += p.rss; u.set(p.uid, x);
    if (!by.has(p.uid)) by.set(p.uid, []);
    by.get(p.uid).push(p);
  }
  prevTicks = new Map(list.map(p => [p.pid, p.ticks])); prevT = now; usage = u; procsByUid = by;
  if (CAN_MANAGE) {
    enforce();
    if (!list.some(p => p.comm === 'sshd' && p.uid === 0)) {
      execFile('/usr/sbin/sshd', ['-f', '/etc/ssh/sshd_config.dockyard'], () => {});
    }
  }
}
function killUid(uid) {
  for (const p of scan()) if (p.uid === uid) { try { process.kill(p.pid, 'SIGKILL'); } catch { /* gone */ } }
}
function enforce() {
  for (const [uid, x] of usage) {
    const a = acctByUid.get(uid); if (!a) continue;
    const p = PLANS[a.plan]; if (!p) continue;
    if (x.rss / 1024 > p.ram * 1024) {
      if (Date.now() - (killedAt.get(uid) || 0) > 60000) {
        killedAt.set(uid, Date.now());
        ev(a.name + ' used more memory than its plan allows, so its processes were stopped');
      }
      killUid(uid);
      continue;
    }
    if (x.cpu > p.cpu * 1.1) cpuStrikes.set(uid, (cpuStrikes.get(uid) || 0) + 1); else cpuStrikes.set(uid, 0);
    if ((cpuStrikes.get(uid) || 0) >= 3) {
      for (const pr of procsByUid.get(uid) || []) { try { os.setPriority(pr.pid, 15); } catch { /* gone */ } }
    }
  }
}
async function diskScan() {
  if (!CAN_MANAGE) return;
  for (const a of [...acctByUid.values()]) {
    try {
      const kb = parseInt(await run('du', ['-sk', '--', HOME_BASE + '/' + a.name]), 10) || 0;
      diskKB.set(a.uid, kb);
      const quota = PLANS[a.plan].disk * 1048576;
      if (kb > quota && !overDisk.has(a.uid)) { overDisk.add(a.uid); ev(a.name + ' is over its disk quota'); }
      if (kb <= quota) overDisk.delete(a.uid);
      if (kb > quota * 1.2 && !a.suspended) {
        await serial(async () => { await setLock(a.name, true); killUid(a.uid); await pool.query('UPDATE servers SET suspended=true WHERE id=$1', [a.id]); });
        await refreshAccounts();
        ev(a.name + ' was suspended because it is far over its disk quota');
      }
    } catch { /* account removed or du failed */ }
  }
}

/* ---------- api shape ---------- */
const SELECT_S = 'SELECT s.*, u.name AS owner_name FROM servers s JOIN users u ON u.id=s.owner_id';
function toApi(a) {
  const u = usage.get(a.uid) || { cpu: 0, rss: 0 };
  return {
    id: a.id, code: 'SV-' + (1000 + a.id), name: a.name, ownerId: a.owner_id, ownerName: a.owner_name, plan: a.plan,
    status: a.suspended ? 'suspended' : 'active', host: SSH_HOST || null, port: SSH_PUBLIC_PORT, user: a.name,
    password: dec(a.pass),
    usage: { cpu: +u.cpu.toFixed(3), ramMB: Math.round(u.rss / 1024), diskMB: Math.round((diskKB.get(a.uid) || 0) / 1024) },
    overDisk: overDisk.has(a.uid), createdAt: a.created_at
  };
}

/* ---------- app ---------- */
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
const h = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.get('/healthz', (req, res) => res.send('ok'));
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && req.get('x-dockyard') !== '1') return res.status(403).json({ error: 'Blocked request.' });
  next();
});

const attempts = new Map();
function limited(ip) {
  const now = Date.now();
  const a = attempts.get(ip) || { n: 0, t: now };
  if (now - a.t > 60000) { a.n = 0; a.t = now; }
  a.n++; attempts.set(ip, a);
  return a.n > 8;
}
app.post('/api/login', h(async (req, res) => {
  if (limited(req.ip)) throw new HttpError(429, 'Too many attempts. Wait a minute and try again.');
  const { email, password } = req.body || {};
  const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [String(email || '').trim().toLowerCase()]);
  if (!rows[0] || !checkPw(String(password || ''), rows[0].pw)) throw new HttpError(401, 'Email or password is incorrect.');
  res.setHeader('Set-Cookie', `sid=${makeCookie(rows[0].id)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${req.secure ? '; Secure' : ''}`);
  res.json({ ok: true });
}));
app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});

const auth = h(async (req, res, next) => {
  const uid = readCookie(req);
  if (!uid) throw new HttpError(401, 'Sign in to continue.');
  const { rows } = await pool.query('SELECT id,name,email,role FROM users WHERE id=$1', [uid]);
  if (!rows[0]) throw new HttpError(401, 'Sign in to continue.');
  req.user = rows[0];
  next();
});
const adminOnly = (req, res, next) =>
  req.user.role === 'admin' ? next() : next(new HttpError(403, 'Only admins can do this.'));

app.get('/api/me', auth, (req, res) => res.json({
  user: req.user, plans: PLANS, totals: TOTAL,
  ssh: { host: SSH_HOST || null, port: SSH_PUBLIC_PORT },
  canManage: CAN_MANAGE, hasVolume: HAS_VOLUME
}));

/* customers */
app.get('/api/customers', auth, adminOnly, h(async (req, res) => {
  const { rows } = await pool.query("SELECT id,name,email,created_at FROM users WHERE role='customer' ORDER BY id");
  res.json({ customers: rows });
}));
app.post('/api/customers', auth, adminOnly, h(async (req, res) => {
  const name = String((req.body || {}).name || '').trim();
  const email = String((req.body || {}).email || '').trim().toLowerCase();
  const password = String((req.body || {}).password || '');
  if (!name || name.length > 60) throw new HttpError(400, 'Enter the customer\u2019s name.');
  if (!EMAIL_RE.test(email)) throw new HttpError(400, 'Enter a valid email address.');
  if (password.length < 8) throw new HttpError(400, 'Use a password with at least 8 characters.');
  try {
    await pool.query('INSERT INTO users(name,email,pw,role) VALUES($1,$2,$3,$4)', [name, email, hashPw(password), 'customer']);
  } catch (e) {
    if (e.code === '23505') throw new HttpError(409, 'A user with that email already exists.');
    throw e;
  }
  ev(name + ' was added as a customer');
  res.json({ ok: true });
}));
app.delete('/api/customers/:id', auth, adminOnly, h(async (req, res) => {
  const id = +req.params.id;
  const { rows } = await pool.query("SELECT name FROM users WHERE id=$1 AND role='customer'", [id]);
  if (!rows[0]) throw new HttpError(404, 'Customer not found.');
  const c = await pool.query('SELECT count(*)::int AS n FROM servers WHERE owner_id=$1', [id]);
  if (c.rows[0].n) throw new HttpError(409, 'This customer still has servers. Delete them first.');
  await pool.query('DELETE FROM users WHERE id=$1', [id]);
  ev(rows[0].name + ' was removed');
  res.json({ ok: true });
}));
app.get('/api/events', auth, adminOnly, h(async (req, res) => {
  const { rows } = await pool.query('SELECT msg, at FROM events ORDER BY id DESC LIMIT 12');
  res.json({ events: rows });
}));

/* servers (one Linux account each) */
async function loadServer(req) {
  const { rows } = await pool.query(SELECT_S + ' WHERE s.id=$1', [+req.params.id]);
  const r = rows[0];
  if (!r || (req.user.role !== 'admin' && r.owner_id !== req.user.id)) throw new HttpError(404, 'Server not found.');
  return r;
}
app.get('/api/servers', auth, h(async (req, res) => {
  const q = req.user.role === 'admin'
    ? await pool.query(SELECT_S + ' ORDER BY s.id')
    : await pool.query(SELECT_S + ' WHERE s.owner_id=$1 ORDER BY s.id', [req.user.id]);
  res.json({ servers: q.rows.map(toApi) });
}));

app.post('/api/servers', auth, adminOnly, h(async (req, res) => {
  needSystem();
  const { name, ownerId, plan } = req.body || {};
  if (!NAME_RE.test(String(name || ''))) throw new HttpError(400, 'Use 2 to 24 lowercase letters, numbers or hyphens, starting with a letter.');
  if (RESERVED.has(name)) throw new HttpError(400, 'That name is reserved. Choose another.');
  const p = PLANS[plan];
  if (!p) throw new HttpError(400, 'Choose a plan.');
  const owner = await pool.query('SELECT id,name FROM users WHERE id=$1', [+ownerId]);
  if (!owner.rows[0]) throw new HttpError(400, 'Choose a customer.');
  if ((await pool.query('SELECT 1 FROM servers WHERE name=$1', [name])).rows.length || await userExists(name)) {
    throw new HttpError(409, 'That name is already used. Choose another.');
  }
  const all = (await pool.query('SELECT plan FROM servers')).rows;
  const used = all.reduce((a, r) => { const q = PLANS[r.plan]; a.cpu += q.cpu; a.ram += q.ram; a.disk += q.disk; return a; }, { cpu: 0, ram: 0, disk: 0 });
  for (const [k, label, unit] of [['cpu', 'CPU', 'vCPU'], ['ram', 'memory', 'GB'], ['disk', 'disk', 'GB']]) {
    if (used[k] + p[k] > TOTAL[k] * OVERCOMMIT + 1e-9) {
      throw new HttpError(409, `Not enough ${label} left on this server (${+(TOTAL[k] * OVERCOMMIT - used[k]).toFixed(2)} ${unit} free). Choose a smaller plan or delete a server.`);
    }
  }

  const pass = genPass();
  await serial(async () => {
    let id;
    try {
      const ins = await pool.query('INSERT INTO servers(name,owner_id,plan,uid,pass) VALUES($1,$2,$3,0,$4) RETURNING id', [name, owner.rows[0].id, plan, enc(pass)]);
      id = ins.rows[0].id;
    } catch (e) {
      if (e.code === '23505') throw new HttpError(409, 'That name is already used. Choose another.');
      throw e;
    }
    const uid = UID_BASE + id;
    await pool.query('UPDATE servers SET uid=$1 WHERE id=$2', [uid, id]);
    try {
      await ensureUser({ id, name, uid, plan, pass: enc(pass), suspended: false });
      await syncLimits();
    } catch (e) {
      await pool.query('DELETE FROM servers WHERE id=$1', [id]);
      try { await run('userdel', ['-r', '-f', name]); } catch { /* nothing to clean */ }
      throw new HttpError(500, 'Could not create the Linux account: ' + e.message);
    }
  });
  await refreshAccounts();
  diskScan();
  ev(name + ' was created for ' + owner.rows[0].name);
  res.json({ ok: true });
}));

app.post('/api/servers/:id/:action(suspend|resume|reboot)', auth, h(async (req, res) => {
  needSystem();
  const r = await loadServer(req);
  const action = req.params.action;
  if (req.user.role !== 'admin' && action !== 'reboot') throw new HttpError(403, 'Only admins can suspend or resume a server.');
  if (r.suspended && action === 'reboot') throw new HttpError(409, 'This server is suspended. Resume it first.');
  await serial(async () => {
    if (action === 'suspend') { await setLock(r.name, true); killUid(r.uid); await pool.query('UPDATE servers SET suspended=true WHERE id=$1', [r.id]); }
    else if (action === 'resume') { await setLock(r.name, false); await pool.query('UPDATE servers SET suspended=false WHERE id=$1', [r.id]); overDisk.delete(r.uid); }
    else killUid(r.uid);
  });
  await refreshAccounts();
  ev(r.name + (action === 'suspend' ? ' was suspended' : action === 'resume' ? ' was resumed' : ' was rebooted'));
  res.json({ ok: true });
}));

app.post('/api/servers/:id/password', auth, h(async (req, res) => {
  needSystem();
  const r = await loadServer(req);
  const pass = genPass();
  await serial(async () => {
    await run('chpasswd', [], r.name + ':' + pass + '\n');
    await pool.query('UPDATE servers SET pass=$1 WHERE id=$2', [enc(pass), r.id]);
    await setLock(r.name, r.suspended);
  });
  ev('Password reset for ' + r.name);
  res.json({ password: pass });
}));

app.get('/api/servers/:id/processes', auth, h(async (req, res) => {
  const r = await loadServer(req);
  const list = (procsByUid.get(r.uid) || []).slice().sort((a, b) => b.rss - a.rss).slice(0, 12)
    .map(p => ({ pid: p.pid, name: p.comm, ramMB: +(p.rss / 1024).toFixed(1), cpu: +p.cpu.toFixed(2) }));
  res.json({ processes: list });
}));

app.delete('/api/servers/:id', auth, adminOnly, h(async (req, res) => {
  needSystem();
  const r = await loadServer(req);
  await serial(async () => {
    try { await setLock(r.name, true); } catch { /* may already be gone */ }
    killUid(r.uid);
    try { await run('userdel', ['-r', '-f', r.name]); } catch (e) { if (!/does not exist/i.test(e.message)) throw e; }
    await fs.promises.rm(HOME_BASE + '/' + r.name, { recursive: true, force: true });
    await pool.query('DELETE FROM servers WHERE id=$1', [r.id]);
    await syncLimits();
  });
  diskKB.delete(r.uid); overDisk.delete(r.uid);
  await refreshAccounts();
  ev(r.name + ' was deleted');
  res.json({ ok: true });
}));

app.use('/vendor/xterm', express.static(path.join(__dirname, 'node_modules/@xterm/xterm')));
app.use('/vendor/xterm-fit', express.static(path.join(__dirname, 'node_modules/@xterm/addon-fit')));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (!err.status || err.status >= 500) console.error(err);
  res.status(err.status || 500).json({ error: err.status ? err.message : 'Something went wrong on the server.' });
});

/* ---------- web terminal (real PTY over WebSocket) ---------- */
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });
const openTerms = new Map(); // key -> count
const TERM_LIMIT = 3;

function startPty(argv, opts) {
  const child = spawn('python3', [path.join(__dirname, 'pty_helper.py'), ...argv], {
    cwd: opts.cwd,
    stdio: ['pipe', 'pipe', 'pipe', 'pipe'],
    env: { PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', TERM: 'xterm-256color', LANG: 'C.UTF-8', HOME: opts.home, SHELL: '/bin/bash' }
  });
  child.stdin.on('error', () => {});
  child.stdio[3].on('error', () => {});
  child.stderr.on('data', () => {});
  return child;
}

server.on('upgrade', async (req, socket, head) => {
  const deny = (code, msg) => { try { socket.write('HTTP/1.1 ' + code + ' ' + msg + '\r\nConnection: close\r\n\r\n'); } catch (_) { /* closed */ } socket.destroy(); };
  try {
    const m = /^\/ws\/terminal\/([a-z0-9]+)$/.exec((req.url || '').split('?')[0]);
    if (!m) return deny(404, 'Not Found');
    let originHost = '';
    try { originHost = new URL(req.headers.origin || '').host; } catch { /* no origin */ }
    if (!originHost || originHost !== req.headers.host) return deny(403, 'Forbidden');
    const uid = readCookie(req);
    if (!uid) return deny(401, 'Unauthorized');
    const u = (await pool.query('SELECT id,name,email,role FROM users WHERE id=$1', [uid])).rows[0];
    if (!u) return deny(401, 'Unauthorized');

    let ctx;
    if (m[1] === 'host') {
      if (u.role !== 'admin') return deny(403, 'Forbidden');
      ctx = { key: 'host', argv: ['/bin/bash', '-l'], cwd: fs.existsSync('/root') ? '/root' : process.cwd(), home: fs.existsSync('/root') ? '/root' : os.homedir(), audit: 'Root terminal opened by ' + u.name };
    } else {
      if (!CAN_MANAGE) return deny(500, 'Not Available');
      const r = (await pool.query(SELECT_S + ' WHERE s.id=$1', [parseInt(m[1], 10)])).rows[0];
      if (!r || (u.role !== 'admin' && r.owner_id !== u.id)) return deny(404, 'Not Found');
      if (r.suspended) return deny(409, 'Suspended');
      ctx = { key: 'srv' + r.id, argv: ['runuser', '-l', r.name], cwd: '/', home: HOME_BASE + '/' + r.name, audit: 'Terminal opened for ' + r.name + ' by ' + u.name };
    }
    if ((openTerms.get(ctx.key) || 0) >= TERM_LIMIT) return deny(429, 'Too Many Requests');
    wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req, ctx));
  } catch (e) {
    console.error('upgrade error', e.message);
    deny(500, 'Error');
  }
});

wss.on('connection', (ws, req, ctx) => {
  openTerms.set(ctx.key, (openTerms.get(ctx.key) || 0) + 1);
  ev(ctx.audit);
  const child = startPty(ctx.argv, ctx);
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return; cleaned = true;
    openTerms.set(ctx.key, Math.max(0, (openTerms.get(ctx.key) || 1) - 1));
    try { child.stdin.end(); } catch (_) { /* closed */ }
    setTimeout(() => { try { child.kill('SIGKILL'); } catch (_) { /* gone */ } }, 3000);
  };
  child.stdout.on('data', d => { if (ws.readyState === 1) ws.send(d, { binary: true }); });
  child.on('exit', () => { try { ws.close(1000); } catch (_) { /* closed */ } cleanup(); });
  ws.on('message', raw => {
    let o; try { o = JSON.parse(raw.toString()); } catch { return; }
    if (typeof o.i === 'string') child.stdin.write(o.i);
    else if (Array.isArray(o.r) && o.r.length === 2) {
      const [c, r] = o.r.map(n => Math.max(1, Math.min(500, parseInt(n, 10) || 0)));
      child.stdio[3].write(c + ' ' + r + '\n');
    }
  });
  ws.on('close', cleanup);
  ws.on('error', cleanup);
});

initDb().then(bootSync).then(refreshAccounts).then(() => {
  sample();
  setInterval(sample, 3000);
  setInterval(() => refreshAccounts().catch(() => {}), 30000);
  setInterval(diskScan, 60000);
  setTimeout(diskScan, 5000);
  server.listen(PORT, () => console.log('Dockyard listening on ' + PORT));
}).catch(e => { console.error('Startup failed:', e); process.exit(1); });
