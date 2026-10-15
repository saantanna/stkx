'use strict';
require('./env');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { db, DATA_DIR } = require('./db');
const { hashPassword, verifyPassword } = require('./auth');

/* ───────────── configuração ───────────── */
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const PROD = process.env.NODE_ENV === 'production';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const RETENTION_DAYS = Math.max(30, Number(process.env.RETENTION_DAYS) || 365);
const SESSION_MS = 8 * 60 * 60 * 1000;
const CONSENT_VERSION = '2026-10-15'; // data da Política de Privacidade vigente
const PUBLIC_DIR = fs.realpathSync(path.join(__dirname, 'public'));
const COOKIE = (PROD ? '__Host-' : '') + 'stkx_sid';

const TYPES = {
  site: 'Site ou landing page', saas: 'Sistema web ou SaaS', automacao: 'Automação',
  ecommerce: 'E-commerce', outro: 'Outro tipo de projeto',
};
const BUDGETS = {
  ate3k: 'Até R$ 3.000', '3k-10k': 'R$ 3.000 – 10.000', '10k-30k': 'R$ 10.000 – 30.000', '30k+': 'Acima de R$ 30.000',
};
const DEADLINES = { '2sem': 'Em até 2 semanas', '1mes': 'Em até 1 mês', '1-3meses': 'De 1 a 3 meses' };

/* ───────────── utilidades ───────────── */
function loadSecret() {
  const f = path.join(DATA_DIR, '.secret');
  try { return fs.readFileSync(f); } catch {
    const s = crypto.randomBytes(32);
    fs.writeFileSync(f, s, { mode: 0o600 });
    return s;
  }
}
const SECRET = loadSecret();
const hmac = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

function makeCounter(windowMs) {
  const m = new Map();
  const live = (k) => {
    const now = Date.now();
    const a = (m.get(k) || []).filter((t) => now - t < windowMs);
    if (a.length) m.set(k, a); else m.delete(k);
    return a;
  };
  setInterval(() => { for (const k of [...m.keys()]) live(k); }, windowMs).unref();
  return {
    count: (k) => live(k).length,
    add: (k) => { const a = live(k); a.push(Date.now()); m.set(k, a); },
    reset: (k) => m.delete(k),
  };
}
const inqByIp = makeCounter(60 * 60 * 1000);
const inqGlobal = makeCounter(60 * 60 * 1000);
const loginFails = makeCounter(15 * 60 * 1000);

function clientIp(req) {
  if (TRUST_PROXY) {
    const x = req.headers['x-forwarded-for'];
    if (x) return String(x).split(',').pop().trim(); // último salto = o que o nosso proxy anexou
  }
  return req.socket.remoteAddress || 'unknown';
}

function sameOrigin(req) {
  const o = req.headers.origin;
  if (o) { try { return new URL(o).host === req.headers.host; } catch { return false; } }
  const sfs = req.headers['sec-fetch-site'];
  return !sfs || sfs === 'same-origin' || sfs === 'none';
}

/* ───────────── cabeçalhos de segurança ───────────── */
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' https://fonts.googleapis.com",
  'font-src https://fonts.gstatic.com',
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  PROD ? 'upgrade-insecure-requests' : '',
].filter(Boolean).join('; ');

function securityHeaders(res) {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  if (PROD) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}

/* ───────────── respostas / corpo ───────────── */
function json(res, status, obj, headers) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(body);
}
const httpErr = (status, message) => Object.assign(new Error(message), { status });

function readJson(req, max = 16 * 1024) {
  return new Promise((resolve, reject) => {
    if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) return reject(httpErr(415, 'Envie JSON.'));
    if (Number(req.headers['content-length']) > max) return reject(httpErr(413, 'Mensagem muito grande.'));
    let size = 0, done = false;
    const chunks = [];
    req.on('data', (c) => {
      if (done) return;
      size += c.length;
      if (size > max) { done = true; reject(httpErr(413, 'Mensagem muito grande.')); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(httpErr(400, 'JSON inválido.')); }
    });
    req.on('error', (e) => { if (!done) { done = true; reject(e); } });
  });
}

/* ───────────── validação do formulário ───────────── */
const CTRL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u2028\u2029]/g;
const CTRL_ML = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u2028\u2029]/g;
function str(v, multiline) {
  if (typeof v !== 'string') return '';
  let s = v.normalize('NFC');
  if (multiline) s = s.replace(/\r\n?/g, '\n').replace(CTRL_ML, ''); else s = s.replace(/\s+/g, ' ').replace(CTRL, '');
  return s.trim();
}
const EMAIL_RE = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const PHONE_RE = /^[\d\s()+\-.]{6,30}$/;

function formToken() {
  const ts = Date.now().toString(36);
  return ts + '.' + hmac('form:' + ts).slice(0, 32);
}
function formTokenAge(t) { // ms desde a emissão, ou null se inválido/expirado
  if (typeof t !== 'string') return null;
  const [ts, sig] = t.split('.');
  if (!ts || !sig || !safeEq(sig, hmac('form:' + ts).slice(0, 32))) return null;
  const age = Date.now() - parseInt(ts, 36);
  return age >= 0 && age < 2 * 60 * 60 * 1000 ? age : null;
}

const insertInquiry = db.prepare(
  `INSERT INTO inquiries (name,email,company,contact,type,budget,deadline,details,consent_version,ip_hash,user_agent)
   VALUES (?,?,?,?,?,?,?,?,?,?,?)`
);

async function postInquiry(req, res) {
  if (!sameOrigin(req)) return json(res, 403, { error: 'Origem não permitida.' });
  const ip = clientIp(req);
  if (inqByIp.count(ip) >= 8 || inqGlobal.count('all') >= 150) {
    return json(res, 429, { error: 'Muitos pedidos em pouco tempo. Tente novamente mais tarde.' }, { 'Retry-After': '3600' });
  }
  const b = await readJson(req);
  if (!b || typeof b !== 'object' || Array.isArray(b)) throw httpErr(400, 'Dados inválidos.');

  const age = formTokenAge(b.token);
  if (age === null) return json(res, 400, { error: 'A sessão do formulário expirou. Tente enviar novamente.', code: 'token' });
  inqByIp.add(ip); inqGlobal.add('all');
  // Armadilhas para robôs: campo oculto preenchido ou envio rápido demais → finge sucesso e descarta.
  if (str(b.website) || age < 3000) return json(res, 200, { ok: true });

  const errors = {};
  const name = str(b.name);
  if (name.length < 2 || name.length > 100) errors.name = 'Informe seu nome.';
  const email = str(b.email).toLowerCase();
  if (email.length > 254 || !EMAIL_RE.test(email)) errors.email = 'Informe um e-mail válido.';
  const company = str(b.company);
  if (company.length > 100) errors.company = 'Use até 100 caracteres.';
  const contact = str(b.contact);
  if (contact && !PHONE_RE.test(contact)) errors.contact = 'Informe um telefone válido.';
  const typeKey = String(b.type ?? '');
  if (!Object.hasOwn(TYPES, typeKey)) errors.type = 'Escolha uma opção.';
  const budgetKey = String(b.budget ?? '');
  if (budgetKey && !Object.hasOwn(BUDGETS, budgetKey)) errors.budget = 'Opção inválida.';
  const deadlineKey = String(b.deadline ?? '');
  if (deadlineKey && !Object.hasOwn(DEADLINES, deadlineKey)) errors.deadline = 'Opção inválida.';
  const details = str(b.details, true);
  if (details.length < 20 || details.length > 3000) errors.details = 'Descreva o projeto com 20 a 3000 caracteres.';
  if (b.consent !== true) errors.consent = 'É necessário concordar para enviar.';
  if (Object.keys(errors).length) return json(res, 422, { error: 'Revise os campos destacados.', fields: errors });

  const ua = String(req.headers['user-agent'] || '').replace(CTRL, '').slice(0, 200);
  const info = insertInquiry.run(
    name, email, company || null, contact || null, TYPES[typeKey],
    budgetKey ? BUDGETS[budgetKey] : null, deadlineKey ? DEADLINES[deadlineKey] : null,
    details, CONSENT_VERSION, hmac('ip:' + ip).slice(0, 32), ua || null
  );
  const evt = { id: Number(info.lastInsertRowid), name, kind: TYPES[typeKey], created_at: new Date().toISOString() };
  broadcast('inquiry', evt);
  pushExternal(evt).catch(() => {});
  return json(res, 201, { ok: true });
}

/* ───────────── notificações ───────────── */
const clients = new Set();
function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const c of clients) { try { c.res.write(msg); } catch { clients.delete(c); } }
}

function openStream(req, res, session) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-store, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write('retry: 3000\n\n');
  const client = { res, tokenHash: session.token_hash, expires: session.expires_at };
  clients.add(client);
  const ping = setInterval(() => {
    if (Date.now() > client.expires) return res.end();
    res.write(': ping\n\n');
  }, 25000);
  req.on('close', () => { clearInterval(ping); clients.delete(client); });
}

// Alerta opcional no celular (só nome + tipo do projeto, nunca a mensagem inteira).
async function pushExternal(evt) {
  const text = `Novo pedido de orçamento: ${evt.name} — ${evt.kind}`;
  const jobs = [];
  const ntfy = process.env.NTFY_URL;
  if (ntfy && /^https:\/\//.test(ntfy)) {
    jobs.push(fetch(ntfy, { method: 'POST', body: text, headers: { Title: 'STKX - novo pedido', Tags: 'incoming_envelope' }, signal: AbortSignal.timeout(8000) }));
  }
  const tg = process.env.TELEGRAM_BOT_TOKEN, chat = process.env.TELEGRAM_CHAT_ID;
  if (tg && chat) {
    jobs.push(fetch(`https://api.telegram.org/bot${tg}/sendMessage`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chat, text }), signal: AbortSignal.timeout(8000),
    }));
  }
  const results = await Promise.allSettled(jobs);
  results.forEach((r) => { if (r.status === 'rejected') console.error('Falha ao enviar alerta externo:', r.reason && r.reason.name); });
}

/* ───────────── sessão do painel ───────────── */
const selSession = db.prepare(
  `SELECT s.token_hash, s.csrf, s.expires_at, a.id AS admin_id, a.username
     FROM sessions s JOIN admins a ON a.id = s.admin_id
    WHERE s.token_hash = ? AND s.expires_at > ?`
);
function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
function getSession(req) {
  const tok = parseCookies(req)[COOKIE];
  if (!tok || tok.length > 100) return null;
  return selSession.get(sha256(tok), Date.now()) || null;
}
function cookie(value, maxAgeSec) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSec}${PROD ? '; Secure' : ''}`;
}

let dummyHash;
async function login(req, res) {
  if (!sameOrigin(req)) return json(res, 403, { error: 'Origem não permitida.' });
  const ip = clientIp(req);
  if (loginFails.count(ip) >= 8) {
    return json(res, 429, { error: 'Muitas tentativas. Aguarde 15 minutos.' }, { 'Retry-After': '900' });
  }
  const b = await readJson(req, 2048);
  const username = typeof b.username === 'string' ? b.username.slice(0, 64) : '';
  const password = typeof b.password === 'string' ? b.password.slice(0, 200) : '';
  const admin = db.prepare('SELECT id, username, pass_hash FROM admins WHERE username = ?').get(username);
  dummyHash ??= await hashPassword('senha-falsa-para-igualar-o-tempo');
  const ok = await verifyPassword(password, admin ? admin.pass_hash : dummyHash) && !!admin;
  if (!ok) {
    loginFails.add(ip);
    await sleep(400);
    return json(res, 401, { error: 'Usuário ou senha incorretos.' });
  }
  loginFails.reset(ip);
  const token = crypto.randomBytes(32).toString('base64url');
  const csrf = crypto.randomBytes(24).toString('base64url');
  db.prepare('INSERT INTO sessions (token_hash, admin_id, csrf, expires_at) VALUES (?,?,?,?)')
    .run(sha256(token), admin.id, csrf, Date.now() + SESSION_MS);
  return json(res, 200, { username: admin.username, csrf }, { 'Set-Cookie': cookie(token, SESSION_MS / 1000) });
}

/* ───────────── API do painel ───────────── */
const STATUSES = ['new', 'read', 'archived'];
const COLS = 'id,created_at,name,email,company,contact,type,budget,deadline,details,status';

function listInquiries(url) {
  const status = url.searchParams.get('status') || 'all';
  const q = (url.searchParams.get('q') || '').slice(0, 100).trim();
  const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit'), 10) || 50));
  const offset = Math.max(0, parseInt(url.searchParams.get('offset'), 10) || 0);
  const where = [], args = [];
  if (STATUSES.includes(status)) { where.push('status = ?'); args.push(status); }
  if (q) {
    const like = '%' + q.replace(/[\\%_]/g, '\\$&') + '%';
    where.push("(name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' OR company LIKE ? ESCAPE '\\' OR details LIKE ? ESCAPE '\\')");
    args.push(like, like, like, like);
  }
  const sql = `SELECT ${COLS} FROM inquiries ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
               ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`;
  const items = db.prepare(sql).all(...args, limit, offset);
  const counts = { new: 0, read: 0, archived: 0, total: 0 };
  for (const r of db.prepare('SELECT status, COUNT(*) AS n FROM inquiries GROUP BY status').all()) {
    counts[r.status] = r.n; counts.total += r.n;
  }
  return { items, counts };
}

function csvCell(v) {
  let s = v == null ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // evita injeção de fórmula no Excel/Sheets
  return '"' + s.replace(/"/g, '""') + '"';
}
function exportCsv(res) {
  const rows = db.prepare(`SELECT ${COLS} FROM inquiries ORDER BY created_at DESC, id DESC`).all();
  const head = ['id', 'recebido_em', 'nome', 'email', 'empresa', 'contato', 'tipo', 'orcamento', 'prazo', 'descricao', 'status'];
  const lines = [head.map(csvCell).join(',')];
  for (const r of rows) {
    lines.push([r.id, r.created_at, r.name, r.email, r.company, r.contact, r.type, r.budget, r.deadline, r.details, r.status].map(csvCell).join(','));
  }
  const body = '\ufeff' + lines.join('\r\n');
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="pedidos-stkx.csv"',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

async function adminApi(req, res, url) {
  const p = url.pathname, m = req.method;
  if (p === '/api/admin/login') {
    if (m !== 'POST') return json(res, 405, { error: 'Método não permitido.' }, { Allow: 'POST' });
    return login(req, res);
  }
  const s = getSession(req);
  if (!s) return json(res, 401, { error: 'Sessão expirada. Entre novamente.' });
  if (m !== 'GET' && m !== 'HEAD') {
    if (!sameOrigin(req) || !safeEq(req.headers['x-csrf-token'] || '', s.csrf)) {
      return json(res, 403, { error: 'Requisição bloqueada.' });
    }
  }

  if (p === '/api/admin/me' && m === 'GET') return json(res, 200, { username: s.username, csrf: s.csrf });

  if (p === '/api/admin/logout' && m === 'POST') {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(s.token_hash);
    for (const c of clients) if (c.tokenHash === s.token_hash) { try { c.res.end(); } catch { /* ok */ } clients.delete(c); }
    return json(res, 200, { ok: true }, { 'Set-Cookie': cookie('', 0) });
  }

  if (p === '/api/admin/stream' && m === 'GET') return openStream(req, res, s);
  if (p === '/api/admin/inquiries' && m === 'GET') return json(res, 200, listInquiries(url));
  if (p === '/api/admin/export.csv' && m === 'GET') return exportCsv(res);

  const idm = p.match(/^\/api\/admin\/inquiries\/(\d{1,12})$/);
  if (idm) {
    const id = Number(idm[1]);
    if (m === 'PATCH') {
      const b = await readJson(req, 1024);
      if (!STATUSES.includes(b.status)) return json(res, 422, { error: 'Status inválido.' });
      const r = db.prepare('UPDATE inquiries SET status = ? WHERE id = ?').run(b.status, id);
      if (!r.changes) return json(res, 404, { error: 'Pedido não encontrado.' });
      return json(res, 200, { item: db.prepare(`SELECT ${COLS} FROM inquiries WHERE id = ?`).get(id) });
    }
    if (m === 'DELETE') {
      const r = db.prepare('DELETE FROM inquiries WHERE id = ?').run(id);
      return json(res, r.changes ? 200 : 404, r.changes ? { ok: true } : { error: 'Pedido não encontrado.' });
    }
  }
  return json(res, 404, { error: 'Não encontrado.' });
}

/* ───────────── arquivos estáticos ───────────── */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8', '.woff2': 'font/woff2',
};

function notFound(res) {
  const body = 'Página não encontrada.';
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store' });
  res.end(body);
}

function serveStatic(req, res, pathname) {
  let rel;
  try { rel = decodeURIComponent(pathname); } catch { return notFound(res); }
  if (rel.includes('\0') || rel.includes('\\')) return notFound(res);
  if (rel === '/admin') { res.writeHead(301, { Location: '/admin/' }); return res.end(); }
  if (rel.endsWith('/')) rel += 'index.html';
  const segs = rel.split('/').filter(Boolean);
  // Bloqueia arquivos ocultos (.env, .git…), exceto /.well-known/
  if (segs.some((sg, i) => sg.startsWith('.') && !(i === 0 && sg === '.well-known'))) return notFound(res);
  const file = path.resolve(PUBLIC_DIR, '.' + rel);
  if (file !== PUBLIC_DIR && !file.startsWith(PUBLIC_DIR + path.sep)) return notFound(res);

  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return notFound(res);
    const ext = path.extname(file).toLowerCase();
    const type = MIME[ext] || (file.endsWith('security.txt') ? MIME['.txt'] : null);
    if (!type) return notFound(res);
    const isAdmin = rel.startsWith('/admin/');
    const headers = {
      'Content-Type': type,
      'Content-Length': st.size,
      'Cache-Control': isAdmin ? 'no-store' : (ext === '.html' ? 'no-cache' : 'public, max-age=3600'),
    };
    if (isAdmin) headers['X-Robots-Tag'] = 'noindex, nofollow';
    res.writeHead(200, headers);
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).on('error', () => res.destroy()).pipe(res);
  });
}

/* ───────────── roteador ───────────── */
async function handle(req, res) {
  securityHeaders(res);
  if (!req.url || req.url[0] !== '/' || req.url.startsWith('//')) return json(res, 400, { error: 'Requisição inválida.' });
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;

  if (p.startsWith('/api/')) {
    if (p === '/api/form-token') {
      if (req.method !== 'GET') return json(res, 405, { error: 'Método não permitido.' }, { Allow: 'GET' });
      return json(res, 200, { token: formToken() });
    }
    if (p === '/api/inquiries') {
      if (req.method !== 'POST') return json(res, 405, { error: 'Método não permitido.' }, { Allow: 'POST' });
      return postInquiry(req, res);
    }
    if (p.startsWith('/api/admin/')) return adminApi(req, res, url);
    return json(res, 404, { error: 'Não encontrado.' });
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { Allow: 'GET, HEAD' });
    return res.end();
  }
  return serveStatic(req, res, p);
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((e) => {
    if (e && e.status) return json(res, e.status, { error: e.message });
    console.error('Erro interno:', e);
    if (!res.headersSent) json(res, 500, { error: 'Erro interno. Tente novamente.' }); else res.end();
  });
});
server.headersTimeout = 10000;
server.requestTimeout = 20000;
server.keepAliveTimeout = 5000;
server.maxHeadersCount = 50;

/* ───────────── manutenção ───────────── */
function purge() {
  const cutoff = new Date(Date.now() - RETENTION_DAYS * 86400000).toISOString();
  const a = db.prepare('DELETE FROM inquiries WHERE created_at < ?').run(cutoff).changes;
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());
  if (a) console.log(`Retenção: ${a} pedido(s) com mais de ${RETENTION_DAYS} dias apagado(s).`);
}
purge();
setInterval(purge, 6 * 60 * 60 * 1000).unref();

server.listen(PORT, HOST, () => {
  console.log(`STKX no ar em http://${HOST}:${PORT}  (painel: /admin/)`);
  if (!db.prepare('SELECT 1 FROM admins LIMIT 1').get()) console.log('Nenhum usuário do painel ainda. Rode:  npm run create-admin');
});

function shutdown() {
  server.close();
  for (const c of clients) { try { c.res.end(); } catch { /* ok */ } }
  try { db.close(); } catch { /* ok */ }
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
