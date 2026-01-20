const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const FROM_EMAIL = process.env.FROM_EMAIL || 'bilgi@g360.ai';
const FROM_NAME = process.env.FROM_NAME || 'G360 AI';
const JWT_SECRET = process.env.JWT_SECRET || 'g360-secret-2024';

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function read(n) {
  const f = path.join(DATA_DIR, n + '.json');
  try { return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : []; } catch(e) { return []; }
}

function write(n, d) {
  fs.writeFileSync(path.join(DATA_DIR, n + '.json'), JSON.stringify(d, null, 2));
}

function readObj(n) {
  const f = path.join(DATA_DIR, n + '.json');
  try { return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : {}; } catch(e) { return {}; }
}

function writeObj(n, d) {
  fs.writeFileSync(path.join(DATA_DIR, n + '.json'), JSON.stringify(d, null, 2));
}

// Initialize
(function() {
  let teams = read('teams');
  if (teams.length === 0) {
    teams = ['Ankara','Istanbul','Izmir','Antalya','Kayseri','Mugla'].map(n => ({
      id: uuidv4(), name: n, created_at: new Date().toISOString()
    }));
    write('teams', teams);
  }

  let users = read('users');
  if (!users.find(u => u.username === 'burakkaan48')) {
    users.push({
      id: uuidv4(), username: 'burakkaan48', password: bcrypt.hashSync('admin123', 10),
      full_name: 'Burak Kaan', role: 'admin', team_id: null, is_active: true, created_at: new Date().toISOString()
    });
    write('users', users);
  }

  let templates = read('templates');
  if (templates.length === 0) {
    templates.push({
      id: uuidv4(),
      name: 'Google Street View Teklif',
      subject: 'Google Street View 360 Teklifi - {{firma}}',
      body: '<p>Sayın <strong>{{musteri}}</strong>,</p><p><strong>{{firma}}</strong> işletmeniz için Google Street View 360 iç mekan çekim hizmeti teklifimizi sunarız.</p><p><strong>Fiyat Teklifimiz:</strong></p><ul><li>30 sahneye kadar: <strong>{{fiyat30}} TL</strong></li><li>30-50 sahne: <strong>{{fiyat50}} TL</strong></li><li>50+ sahne: <strong>{{fiyat50ustu}} TL</strong></li></ul><p>Detaylı bilgi için bizimle iletişime geçebilirsiniz.</p>',
      variables: ['musteri', 'firma', 'fiyat30', 'fiyat50', 'fiyat50ustu'],
      created_at: new Date().toISOString(), is_active: true
    });
    write('templates', templates);
  }

  // Default signature
  let settings = readObj('settings');
  if (!settings.signature) {
    settings.signature = '<p style="color:#666;border-top:1px solid #ddd;padding-top:15px;margin-top:20px;">Saygılarımızla,<br><strong style="color:#0d9488;">G360 AI Ekibi</strong><br>📞 +90 XXX XXX XX XX<br>🌐 www.g360.ai</p>';
    writeObj('settings', settings);
  }
})();

// Send email
async function sendMail(to, subject, html) {
  if (!RESEND_API_KEY) throw new Error('RESEND_API_KEY ayarlanmamis');
  
  const settings = readObj('settings');
  if (settings.signature) html += settings.signature;
  
  const text = html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: FROM_NAME + ' <' + FROM_EMAIL + '>',
      reply_to: FROM_EMAIL,
      to: [to],
      subject: subject,
      html: html,
      text: text
    })
  });
  
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Gonderilemedi');
  return data;
}

// Auth
function auth(req, res, next) {
  const h = req.headers.authorization;
  const t = h && h.split(' ')[1];
  if (!t) return res.status(401).json({ error: 'Token gerekli' });
  jwt.verify(t, JWT_SECRET, (e, u) => {
    if (e) return res.status(403).json({ error: 'Gecersiz token' });
    req.user = u; next();
  });
}

function admin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetki yok' });
  next();
}

// AUTH
app.post('/api/auth/login', (req, res) => {
  const users = read('users');
  const teams = read('teams');
  const u = users.find(x => x.username === req.body.username && x.is_active);
  if (!u || !bcrypt.compareSync(req.body.password, u.password)) {
    return res.status(401).json({ error: 'Hatali giris' });
  }
  const team = teams.find(t => t.id === u.team_id);
  const token = jwt.sign({ id: u.id, username: u.username, role: u.role, full_name: u.full_name, team_id: u.team_id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { ...u, password: undefined, team_name: team?.name } });
});

app.get('/api/auth/me', auth, (req, res) => {
  const users = read('users');
  const teams = read('teams');
  const u = users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'Bulunamadi' });
  const team = teams.find(t => t.id === u.team_id);
  res.json({ ...u, password: undefined, team_name: team?.name });
});

app.post('/api/auth/change-password', auth, (req, res) => {
  const users = read('users');
  const i = users.findIndex(x => x.id === req.user.id);
  if (i === -1) return res.status(404).json({ error: 'Bulunamadi' });
  if (!bcrypt.compareSync(req.body.current, users[i].password)) {
    return res.status(400).json({ error: 'Mevcut sifre yanlis' });
  }
  users[i].password = bcrypt.hashSync(req.body.newpass, 10);
  write('users', users);
  res.json({ ok: true });
});

// TEAMS
app.get('/api/teams', auth, (req, res) => res.json(read('teams')));

app.post('/api/teams', auth, admin, (req, res) => {
  const teams = read('teams');
  const t = { id: uuidv4(), name: req.body.name, created_at: new Date().toISOString() };
  teams.push(t);
  write('teams', teams);
  res.json(t);
});

app.put('/api/teams/:id', auth, admin, (req, res) => {
  const teams = read('teams');
  const i = teams.findIndex(t => t.id === req.params.id);
  if (i === -1) return res.status(404).json({ error: 'Bulunamadi' });
  teams[i].name = req.body.name;
  write('teams', teams);
  res.json(teams[i]);
});

app.delete('/api/teams/:id', auth, admin, (req, res) => {
  let teams = read('teams');
  const users = read('users');
  if (users.some(u => u.team_id === req.params.id)) {
    return res.status(400).json({ error: 'Ekipte kullanici var' });
  }
  teams = teams.filter(t => t.id !== req.params.id);
  write('teams', teams);
  res.json({ ok: true });
});

// USERS
app.get('/api/users', auth, (req, res) => {
  let users = read('users');
  const teams = read('teams');
  
  if (req.user.role === 'manager') {
    users = users.filter(u => u.team_id === req.user.team_id);
  } else if (req.user.role === 'sales') {
    users = users.filter(u => u.id === req.user.id);
  }
  
  res.json(users.map(u => {
    const team = teams.find(t => t.id === u.team_id);
    return { ...u, password: undefined, team_name: team?.name };
  }));
});

app.post('/api/users', auth, admin, (req, res) => {
  const users = read('users');
  if (users.find(u => u.username === req.body.username)) {
    return res.status(400).json({ error: 'Kullanici adi mevcut' });
  }
  const u = {
    id: uuidv4(), username: req.body.username, password: bcrypt.hashSync(req.body.password, 10),
    full_name: req.body.full_name, role: req.body.role || 'sales', team_id: req.body.team_id || null,
    is_active: true, created_at: new Date().toISOString()
  };
  users.push(u);
  write('users', users);
  res.json({ ...u, password: undefined });
});

app.put('/api/users/:id', auth, admin, (req, res) => {
  const users = read('users');
  const i = users.findIndex(u => u.id === req.params.id);
  if (i === -1) return res.status(404).json({ error: 'Bulunamadi' });
  users[i].full_name = req.body.full_name || users[i].full_name;
  users[i].role = req.body.role || users[i].role;
  users[i].team_id = req.body.team_id !== undefined ? req.body.team_id : users[i].team_id;
  if (req.body.password) users[i].password = bcrypt.hashSync(req.body.password, 10);
  write('users', users);
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth, admin, (req, res) => {
  let users = read('users');
  const u = users.find(x => x.id === req.params.id);
  if (u?.role === 'admin') return res.status(400).json({ error: 'Admin silinemez' });
  users = users.filter(x => x.id !== req.params.id);
  write('users', users);
  res.json({ ok: true });
});

// TEMPLATES
app.get('/api/templates', auth, (req, res) => {
  res.json(read('templates').filter(t => t.is_active));
});

app.post('/api/templates', auth, admin, (req, res) => {
  const templates = read('templates');
  const matches = (req.body.subject + ' ' + req.body.body).match(/\{\{(\w+)\}\}/g) || [];
  const variables = [...new Set(matches.map(m => m.slice(2, -2)))];
  
  const t = {
    id: uuidv4(), name: req.body.name, subject: req.body.subject, body: req.body.body,
    variables, created_at: new Date().toISOString(), is_active: true
  };
  templates.push(t);
  write('templates', templates);
  res.json(t);
});

app.put('/api/templates/:id', auth, admin, (req, res) => {
  const templates = read('templates');
  const i = templates.findIndex(t => t.id === req.params.id);
  if (i === -1) return res.status(404).json({ error: 'Bulunamadi' });
  
  const matches = (req.body.subject + ' ' + req.body.body).match(/\{\{(\w+)\}\}/g) || [];
  const variables = [...new Set(matches.map(m => m.slice(2, -2)))];
  
  templates[i] = { ...templates[i], name: req.body.name, subject: req.body.subject, body: req.body.body, variables };
  write('templates', templates);
  res.json(templates[i]);
});

app.delete('/api/templates/:id', auth, admin, (req, res) => {
  const templates = read('templates');
  const i = templates.findIndex(t => t.id === req.params.id);
  if (i !== -1) { templates[i].is_active = false; write('templates', templates); }
  res.json({ ok: true });
});

// SETTINGS (signature)
app.get('/api/settings', auth, (req, res) => {
  res.json(readObj('settings'));
});

app.post('/api/settings', auth, admin, (req, res) => {
  const settings = readObj('settings');
  if (req.body.signature !== undefined) settings.signature = req.body.signature;
  writeObj('settings', settings);
  res.json({ ok: true });
});

// EMAILS
app.get('/api/emails', auth, (req, res) => {
  let emails = read('emails');
  const users = read('users');
  const teams = read('teams');
  
  if (req.user.role === 'manager') {
    const teamUserIds = users.filter(u => u.team_id === req.user.team_id).map(u => u.id);
    emails = emails.filter(e => teamUserIds.includes(e.user_id));
  } else if (req.user.role === 'sales') {
    emails = emails.filter(e => e.user_id === req.user.id);
  }
  
  emails = emails.map(e => {
    const sender = users.find(u => u.id === e.user_id);
    const team = sender ? teams.find(t => t.id === sender.team_id) : null;
    return { ...e, sender_name: sender?.full_name, team_name: team?.name };
  });
  
  emails.sort((a, b) => new Date(b.sent_at) - new Date(a.sent_at));
  res.json(emails);
});

app.get('/api/emails/:id', auth, (req, res) => {
  const emails = read('emails');
  const users = read('users');
  const e = emails.find(x => x.id === req.params.id);
  if (!e) return res.status(404).json({ error: 'Bulunamadi' });
  
  if (req.user.role === 'sales' && e.user_id !== req.user.id) {
    return res.status(403).json({ error: 'Yetki yok' });
  }
  if (req.user.role === 'manager') {
    const teamUserIds = users.filter(u => u.team_id === req.user.team_id).map(u => u.id);
    if (!teamUserIds.includes(e.user_id)) return res.status(403).json({ error: 'Yetki yok' });
  }
  
  const sender = users.find(u => u.id === e.user_id);
  res.json({ ...e, sender_name: sender?.full_name });
});

app.post('/api/emails/send', auth, async (req, res) => {
  const templates = read('templates');
  const t = templates.find(x => x.id === req.body.template_id);
  if (!t) return res.status(404).json({ error: 'Taslak bulunamadi' });
  
  let subject = t.subject;
  let body = t.body;
  const vars = req.body.variables || {};
  
  Object.keys(vars).forEach(k => {
    const re = new RegExp('\\{\\{' + k + '\\}\\}', 'g');
    subject = subject.replace(re, vars[k]);
    body = body.replace(re, vars[k]);
  });
  
  const eid = uuidv4();
  const emails = read('emails');
  const emailData = {
    id: eid, user_id: req.user.id, template_id: req.body.template_id, template_name: t.name,
    recipient_email: req.body.recipient_email, recipient_name: req.body.recipient_name,
    subject, body, variables_used: vars, status: 'sending', sent_at: new Date().toISOString()
  };
  emails.push(emailData);
  write('emails', emails);
  
  try {
    const result = await sendMail(req.body.recipient_email, subject, body);
    const es = read('emails');
    const i = es.findIndex(e => e.id === eid);
    if (i !== -1) { es[i].status = 'sent'; es[i].resend_id = result.id; write('emails', es); }
    res.json({ ok: true, id: result.id });
  } catch (err) {
    const es = read('emails');
    const i = es.findIndex(e => e.id === eid);
    if (i !== -1) { es[i].status = 'failed'; es[i].error = err.message; write('emails', es); }
    res.status(500).json({ error: err.message });
  }
});

// STATS
app.get('/api/stats', auth, (req, res) => {
  let emails = read('emails');
  const users = read('users');
  const teams = read('teams');
  
  if (req.user.role === 'manager') {
    const teamUserIds = users.filter(u => u.team_id === req.user.team_id).map(u => u.id);
    emails = emails.filter(e => teamUserIds.includes(e.user_id));
  } else if (req.user.role === 'sales') {
    emails = emails.filter(e => e.user_id === req.user.id);
  }
  
  res.json({
    total: emails.length,
    sent: emails.filter(e => e.status === 'sent').length,
    failed: emails.filter(e => e.status === 'failed').length,
    teams: teams.length,
    users: users.filter(u => u.role !== 'admin').length
  });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/health', (req, res) => res.json({ ok: true, v: '3.0', from: FROM_EMAIL }));

app.listen(PORT, () => {
  console.log('G360 Mail v3.0 | Port:', PORT, '| From:', FROM_EMAIL);
});
