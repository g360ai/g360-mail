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
const JWT_SECRET = process.env.JWT_SECRET || 'g360-mail-secret-key';

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const dbFiles = {
  users: path.join(DATA_DIR, 'users.json'),
  teams: path.join(DATA_DIR, 'teams.json'),
  templates: path.join(DATA_DIR, 'templates.json'),
  emails: path.join(DATA_DIR, 'emails.json')
};

function readDB(file) {
  try { if (fs.existsSync(dbFiles[file])) return JSON.parse(fs.readFileSync(dbFiles[file], 'utf8')); } catch (e) {}
  return [];
}

function writeDB(file, data) {
  try { fs.writeFileSync(dbFiles[file], JSON.stringify(data, null, 2)); } catch (e) {}
}

// Initialize default data
function initializeData() {
  // Teams
  var teams = readDB('teams');
  if (teams.length === 0) {
    teams = [
      { id: uuidv4(), name: 'Ankara' },
      { id: uuidv4(), name: 'Istanbul' },
      { id: uuidv4(), name: 'Izmir' },
      { id: uuidv4(), name: 'Antalya' },
      { id: uuidv4(), name: 'Mugla' },
      { id: uuidv4(), name: 'Kayseri' }
    ];
    writeDB('teams', teams);
  }

  // Users
  var users = readDB('users');
  if (!users.find(function(u) { return u.username === 'burakkaan48'; })) {
    users.push({
      id: uuidv4(),
      username: 'burakkaan48',
      password: bcrypt.hashSync('admin123', 10),
      full_name: 'Burak Kaan',
      role: 'admin', // admin, manager, sales
      team_id: null, // admin doesn't need team
      created_at: new Date().toISOString(),
      is_active: 1
    });
    writeDB('users', users);
  }

  // Templates
  var templates = readDB('templates');
  if (templates.length === 0) {
    templates.push({
      id: uuidv4(),
      name: 'Google Street View Teklif',
      subject: 'Google Street View 360 Teklifi - {isletme_adi}',
      body: '<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:30px;background:#ffffff;">' +
        '<div style="text-align:center;margin-bottom:30px;">' +
        '<h1 style="color:#0d9488;margin:0;">G360 AI</h1>' +
        '<p style="color:#64748b;margin:5px 0;">Google Street View 360 Cozumleri</p></div>' +
        '<p style="font-size:16px;color:#334155;">Sayin <strong>{alici_adi}</strong>,</p>' +
        '<p style="font-size:15px;color:#475569;line-height:1.7;">' +
        '<strong>{isletme_adi}</strong> isletmeniz icin Google Street View 360 ic mekan cekim hizmeti teklifimizi bilgilerinize sunariz.</p>' +
        '<div style="background:linear-gradient(135deg,#0d9488,#0891b2);color:white;padding:25px;border-radius:12px;margin:25px 0;">' +
        '<h3 style="margin:0 0 15px 0;font-size:18px;">Fiyat Teklifimiz</h3>' +
        '<table style="width:100%;color:white;">' +
        '<tr><td style="padding:8px 0;">30 sahneye kadar:</td><td style="text-align:right;font-weight:bold;">{fiyat_30} TL + KDV</td></tr>' +
        '<tr><td style="padding:8px 0;">30-50 sahne:</td><td style="text-align:right;font-weight:bold;">{fiyat_50} TL + KDV</td></tr>' +
        '<tr><td style="padding:8px 0;">50+ sahne:</td><td style="text-align:right;font-weight:bold;">{fiyat_50_ustu} TL + KDV</td></tr>' +
        '</table></div>' +
        '<p style="font-size:15px;color:#475569;">Detayli bilgi ve sorulariniz icin bizimle iletisime gecebilirsiniz.</p>' +
        '<p style="font-size:15px;color:#334155;margin-top:30px;">Saygilarimizla,<br><strong style="color:#0d9488;">G360 AI Ekibi</strong></p>' +
        '</div>',
      variables: ['alici_adi', 'isletme_adi', 'fiyat_30', 'fiyat_50', 'fiyat_50_ustu'],
      created_by: null,
      created_at: new Date().toISOString(),
      is_active: 1
    });
    writeDB('templates', templates);
  }
}
initializeData();

// Send email with Resend
async function sendEmailWithResend(to, subject, html) {
  if (!RESEND_API_KEY) throw new Error('RESEND_API_KEY ayarlanmamis');
  
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: 'G360 AI <' + FROM_EMAIL + '>', to: [to], subject: subject, html: html })
  });
  
  const data = await response.json();
  if (!response.ok) throw new Error(data.message || 'Email gonderilemedi');
  return data;
}

// Auth middleware
function auth(req, res, next) {
  var h = req.headers['authorization'];
  var t = h && h.split(' ')[1];
  if (!t) return res.status(401).json({ error: 'Token gerekli' });
  jwt.verify(t, JWT_SECRET, function(e, u) {
    if (e) return res.status(403).json({ error: 'Gecersiz token' });
    req.user = u;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin yetkisi gerekli' });
  next();
}

// AUTH ROUTES
app.post('/api/auth/login', function(req, res) {
  var users = readDB('users');
  var teams = readDB('teams');
  var u = users.find(function(x) { return x.username === req.body.username && x.is_active; });
  if (!u || !bcrypt.compareSync(req.body.password, u.password)) {
    return res.status(401).json({ error: 'Hatali kullanici adi veya sifre' });
  }
  var team = teams.find(function(t) { return t.id === u.team_id; });
  var t = jwt.sign({
    id: u.id, username: u.username, role: u.role, full_name: u.full_name, team_id: u.team_id
  }, JWT_SECRET, { expiresIn: '24h' });
  res.json({
    token: t,
    user: { id: u.id, username: u.username, full_name: u.full_name, role: u.role, team_id: u.team_id, team_name: team ? team.name : null }
  });
});

app.get('/api/auth/me', auth, function(req, res) {
  var users = readDB('users');
  var teams = readDB('teams');
  var u = users.find(function(x) { return x.id === req.user.id; });
  if (!u) return res.status(404).json({ error: 'Kullanici bulunamadi' });
  var team = teams.find(function(t) { return t.id === u.team_id; });
  res.json({ id: u.id, username: u.username, full_name: u.full_name, role: u.role, team_id: u.team_id, team_name: team ? team.name : null });
});

app.post('/api/auth/change-password', auth, function(req, res) {
  var users = readDB('users');
  var i = users.findIndex(function(x) { return x.id === req.user.id; });
  if (i === -1) return res.status(404).json({ error: 'Kullanici bulunamadi' });
  if (!bcrypt.compareSync(req.body.currentPassword, users[i].password)) {
    return res.status(400).json({ error: 'Mevcut sifre yanlis' });
  }
  users[i].password = bcrypt.hashSync(req.body.newPassword, 10);
  writeDB('users', users);
  res.json({ success: true });
});

// TEAM ROUTES
app.get('/api/teams', auth, function(req, res) {
  res.json(readDB('teams'));
});

app.post('/api/teams', auth, requireAdmin, function(req, res) {
  var teams = readDB('teams');
  var t = { id: uuidv4(), name: req.body.name };
  teams.push(t);
  writeDB('teams', teams);
  res.json(t);
});

app.delete('/api/teams/:id', auth, requireAdmin, function(req, res) {
  var teams = readDB('teams');
  var users = readDB('users');
  // Check if team has users
  var hasUsers = users.some(function(u) { return u.team_id === req.params.id; });
  if (hasUsers) return res.status(400).json({ error: 'Ekipte kullanici var, once kullanicilari tasiyin' });
  teams = teams.filter(function(t) { return t.id !== req.params.id; });
  writeDB('teams', teams);
  res.json({ success: true });
});

// USER ROUTES
app.get('/api/users', auth, function(req, res) {
  var users = readDB('users');
  var teams = readDB('teams');
  
  // Filter based on role
  if (req.user.role === 'manager') {
    users = users.filter(function(u) { return u.team_id === req.user.team_id; });
  } else if (req.user.role === 'sales') {
    users = users.filter(function(u) { return u.id === req.user.id; });
  }
  
  var result = users.map(function(u) {
    var team = teams.find(function(t) { return t.id === u.team_id; });
    return {
      id: u.id, username: u.username, full_name: u.full_name, role: u.role,
      team_id: u.team_id, team_name: team ? team.name : null, is_active: u.is_active, created_at: u.created_at
    };
  });
  res.json(result);
});

app.post('/api/users', auth, requireAdmin, function(req, res) {
  var users = readDB('users');
  if (users.find(function(x) { return x.username === req.body.username; })) {
    return res.status(400).json({ error: 'Bu kullanici adi zaten mevcut' });
  }
  var u = {
    id: uuidv4(),
    username: req.body.username,
    password: bcrypt.hashSync(req.body.password, 10),
    full_name: req.body.full_name,
    role: req.body.role || 'sales',
    team_id: req.body.team_id || null,
    created_at: new Date().toISOString(),
    is_active: 1
  };
  users.push(u);
  writeDB('users', users);
  
  var teams = readDB('teams');
  var team = teams.find(function(t) { return t.id === u.team_id; });
  res.json({ id: u.id, username: u.username, full_name: u.full_name, role: u.role, team_id: u.team_id, team_name: team ? team.name : null });
});

app.put('/api/users/:id', auth, requireAdmin, function(req, res) {
  var users = readDB('users');
  var i = users.findIndex(function(u) { return u.id === req.params.id; });
  if (i === -1) return res.status(404).json({ error: 'Kullanici bulunamadi' });
  
  users[i].full_name = req.body.full_name || users[i].full_name;
  users[i].role = req.body.role || users[i].role;
  users[i].team_id = req.body.team_id !== undefined ? req.body.team_id : users[i].team_id;
  if (req.body.password) users[i].password = bcrypt.hashSync(req.body.password, 10);
  
  writeDB('users', users);
  res.json({ success: true });
});

app.delete('/api/users/:id', auth, requireAdmin, function(req, res) {
  var users = readDB('users');
  var u = users.find(function(x) { return x.id === req.params.id; });
  if (u && u.role === 'admin') return res.status(400).json({ error: 'Admin kullanici silinemez' });
  users = users.filter(function(x) { return x.id !== req.params.id; });
  writeDB('users', users);
  res.json({ success: true });
});

// TEMPLATE ROUTES
app.get('/api/templates', auth, function(req, res) {
  res.json(readDB('templates').filter(function(t) { return t.is_active; }));
});

app.post('/api/templates', auth, requireAdmin, function(req, res) {
  var templates = readDB('templates');
  // Auto-detect variables from body and subject
  var allText = (req.body.subject || '') + ' ' + (req.body.body || '');
  var matches = allText.match(/\{([^}]+)\}/g) || [];
  var variables = matches.map(function(m) { return m.slice(1, -1); });
  variables = variables.filter(function(v, i, a) { return a.indexOf(v) === i; }); // unique
  
  var t = {
    id: uuidv4(),
    name: req.body.name,
    subject: req.body.subject,
    body: req.body.body,
    variables: variables,
    created_by: req.user.id,
    created_at: new Date().toISOString(),
    is_active: 1
  };
  templates.push(t);
  writeDB('templates', templates);
  res.json(t);
});

app.put('/api/templates/:id', auth, requireAdmin, function(req, res) {
  var templates = readDB('templates');
  var i = templates.findIndex(function(t) { return t.id === req.params.id; });
  if (i === -1) return res.status(404).json({ error: 'Taslak bulunamadi' });
  
  // Auto-detect variables
  var allText = (req.body.subject || '') + ' ' + (req.body.body || '');
  var matches = allText.match(/\{([^}]+)\}/g) || [];
  var variables = matches.map(function(m) { return m.slice(1, -1); });
  variables = variables.filter(function(v, i, a) { return a.indexOf(v) === i; });
  
  templates[i].name = req.body.name;
  templates[i].subject = req.body.subject;
  templates[i].body = req.body.body;
  templates[i].variables = variables;
  writeDB('templates', templates);
  res.json(templates[i]);
});

app.delete('/api/templates/:id', auth, requireAdmin, function(req, res) {
  var templates = readDB('templates');
  var i = templates.findIndex(function(t) { return t.id === req.params.id; });
  if (i !== -1) { templates[i].is_active = 0; writeDB('templates', templates); }
  res.json({ success: true });
});

// EMAIL ROUTES
app.get('/api/emails', auth, function(req, res) {
  var emails = readDB('emails');
  var users = readDB('users');
  var teams = readDB('teams');
  
  // Filter based on role
  if (req.user.role === 'manager') {
    // Get all users in manager's team
    var teamUserIds = users.filter(function(u) { return u.team_id === req.user.team_id; }).map(function(u) { return u.id; });
    emails = emails.filter(function(e) { return teamUserIds.indexOf(e.user_id) !== -1; });
  } else if (req.user.role === 'sales') {
    emails = emails.filter(function(e) { return e.user_id === req.user.id; });
  }
  
  emails.forEach(function(e) {
    var sender = users.find(function(u) { return u.id === e.user_id; });
    if (sender) {
      e.sender_name = sender.full_name;
      var team = teams.find(function(t) { return t.id === sender.team_id; });
      e.team_name = team ? team.name : null;
    }
  });
  
  emails.sort(function(a, b) { return new Date(b.sent_at) - new Date(a.sent_at); });
  res.json(emails);
});

app.post('/api/emails/send', auth, async function(req, res) {
  var templates = readDB('templates');
  var t = templates.find(function(x) { return x.id === req.body.template_id; });
  if (!t) return res.status(404).json({ error: 'Taslak bulunamadi' });
  
  var subj = t.subject, body = t.body, vars = req.body.variables || {};
  Object.keys(vars).forEach(function(k) {
    subj = subj.split('{' + k + '}').join(vars[k]);
    body = body.split('{' + k + '}').join(vars[k]);
  });
  
  var eid = uuidv4();
  var emails = readDB('emails');
  emails.push({
    id: eid, user_id: req.user.id, template_id: req.body.template_id,
    recipient_email: req.body.recipient_email, recipient_name: req.body.recipient_name,
    subject: subj, body: body, variables_used: vars, status: 'sending', sent_at: new Date().toISOString()
  });
  writeDB('emails', emails);
  
  try {
    var result = await sendEmailWithResend(req.body.recipient_email, subj, body);
    var es = readDB('emails');
    var i = es.findIndex(function(e) { return e.id === eid; });
    if (i !== -1) { es[i].status = 'sent'; es[i].resend_id = result.id; writeDB('emails', es); }
    res.json({ success: true, id: result.id });
  } catch (err) {
    var es2 = readDB('emails');
    var i2 = es2.findIndex(function(e) { return e.id === eid; });
    if (i2 !== -1) { es2[i2].status = 'failed'; es2[i2].error_message = err.message; writeDB('emails', es2); }
    res.status(500).json({ error: err.message });
  }
});

// STATS
app.get('/api/stats', auth, function(req, res) {
  var emails = readDB('emails');
  var users = readDB('users');
  var teams = readDB('teams');
  
  // Filter based on role
  if (req.user.role === 'manager') {
    var teamUserIds = users.filter(function(u) { return u.team_id === req.user.team_id; }).map(function(u) { return u.id; });
    emails = emails.filter(function(e) { return teamUserIds.indexOf(e.user_id) !== -1; });
    users = users.filter(function(u) { return u.team_id === req.user.team_id; });
  } else if (req.user.role === 'sales') {
    emails = emails.filter(function(e) { return e.user_id === req.user.id; });
    users = [req.user];
  }
  
  res.json({
    totalEmails: emails.length,
    sentEmails: emails.filter(function(x) { return x.status === 'sent'; }).length,
    failedEmails: emails.filter(function(x) { return x.status === 'failed'; }).length,
    totalUsers: users.filter(function(x) { return x.role !== 'admin'; }).length,
    totalTeams: req.user.role === 'admin' ? teams.length : 1
  });
});

// Frontend
app.get('/', function(req, res) { res.sendFile(path.join(__dirname, 'index.html')); });
app.get('/health', function(req, res) { res.json({ status: 'ok', from: FROM_EMAIL, resend: !!RESEND_API_KEY }); });

app.listen(PORT, function() {
  console.log('=================================');
  console.log('G360 Mail System v2.0');
  console.log('Port: ' + PORT);
  console.log('From: ' + FROM_EMAIL);
  console.log('Resend: ' + (RESEND_API_KEY ? 'OK' : 'NOT SET'));
  console.log('=================================');
});
