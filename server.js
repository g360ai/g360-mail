const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

const GMAIL_USER = process.env.GMAIL_USER || 'burak@g360.ai';
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || '';
const JWT_SECRET = process.env.JWT_SECRET || 'g360-mail-secret-key';

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const dbFiles = {
  users: path.join(DATA_DIR, 'users.json'),
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

function initializeData() {
  var users = readDB('users');
  if (!users.find(function(u) { return u.username === 'burakkaan48'; })) {
    users.push({ id: uuidv4(), username: 'burakkaan48', password: bcrypt.hashSync('admin123', 10), full_name: 'Burak Kaan', role: 'admin', created_at: new Date().toISOString(), is_active: 1 });
    writeDB('users', users);
  }
  var templates = readDB('templates');
  if (templates.length === 0) {
    var admin = users.find(function(u) { return u.username === 'burakkaan48'; });
    templates.push({
      id: uuidv4(), name: 'Google Street View Teklif', subject: 'Google Street View Teklifi - {isletme_adi}',
      body: '<div style="font-family:Arial;padding:20px"><p>Sayin <b>{alici_adi}</b>,</p><p><b>{isletme_adi}</b> icin 360 cekim teklifi:</p><ul><li>30 sahne: <b>{fiyat_30} TL</b></li><li>30-50 sahne: <b>{fiyat_50} TL</b></li><li>50+ sahne: <b>{fiyat_50_ustu} TL</b></li></ul><p>G360 AI</p></div>',
      variables: ['alici_adi', 'isletme_adi', 'fiyat_30', 'fiyat_50', 'fiyat_50_ustu'],
      created_by: admin ? admin.id : null, created_at: new Date().toISOString(), is_active: 1
    });
    writeDB('templates', templates);
  }
}
initializeData();

function createTransporter() {
  console.log('SMTP:', GMAIL_USER, 'Pass:', GMAIL_APP_PASSWORD ? GMAIL_APP_PASSWORD.length + ' chars' : 'NOT SET');
  if (!GMAIL_APP_PASSWORD) return null;
  return nodemailer.createTransport({ service: 'gmail', auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD } });
}

function auth(req, res, next) {
  var h = req.headers['authorization'];
  var t = h && h.split(' ')[1];
  if (!t) return res.status(401).json({ error: 'Token gerekli' });
  jwt.verify(t, JWT_SECRET, function(e, u) { if (e) return res.status(403).json({ error: 'Gecersiz token' }); req.user = u; next(); });
}

function admin(req, res, next) { if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin gerekli' }); next(); }

app.post('/api/auth/login', function(req, res) {
  var users = readDB('users');
  var u = users.find(function(x) { return x.username === req.body.username && x.is_active; });
  if (!u || !bcrypt.compareSync(req.body.password, u.password)) return res.status(401).json({ error: 'Hatali giris' });
  var t = jwt.sign({ id: u.id, username: u.username, role: u.role, full_name: u.full_name }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token: t, user: { id: u.id, username: u.username, full_name: u.full_name, role: u.role } });
});

app.get('/api/auth/me', auth, function(req, res) {
  var u = readDB('users').find(function(x) { return x.id === req.user.id; });
  u ? res.json({ id: u.id, username: u.username, full_name: u.full_name, role: u.role }) : res.status(404).json({ error: 'Yok' });
});

app.post('/api/auth/change-password', auth, function(req, res) {
  var users = readDB('users');
  var i = users.findIndex(function(x) { return x.id === req.user.id; });
  if (i === -1) return res.status(404).json({ error: 'Yok' });
  if (!bcrypt.compareSync(req.body.currentPassword, users[i].password)) return res.status(400).json({ error: 'Yanlis sifre' });
  users[i].password = bcrypt.hashSync(req.body.newPassword, 10);
  writeDB('users', users);
  res.json({ success: true });
});

app.get('/api/users', auth, admin, function(req, res) {
  res.json(readDB('users').map(function(u) { return { id: u.id, username: u.username, full_name: u.full_name, role: u.role, is_active: u.is_active }; }));
});

app.post('/api/users', auth, admin, function(req, res) {
  var users = readDB('users');
  if (users.find(function(x) { return x.username === req.body.username; })) return res.status(400).json({ error: 'Mevcut' });
  var u = { id: uuidv4(), username: req.body.username, password: bcrypt.hashSync(req.body.password, 10), full_name: req.body.full_name, role: 'user', created_at: new Date().toISOString(), is_active: 1 };
  users.push(u);
  writeDB('users', users);
  res.json({ id: u.id, username: u.username, full_name: u.full_name, role: 'user' });
});

app.delete('/api/users/:id', auth, admin, function(req, res) {
  var users = readDB('users');
  var u = users.find(function(x) { return x.id === req.params.id; });
  if (u && u.role === 'admin') return res.status(400).json({ error: 'Admin silinemez' });
  writeDB('users', users.filter(function(x) { return x.id !== req.params.id; }));
  res.json({ success: true });
});

app.get('/api/templates', auth, function(req, res) {
  res.json(readDB('templates').filter(function(t) { return t.is_active; }));
});

app.post('/api/templates', auth, admin, function(req, res) {
  var ts = readDB('templates');
  var t = { id: uuidv4(), name: req.body.name, subject: req.body.subject, body: req.body.body, variables: req.body.variables || [], created_by: req.user.id, created_at: new Date().toISOString(), is_active: 1 };
  ts.push(t);
  writeDB('templates', ts);
  res.json(t);
});

app.delete('/api/templates/:id', auth, admin, function(req, res) {
  var ts = readDB('templates');
  var i = ts.findIndex(function(t) { return t.id === req.params.id; });
  if (i !== -1) { ts[i].is_active = 0; writeDB('templates', ts); }
  res.json({ success: true });
});

app.get('/api/emails', auth, function(req, res) {
  var emails = readDB('emails');
  var users = readDB('users');
  if (req.user.role !== 'admin') emails = emails.filter(function(e) { return e.user_id === req.user.id; });
  emails.forEach(function(e) { var s = users.find(function(u) { return u.id === e.user_id; }); e.sender_name = s ? s.full_name : null; });
  emails.sort(function(a, b) { return new Date(b.sent_at) - new Date(a.sent_at); });
  res.json(emails);
});

app.post('/api/emails/send', auth, function(req, res) {
  console.log('=== SEND EMAIL ===');
  console.log('To:', req.body.recipient_email);
  
  var ts = readDB('templates');
  var t = ts.find(function(x) { return x.id === req.body.template_id; });
  if (!t) return res.status(404).json({ error: 'Taslak yok' });
  
  var subj = t.subject, body = t.body, vars = req.body.variables || {};
  Object.keys(vars).forEach(function(k) { subj = subj.split('{' + k + '}').join(vars[k]); body = body.split('{' + k + '}').join(vars[k]); });
  
  var eid = uuidv4();
  var emails = readDB('emails');
  emails.push({ id: eid, user_id: req.user.id, template_id: req.body.template_id, recipient_email: req.body.recipient_email, recipient_name: req.body.recipient_name, subject: subj, body: body, variables_used: vars, status: 'sending', sent_at: new Date().toISOString() });
  writeDB('emails', emails);
  
  var tr = createTransporter();
  if (!tr) {
    var es = readDB('emails'); var i = es.findIndex(function(e) { return e.id === eid; });
    if (i !== -1) { es[i].status = 'failed'; es[i].error_message = 'Gmail ayarlanmamis'; writeDB('emails', es); }
    return res.status(500).json({ error: 'Gmail ayarlanmamis' });
  }
  
  tr.sendMail({ from: '"G360 AI" <' + GMAIL_USER + '>', to: req.body.recipient_email, subject: subj, html: body }, function(err, info) {
    var es2 = readDB('emails'); var i2 = es2.findIndex(function(e) { return e.id === eid; });
    if (err) {
      console.error('MAIL ERROR:', err.code, err.message);
      if (i2 !== -1) { es2[i2].status = 'failed'; es2[i2].error_message = err.message; writeDB('emails', es2); }
      return res.status(500).json({ error: 'Gonderilemedi: ' + err.message });
    }
    console.log('MAIL SENT:', info.messageId);
    if (i2 !== -1) { es2[i2].status = 'sent'; writeDB('emails', es2); }
    res.json({ success: true });
  });
});

app.get('/api/stats', auth, admin, function(req, res) {
  var e = readDB('emails'), u = readDB('users'), t = readDB('templates');
  res.json({ totalEmails: e.length, sentEmails: e.filter(function(x) { return x.status === 'sent'; }).length, failedEmails: e.filter(function(x) { return x.status === 'failed'; }).length, totalUsers: u.filter(function(x) { return x.role === 'user'; }).length, totalTemplates: t.filter(function(x) { return x.is_active; }).length });
});

app.get('/', function(req, res) { res.sendFile(path.join(__dirname, 'index.html')); });
app.get('/health', function(req, res) { res.json({ status: 'ok', gmail: GMAIL_USER, pass: !!GMAIL_APP_PASSWORD }); });

app.listen(PORT, function() { console.log('G360 Mail on port ' + PORT + ' | Gmail: ' + GMAIL_USER + ' | Pass: ' + (GMAIL_APP_PASSWORD ? 'SET' : 'NOT SET')); });
