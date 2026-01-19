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

// JSON Database
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const dbFiles = {
  users: path.join(DATA_DIR, 'users.json'),
  templates: path.join(DATA_DIR, 'templates.json'),
  emails: path.join(DATA_DIR, 'emails.json')
};

function readDB(file) {
  try {
    if (fs.existsSync(dbFiles[file])) {
      return JSON.parse(fs.readFileSync(dbFiles[file], 'utf8'));
    }
  } catch (e) { console.error('Read error:', e); }
  return [];
}

function writeDB(file, data) {
  try {
    fs.writeFileSync(dbFiles[file], JSON.stringify(data, null, 2));
  } catch (e) { console.error('Write error:', e); }
}

// Initialize
function initializeData() {
  var users = readDB('users');
  if (!users.find(function(u) { return u.username === 'burakkaan48'; })) {
    users.push({
      id: uuidv4(),
      username: 'burakkaan48',
      password: bcrypt.hashSync('admin123', 10),
      full_name: 'Burak Kaan',
      role: 'admin',
      created_at: new Date().toISOString(),
      is_active: 1
    });
    writeDB('users', users);
    console.log('Admin user created');
  }

  var templates = readDB('templates');
  if (templates.length === 0) {
    var adminUser = users.find(function(u) { return u.username === 'burakkaan48'; });
    templates.push({
      id: uuidv4(),
      name: 'Google Street View Teklif',
      subject: 'Google Street View 360 Cekim Teklifi - {isletme_adi}',
      body: getDefaultTemplateBody(),
      variables: ['alici_adi', 'isletme_adi', 'fiyat_30', 'fiyat_50', 'fiyat_50_ustu'],
      created_by: adminUser ? adminUser.id : null,
      created_at: new Date().toISOString(),
      is_active: 1
    });
    writeDB('templates', templates);
    console.log('Default template created');
  }
}

function getDefaultTemplateBody() {
  return '<div style="font-family: Arial, sans-serif; max-width: 700px; margin: 0 auto; padding: 30px; background: #ffffff;">' +
    '<p style="font-size: 16px; color: #333;">Sayin <strong>{alici_adi}</strong>,</p>' +
    '<p style="font-size: 15px; color: #444; line-height: 1.7;">' +
    'Gectigimiz gorusmemiz dogrultusunda, <strong>{isletme_adi}</strong> icin Google Street View kapsaminda sunabilecegimiz 360 ic mekan cekim hizmetiyle ilgili teklifimizi asagida bilgilerinize sunariz.</p>' +
    '<div style="background: linear-gradient(135deg, #0d9488 0%, #0891b2 100%); color: white; padding: 20px; border-radius: 10px; margin: 25px 0;">' +
    '<h3 style="margin: 0 0 15px 0; font-size: 18px;">Hizmet Icerigi</h3>' +
    '<ul style="margin: 0; padding-left: 20px; line-height: 1.8;">' +
    '<li>Isletme genelinde ic ve dis mekanlarin tamami 360 cekim ile belgelenir</li>' +
    '<li>Tum gorseller Google Street View standartlarina uygun sekilde optimize edilir</li>' +
    '<li>SEO uyumlu, mobil cihazlarla tam uyumlu dijital sanal tur</li>' +
    '</ul></div>' +
    '<div style="background: #f8fafc; border: 2px solid #e2e8f0; border-radius: 10px; padding: 20px; margin: 25px 0;">' +
    '<h3 style="margin: 0 0 15px 0; color: #1e293b; font-size: 18px;">Teklif Detaylari</h3>' +
    '<table style="width: 100%; border-collapse: collapse;">' +
    '<tr style="background: #0d9488; color: white;"><th style="padding: 12px; text-align: left;">Sahne Sayisi</th><th style="padding: 12px; text-align: right;">Fiyat</th></tr>' +
    '<tr><td style="padding: 12px; border-bottom: 1px solid #e2e8f0;">30 sahneye kadar</td><td style="padding: 12px; border-bottom: 1px solid #e2e8f0; text-align: right; font-weight: bold; color: #0d9488;">{fiyat_30} + KDV</td></tr>' +
    '<tr><td style="padding: 12px; border-bottom: 1px solid #e2e8f0;">30-50 sahne arasi</td><td style="padding: 12px; border-bottom: 1px solid #e2e8f0; text-align: right; font-weight: bold; color: #0d9488;">{fiyat_50} + KDV</td></tr>' +
    '<tr><td style="padding: 12px;">50 sahne ve uzeri</td><td style="padding: 12px; text-align: right; font-weight: bold; color: #0d9488;">{fiyat_50_ustu} + KDV</td></tr>' +
    '</table></div>' +
    '<p style="font-size: 15px; color: #444;">Is birligi icin simdiden tesekkur eder, isletmenizin dijital gorunurlugunu birlikte guclendirmekten mutluluk duyariz.</p>' +
    '<p style="font-size: 15px; color: #333; margin-top: 30px;">Saygilarimizla,</p>' +
    '<div style="margin-top: 30px; padding-top: 20px; border-top: 2px solid #e2e8f0;">' +
    '<p style="margin: 0; font-weight: bold; color: #0d9488;">G360 AI</p>' +
    '<p style="margin: 5px 0 0 0; font-size: 13px; color: #64748b;">g360.ai</p></div></div>';
}

initializeData();

// Email transporter
function createTransporter() {
  if (!GMAIL_APP_PASSWORD) {
    console.warn('Gmail App Password not configured!');
    return null;
  }
  return nodemailer.createTransport({
    service: 'gmail',
    auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD }
  });
}

// Auth middleware
function authenticateToken(req, res, next) {
  var authHeader = req.headers['authorization'];
  var token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token gerekli' });
  
  jwt.verify(token, JWT_SECRET, function(err, user) {
    if (err) return res.status(403).json({ error: 'Gecersiz token' });
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin yetkisi gerekli' });
  next();
}

// AUTH ROUTES
app.post('/api/auth/login', function(req, res) {
  try {
    var username = req.body.username;
    var password = req.body.password;
    var users = readDB('users');
    var user = users.find(function(u) { return u.username === username && u.is_active; });
    
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Gecersiz kullanici adi veya sifre' });
    }
    
    var token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, full_name: user.full_name },
      JWT_SECRET, { expiresIn: '24h' }
    );
    
    res.json({ token: token, user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Giris yapilamadi' });
  }
});

app.get('/api/auth/me', authenticateToken, function(req, res) {
  var users = readDB('users');
  var user = users.find(function(u) { return u.id === req.user.id; });
  if (user) res.json({ id: user.id, username: user.username, full_name: user.full_name, role: user.role });
  else res.status(404).json({ error: 'Kullanici bulunamadi' });
});

// USER ROUTES
app.get('/api/users', authenticateToken, requireAdmin, function(req, res) {
  var users = readDB('users').map(function(u) {
    return { id: u.id, username: u.username, full_name: u.full_name, role: u.role, created_at: u.created_at, is_active: u.is_active };
  });
  res.json(users);
});

app.post('/api/users', authenticateToken, requireAdmin, function(req, res) {
  try {
    var username = req.body.username;
    var password = req.body.password;
    var full_name = req.body.full_name;
    var users = readDB('users');
    if (users.find(function(u) { return u.username === username; })) {
      return res.status(400).json({ error: 'Bu kullanici adi zaten kullaniliyor' });
    }
    var newUser = {
      id: uuidv4(), username: username, password: bcrypt.hashSync(password, 10), full_name: full_name, role: 'user',
      created_at: new Date().toISOString(), is_active: 1
    };
    users.push(newUser);
    writeDB('users', users);
    res.json({ id: newUser.id, username: username, full_name: full_name, role: 'user' });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: 'Kullanici olusturulamadi' });
  }
});

app.delete('/api/users/:id', authenticateToken, requireAdmin, function(req, res) {
  try {
    var id = req.params.id;
    var users = readDB('users');
    var user = users.find(function(u) { return u.id === id; });
    if (user && user.role === 'admin') return res.status(400).json({ error: 'Admin kullanici silinemez' });
    users = users.filter(function(u) { return u.id !== id; });
    writeDB('users', users);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Kullanici silinemedi' });
  }
});

// TEMPLATE ROUTES
app.get('/api/templates', authenticateToken, function(req, res) {
  var templates = readDB('templates').filter(function(t) { return t.is_active; });
  var users = readDB('users');
  templates.forEach(function(t) {
    var creator = users.find(function(u) { return u.id === t.created_by; });
    t.created_by_name = creator ? creator.full_name : null;
  });
  res.json(templates);
});

app.post('/api/templates', authenticateToken, requireAdmin, function(req, res) {
  try {
    var templates = readDB('templates');
    var newTemplate = {
      id: uuidv4(), name: req.body.name, subject: req.body.subject, body: req.body.body, variables: req.body.variables || [],
      created_by: req.user.id, created_at: new Date().toISOString(), is_active: 1
    };
    templates.push(newTemplate);
    writeDB('templates', templates);
    res.json(newTemplate);
  } catch (error) {
    res.status(500).json({ error: 'Taslak olusturulamadi' });
  }
});

app.delete('/api/templates/:id', authenticateToken, requireAdmin, function(req, res) {
  try {
    var templates = readDB('templates');
    var idx = templates.findIndex(function(t) { return t.id === req.params.id; });
    if (idx !== -1) { templates[idx].is_active = 0; writeDB('templates', templates); }
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Taslak silinemedi' });
  }
});

// EMAIL ROUTES
app.get('/api/emails', authenticateToken, function(req, res) {
  var emails = readDB('emails');
  var users = readDB('users');
  var templates = readDB('templates');
  
  if (req.user.role !== 'admin') {
    emails = emails.filter(function(e) { return e.user_id === req.user.id; });
  }
  
  emails.forEach(function(e) {
    var sender = users.find(function(u) { return u.id === e.user_id; });
    var template = templates.find(function(t) { return t.id === e.template_id; });
    e.sender_name = sender ? sender.full_name : null;
    e.template_name = template ? template.name : null;
  });
  
  emails.sort(function(a, b) { return new Date(b.sent_at) - new Date(a.sent_at); });
  res.json(emails);
});

app.post('/api/emails/send', authenticateToken, function(req, res) {
  var template_id = req.body.template_id;
  var recipient_email = req.body.recipient_email;
  var recipient_name = req.body.recipient_name;
  var variables = req.body.variables || {};
  
  var templates = readDB('templates');
  var template = templates.find(function(t) { return t.id === template_id; });
  if (!template) return res.status(404).json({ error: 'Taslak bulunamadi' });
  
  var subject = template.subject;
  var body = template.body;
  Object.keys(variables).forEach(function(key) {
    var regex = new RegExp('\\{' + key + '\\}', 'g');
    subject = subject.replace(regex, variables[key]);
    body = body.replace(regex, variables[key]);
  });
  
  var emailId = uuidv4();
  var newEmail = {
    id: emailId, user_id: req.user.id, template_id: template_id, recipient_email: recipient_email, recipient_name: recipient_name,
    subject: subject, body: body, variables_used: variables, status: 'sending', sent_at: new Date().toISOString()
  };
  
  var emails = readDB('emails');
  emails.push(newEmail);
  writeDB('emails', emails);
  
  var transporter = createTransporter();
  if (!transporter) {
    emails = readDB('emails');
    var idx = emails.findIndex(function(e) { return e.id === emailId; });
    if (idx !== -1) { emails[idx].status = 'failed'; emails[idx].error_message = 'Gmail yapilandirilmamis'; writeDB('emails', emails); }
    return res.status(500).json({ error: 'Gmail yapilandirilmamis' });
  }
  
  transporter.sendMail({
    from: '"G360 AI" <' + GMAIL_USER + '>',
    to: recipient_email,
    subject: subject,
    html: body
  }).then(function() {
    var emails2 = readDB('emails');
    var idx2 = emails2.findIndex(function(e) { return e.id === emailId; });
    if (idx2 !== -1) { emails2[idx2].status = 'sent'; writeDB('emails', emails2); }
    res.json({ success: true, message: 'Mail basariyla gonderildi' });
  }).catch(function(err) {
    var emails3 = readDB('emails');
    var idx3 = emails3.findIndex(function(e) { return e.id === emailId; });
    if (idx3 !== -1) { emails3[idx3].status = 'failed'; emails3[idx3].error_message = err.message; writeDB('emails', emails3); }
    res.status(500).json({ error: 'Mail gonderilemedi', details: err.message });
  });
});

// STATS ROUTE
app.get('/api/stats', authenticateToken, requireAdmin, function(req, res) {
  var emails = readDB('emails');
  var users = readDB('users');
  var templates = readDB('templates');
  
  res.json({
    totalEmails: emails.length,
    sentEmails: emails.filter(function(e) { return e.status === 'sent'; }).length,
    failedEmails: emails.filter(function(e) { return e.status === 'failed'; }).length,
    totalUsers: users.filter(function(u) { return u.role === 'user'; }).length,
    totalTemplates: templates.filter(function(t) { return t.is_active; }).length,
    recentEmails: emails.sort(function(a, b) { return new Date(b.sent_at) - new Date(a.sent_at); }).slice(0, 5)
  });
});

// FRONTEND
app.get('/', function(req, res) {
  res.send(getFrontendHTML());
});

app.get('/health', function(req, res) {
  res.json({ status: 'ok', gmail: GMAIL_USER, configured: !!GMAIL_APP_PASSWORD });
});

app.listen(PORT, function() {
  console.log('G360 Mail System running on port ' + PORT);
  console.log('Gmail: ' + GMAIL_USER);
  console.log('Gmail configured: ' + !!GMAIL_APP_PASSWORD);
});

function getFrontendHTML() {
  return '<!DOCTYPE html>' +
'<html lang="tr">' +
'<head>' +
'<meta charset="UTF-8">' +
'<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
'<title>G360 AI - Mail Sistemi</title>' +
'<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">' +
'<script src="https://cdn.tailwindcss.com"><\/script>' +
'<script>' +
'tailwind.config = {' +
'  theme: {' +
'    extend: {' +
'      colors: {' +
'        primary: { 500:"#14b8a6",600:"#0d9488",700:"#0f766e" },' +
'        secondary: { 500:"#06b6d4",600:"#0891b2" }' +
'      }' +
'    }' +
'  }' +
'}' +
'<\/script>' +
'<style>' +
'body { font-family: "Inter", sans-serif; background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%); min-height: 100vh; }' +
'.glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(71, 85, 105, 0.3); }' +
'.gradient-text { background: linear-gradient(135deg, #14b8a6 0%, #0891b2 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }' +
'.btn-primary { background: linear-gradient(135deg, #0d9488 0%, #0891b2 100%); }' +
'.btn-primary:hover { box-shadow: 0 10px 40px -10px rgba(13, 148, 136, 0.5); }' +
'<\/style>' +
'</head>' +
'<body>' +
'<div id="app"></div>' +
'<script>' +
'var currentUser = null;' +
'var currentPage = "login";' +
'var currentTemplates = [];' +
'' +
'function getToken() { return localStorage.getItem("token"); }' +
'function setToken(t) { localStorage.setItem("token", t); }' +
'function clearToken() { localStorage.removeItem("token"); localStorage.removeItem("user"); }' +
'function getUser() { var u = localStorage.getItem("user"); return u ? JSON.parse(u) : null; }' +
'function setUser(u) { localStorage.setItem("user", JSON.stringify(u)); currentUser = u; }' +
'function isAdmin() { return currentUser && currentUser.role === "admin"; }' +
'' +
'function api(endpoint, options) {' +
'  options = options || {};' +
'  var token = getToken();' +
'  var headers = { "Content-Type": "application/json" };' +
'  if (token) headers["Authorization"] = "Bearer " + token;' +
'  options.headers = headers;' +
'  return fetch(endpoint, options).then(function(res) {' +
'    if (res.status === 401 || res.status === 403) { clearToken(); navigate("login"); throw new Error("Unauthorized"); }' +
'    return res.json().then(function(data) {' +
'      if (!res.ok) throw new Error(data.error || "Bir hata olustu");' +
'      return data;' +
'    });' +
'  });' +
'}' +
'' +
'function navigate(page) { currentPage = page; render(); }' +
'' +
'function showToast(msg, type) {' +
'  var t = document.createElement("div");' +
'  t.className = "fixed top-4 right-4 px-6 py-3 rounded-lg text-white z-50 " + (type === "error" ? "bg-red-500" : "bg-emerald-500");' +
'  t.textContent = msg;' +
'  document.body.appendChild(t);' +
'  setTimeout(function() { t.remove(); }, 3000);' +
'}' +
'' +
'function renderLogin() {' +
'  return \'<div class="min-h-screen flex items-center justify-center p-4">\' +' +
'    \'<div class="w-full max-w-md">\' +' +
'    \'<div class="text-center mb-8">\' +' +
'    \'<div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-primary-500 to-secondary-500 flex items-center justify-center">\' +' +
'    \'<svg class="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>\' +' +
'    \'</div>\' +' +
'    \'<h1 class="text-3xl font-bold gradient-text">G360 AI</h1>\' +' +
'    \'<p class="text-slate-400 mt-2">Mail Sistemine Giris Yapin</p>\' +' +
'    \'</div>\' +' +
'    \'<div class="glass rounded-2xl p-8">\' +' +
'    \'<form id="loginForm" class="space-y-5">\' +' +
'    \'<div><label class="block text-sm font-medium text-slate-300 mb-2">Kullanici Adi</label>\' +' +
'    \'<input type="text" id="username" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 focus:outline-none focus:border-primary-500" required></div>\' +' +
'    \'<div><label class="block text-sm font-medium text-slate-300 mb-2">Sifre</label>\' +' +
'    \'<input type="password" id="password" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 focus:outline-none focus:border-primary-500" required></div>\' +' +
'    \'<button type="submit" class="w-full btn-primary text-white font-medium py-3 rounded-lg">Giris Yap</button>\' +' +
'    \'</form></div></div></div>\';' +
'}' +
'' +
'function renderDashboard() {' +
'  return \'<div class="space-y-6">\' +' +
'    \'<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">\' +' +
'    \'<div><h1 class="text-2xl font-bold text-slate-100">Hos Geldin, \' + (currentUser ? currentUser.full_name.split(" ")[0] : "") + \'</h1></div>\' +' +
'    \'<button onclick="navigate(\\\'send\\\')" class="btn-primary text-white px-5 py-2.5 rounded-lg">Yeni Mail Gonder</button>\' +' +
'    \'</div>\' +' +
'    \'<div id="statsContainer" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"><div class="glass rounded-xl p-6 text-slate-400">Yukleniyor...</div></div>\' +' +
'    \'<div class="glass rounded-xl p-6">\' +' +
'    \'<div class="flex items-center justify-between mb-4"><h2 class="text-lg font-semibold text-slate-100">Son Mailler</h2>\' +' +
'    \'<button onclick="navigate(\\\'emails\\\')" class="text-sm text-primary-500">Tumunu Gor</button></div>\' +' +
'    \'<div id="recentEmails">Yukleniyor...</div></div></div>\';' +
'}' +
'' +
'function renderSend() {' +
'  return \'<div class="max-w-4xl mx-auto space-y-6">\' +' +
'    \'<div><h1 class="text-2xl font-bold text-slate-100">Mail Gonder</h1></div>\' +' +
'    \'<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">\' +' +
'    \'<div class="glass rounded-xl p-6">\' +' +
'    \'<form id="sendForm" class="space-y-5">\' +' +
'    \'<div><label class="block text-sm text-slate-300 mb-2">Mail Taslagi</label>\' +' +
'    \'<select id="templateSelect" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200"><option>Yukleniyor...</option></select></div>\' +' +
'    \'<div class="grid grid-cols-2 gap-4">\' +' +
'    \'<div><label class="block text-sm text-slate-300 mb-2">Alici E-posta *</label>\' +' +
'    \'<input type="email" id="recipientEmail" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200" required></div>\' +' +
'    \'<div><label class="block text-sm text-slate-300 mb-2">Alici Adi</label>\' +' +
'    \'<input type="text" id="recipientName" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200"></div></div>\' +' +
'    \'<div id="variablesContainer"></div>\' +' +
'    \'<button type="submit" class="w-full btn-primary text-white py-3 rounded-lg">Mail Gonder</button>\' +' +
'    \'</form></div>\' +' +
'    \'<div class="glass rounded-xl p-6"><h3 class="font-semibold text-slate-200 mb-4">Onizleme</h3>\' +' +
'    \'<div id="previewContainer" class="bg-white rounded-lg overflow-hidden max-h-96 overflow-y-auto"><div class="p-4 text-gray-500">Taslak secin...</div></div></div>\' +' +
'    \'</div></div>\';' +
'}' +
'' +
'function renderEmails() {' +
'  var adminCol = isAdmin() ? \'<th class="text-left py-4 px-6 text-sm text-slate-400">Gonderen</th>\' : "";' +
'  return \'<div class="space-y-6">\' +' +
'    \'<div><h1 class="text-2xl font-bold text-slate-100">\' + (isAdmin() ? "Tum Mailler" : "Gonderdigim Mailler") + \'</h1>\' +' +
'    \'<p class="text-slate-400" id="emailCount">Yukleniyor...</p></div>\' +' +
'    \'<div class="glass rounded-xl overflow-hidden"><table class="w-full">\' +' +
'    \'<thead><tr class="border-b border-slate-700 bg-slate-800/50">\' +' +
'    \'<th class="text-left py-4 px-6 text-sm text-slate-400">Alici</th>\' + adminCol +' +
'    \'<th class="text-left py-4 px-6 text-sm text-slate-400">Konu</th>\' +' +
'    \'<th class="text-left py-4 px-6 text-sm text-slate-400">Durum</th>\' +' +
'    \'<th class="text-left py-4 px-6 text-sm text-slate-400">Tarih</th></tr></thead>\' +' +
'    \'<tbody id="emailsTable"><tr><td colspan="5" class="py-8 text-center text-slate-400">Yukleniyor...</td></tr></tbody>\' +' +
'    \'</table></div></div>\';' +
'}' +
'' +
'function renderUsers() {' +
'  return \'<div class="space-y-6">\' +' +
'    \'<div class="flex justify-between items-center">\' +' +
'    \'<div><h1 class="text-2xl font-bold text-slate-100">Kullanicilar</h1><p class="text-slate-400" id="userCount"></p></div>\' +' +
'    \'<button onclick="showUserModal()" class="btn-primary text-white px-5 py-2.5 rounded-lg">+ Yeni Kullanici</button></div>\' +' +
'    \'<div class="glass rounded-xl overflow-hidden"><table class="w-full">\' +' +
'    \'<thead><tr class="border-b border-slate-700 bg-slate-800/50">\' +' +
'    \'<th class="text-left py-4 px-6 text-sm text-slate-400">Kullanici</th>\' +' +
'    \'<th class="text-left py-4 px-6 text-sm text-slate-400">Kullanici Adi</th>\' +' +
'    \'<th class="text-left py-4 px-6 text-sm text-slate-400">Rol</th>\' +' +
'    \'<th class="text-right py-4 px-6 text-sm text-slate-400">Islemler</th></tr></thead>\' +' +
'    \'<tbody id="usersTable"></tbody></table></div></div>\' +' +
'    \'<div id="userModal" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 hidden">\' +' +
'    \'<div class="glass rounded-xl p-6 max-w-md w-full mx-4">\' +' +
'    \'<h3 class="text-lg font-semibold text-slate-100 mb-4">Yeni Kullanici</h3>\' +' +
'    \'<form id="userForm" class="space-y-4">\' +' +
'    \'<div><label class="block text-sm text-slate-300 mb-2">Kullanici Adi *</label><input type="text" id="newUsername" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200" required></div>\' +' +
'    \'<div><label class="block text-sm text-slate-300 mb-2">Ad Soyad *</label><input type="text" id="newFullName" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200" required></div>\' +' +
'    \'<div><label class="block text-sm text-slate-300 mb-2">Sifre *</label><input type="password" id="newPassword" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200" required></div>\' +' +
'    \'<div class="flex gap-3"><button type="button" onclick="hideUserModal()" class="flex-1 bg-slate-700 text-slate-200 py-3 rounded-lg">Iptal</button>\' +' +
'    \'<button type="submit" class="flex-1 btn-primary text-white py-3 rounded-lg">Kaydet</button></div></form></div></div>\';' +
'}' +
'' +
'function renderTemplates() {' +
'  return \'<div class="space-y-6">\' +' +
'    \'<div class="flex justify-between items-center">\' +' +
'    \'<div><h1 class="text-2xl font-bold text-slate-100">Taslaklar</h1><p class="text-slate-400" id="templateCount"></p></div>\' +' +
'    \'<button onclick="showTemplateModal()" class="btn-primary text-white px-5 py-2.5 rounded-lg">+ Yeni Taslak</button></div>\' +' +
'    \'<div id="templatesGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"></div></div>\' +' +
'    \'<div id="templateModal" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 hidden overflow-y-auto py-8">\' +' +
'    \'<div class="glass rounded-xl p-6 max-w-2xl w-full mx-4">\' +' +
'    \'<h3 class="text-lg font-semibold text-slate-100 mb-4">Yeni Taslak</h3>\' +' +
'    \'<form id="templateForm" class="space-y-4">\' +' +
'    \'<div><label class="block text-sm text-slate-300 mb-2">Taslak Adi *</label><input type="text" id="tplName" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200" required></div>\' +' +
'    \'<div><label class="block text-sm text-slate-300 mb-2">Mail Konusu *</label><input type="text" id="tplSubject" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200" required></div>\' +' +
'    \'<div><label class="block text-sm text-slate-300 mb-2">Degiskenler (virgul ile ayirin)</label><input type="text" id="tplVariables" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200" placeholder="alici_adi, fiyat"></div>\' +' +
'    \'<div><label class="block text-sm text-slate-300 mb-2">Icerik (HTML) *</label><textarea id="tplBody" rows="10" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 font-mono text-sm" required></textarea></div>\' +' +
'    \'<div class="flex gap-3"><button type="button" onclick="hideTemplateModal()" class="flex-1 bg-slate-700 text-slate-200 py-3 rounded-lg">Iptal</button>\' +' +
'    \'<button type="submit" class="flex-1 btn-primary text-white py-3 rounded-lg">Kaydet</button></div></form></div></div>\';' +
'}' +
'' +
'function renderLayout(content) {' +
'  var navItems = [' +
'    { id: "dashboard", label: "Dashboard" },' +
'    { id: "send", label: "Mail Gonder" },' +
'    { id: "emails", label: "Mailler" }' +
'  ];' +
'  var adminItems = [' +
'    { id: "templates", label: "Taslaklar" },' +
'    { id: "users", label: "Kullanicilar" }' +
'  ];' +
'  ' +
'  var navHtml = "";' +
'  for (var i = 0; i < navItems.length; i++) {' +
'    var item = navItems[i];' +
'    var active = currentPage === item.id ? "bg-gradient-to-r from-primary-600/20 to-secondary-600/20 text-primary-500" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50";' +
'    navHtml += \'<button onclick="navigate(\\\'\' + item.id + \'\\\')" class="w-full flex items-center gap-3 px-4 py-3 rounded-lg \' + active + \'">\' + item.label + \'</button>\';' +
'  }' +
'  ' +
'  var adminHtml = "";' +
'  if (isAdmin()) {' +
'    adminHtml = \'<p class="text-xs font-semibold text-slate-500 uppercase px-4 mt-6 mb-2">Yonetim</p>\';' +
'    for (var j = 0; j < adminItems.length; j++) {' +
'      var aitem = adminItems[j];' +
'      var aactive = currentPage === aitem.id ? "bg-gradient-to-r from-primary-600/20 to-secondary-600/20 text-primary-500" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50";' +
'      adminHtml += \'<button onclick="navigate(\\\'\' + aitem.id + \'\\\')" class="w-full flex items-center gap-3 px-4 py-3 rounded-lg \' + aactive + \'">\' + aitem.label + \'</button>\';' +
'    }' +
'  }' +
'  ' +
'  return \'<div class="min-h-screen flex">\' +' +
'    \'<aside class="w-64 bg-slate-900/95 border-r border-slate-800 hidden lg:flex flex-col">\' +' +
'    \'<div class="p-6 border-b border-slate-800">\' +' +
'    \'<h1 class="text-xl font-bold gradient-text">G360 AI Mail</h1></div>\' +' +
'    \'<nav class="flex-1 p-4 space-y-1">\' +' +
'    \'<p class="text-xs font-semibold text-slate-500 uppercase px-4 mb-2">Menu</p>\' + navHtml + adminHtml + \'</nav>\' +' +
'    \'<div class="p-4 border-t border-slate-800">\' +' +
'    \'<div class="flex items-center gap-3 px-4 py-3 rounded-lg bg-slate-800/50">\' +' +
'    \'<div class="w-10 h-10 rounded-full bg-gradient-to-br from-primary-500 to-secondary-500 flex items-center justify-center text-white font-bold">\' + (currentUser ? currentUser.full_name.charAt(0).toUpperCase() : "?") + \'</div>\' +' +
'    \'<div class="flex-1"><p class="font-medium text-slate-200">\' + (currentUser ? currentUser.full_name : "") + \'</p>\' +' +
'    \'<p class="text-xs text-slate-500">\' + (isAdmin() ? "Yonetici" : "Kullanici") + \'</p></div>\' +' +
'    \'<button onclick="logout()" class="p-2 text-slate-400 hover:text-red-400" title="Cikis">X</button>\' +' +
'    \'</div></div></aside>\' +' +
'    \'<main class="flex-1 p-4 lg:p-8 overflow-y-auto">\' + content + \'</main></div>\';' +
'}' +
'' +
'function render() {' +
'  var app = document.getElementById("app");' +
'  if (currentPage === "login") {' +
'    app.innerHTML = renderLogin();' +
'    var form = document.getElementById("loginForm");' +
'    if (form) form.addEventListener("submit", handleLogin);' +
'  } else {' +
'    var content = "";' +
'    if (currentPage === "dashboard") content = renderDashboard();' +
'    else if (currentPage === "send") content = renderSend();' +
'    else if (currentPage === "emails") content = renderEmails();' +
'    else if (currentPage === "users") content = renderUsers();' +
'    else if (currentPage === "templates") content = renderTemplates();' +
'    else content = renderDashboard();' +
'    app.innerHTML = renderLayout(content);' +
'    loadPageData();' +
'  }' +
'}' +
'' +
'function loadPageData() {' +
'  if (currentPage === "dashboard") {' +
'    Promise.all([' +
'      isAdmin() ? api("/api/stats") : Promise.resolve(null),' +
'      api("/api/emails")' +
'    ]).then(function(results) {' +
'      var stats = results[0];' +
'      var emails = results[1];' +
'      if (!stats) {' +
'        stats = {' +
'          totalEmails: emails.length,' +
'          sentEmails: emails.filter(function(e) { return e.status === "sent"; }).length,' +
'          failedEmails: emails.filter(function(e) { return e.status === "failed"; }).length' +
'        };' +
'      }' +
'      var statsHtml = \'<div class="glass rounded-xl p-6"><p class="text-slate-400 text-sm">Toplam</p><p class="text-3xl font-bold text-slate-100">\' + stats.totalEmails + \'</p></div>\' +' +
'        \'<div class="glass rounded-xl p-6"><p class="text-slate-400 text-sm">Basarili</p><p class="text-3xl font-bold text-emerald-400">\' + stats.sentEmails + \'</p></div>\' +' +
'        \'<div class="glass rounded-xl p-6"><p class="text-slate-400 text-sm">Basarisiz</p><p class="text-3xl font-bold text-red-400">\' + stats.failedEmails + \'</p></div>\';' +
'      if (isAdmin() && stats.totalUsers !== undefined) {' +
'        statsHtml += \'<div class="glass rounded-xl p-6"><p class="text-slate-400 text-sm">Kullanicilar</p><p class="text-3xl font-bold text-purple-400">\' + stats.totalUsers + \'</p></div>\';' +
'      }' +
'      document.getElementById("statsContainer").innerHTML = statsHtml;' +
'      ' +
'      var recent = emails.slice(0, 5);' +
'      var recentHtml = "";' +
'      if (recent.length === 0) {' +
'        recentHtml = \'<p class="text-slate-500 text-center py-4">Henuz mail gonderilmemis</p>\';' +
'      } else {' +
'        for (var i = 0; i < recent.length; i++) {' +
'          var e = recent[i];' +
'          var statusClass = e.status === "sent" ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400";' +
'          var statusText = e.status === "sent" ? "Gonderildi" : "Basarisiz";' +
'          recentHtml += \'<div class="flex items-center justify-between py-3 border-b border-slate-700 last:border-0">\' +' +
'            \'<div><p class="text-slate-200">\' + (e.recipient_name || e.recipient_email) + \'</p>\' +' +
'            \'<p class="text-xs text-slate-500">\' + e.subject + \'</p></div>\' +' +
'            \'<span class="px-2 py-1 rounded-full text-xs \' + statusClass + \'">\' + statusText + \'</span></div>\';' +
'        }' +
'      }' +
'      document.getElementById("recentEmails").innerHTML = recentHtml;' +
'    }).catch(function(err) { console.error(err); });' +
'  }' +
'  ' +
'  if (currentPage === "send") {' +
'    api("/api/templates").then(function(templates) {' +
'      currentTemplates = templates;' +
'      var select = document.getElementById("templateSelect");' +
'      var opts = "";' +
'      for (var i = 0; i < templates.length; i++) {' +
'        opts += \'<option value="\' + templates[i].id + \'">\' + templates[i].name + \'</option>\';' +
'      }' +
'      select.innerHTML = opts;' +
'      select.addEventListener("change", updateSendForm);' +
'      document.getElementById("sendForm").addEventListener("submit", handleSendEmail);' +
'      updateSendForm();' +
'    });' +
'  }' +
'  ' +
'  if (currentPage === "emails") {' +
'    api("/api/emails").then(function(emails) {' +
'      document.getElementById("emailCount").textContent = emails.length + " mail";' +
'      var html = "";' +
'      if (emails.length === 0) {' +
'        html = \'<tr><td colspan="5" class="py-8 text-center text-slate-400">Henuz mail gonderilmemis</td></tr>\';' +
'      } else {' +
'        for (var i = 0; i < emails.length; i++) {' +
'          var e = emails[i];' +
'          var statusClass = e.status === "sent" ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400";' +
'          var statusText = e.status === "sent" ? "Gonderildi" : "Basarisiz";' +
'          var adminCol = isAdmin() ? \'<td class="py-4 px-6 text-slate-300">\' + (e.sender_name || "-") + \'</td>\' : "";' +
'          html += \'<tr class="border-b border-slate-800 hover:bg-slate-800/30">\' +' +
'            \'<td class="py-4 px-6"><p class="text-slate-200">\' + (e.recipient_name || "-") + \'</p><p class="text-xs text-slate-500">\' + e.recipient_email + \'</p></td>\' + adminCol +' +
'            \'<td class="py-4 px-6 text-slate-300">\' + e.subject + \'</td>\' +' +
'            \'<td class="py-4 px-6"><span class="px-2 py-1 rounded-full text-xs \' + statusClass + \'">\' + statusText + \'</span></td>\' +' +
'            \'<td class="py-4 px-6 text-slate-400 text-sm">\' + new Date(e.sent_at).toLocaleString("tr-TR") + \'</td></tr>\';' +
'        }' +
'      }' +
'      document.getElementById("emailsTable").innerHTML = html;' +
'    });' +
'  }' +
'  ' +
'  if (currentPage === "users") {' +
'    api("/api/users").then(function(users) {' +
'      var userCount = users.filter(function(u) { return u.role !== "admin"; }).length;' +
'      document.getElementById("userCount").textContent = userCount + " kullanici";' +
'      var html = "";' +
'      for (var i = 0; i < users.length; i++) {' +
'        var u = users[i];' +
'        var roleClass = u.role === "admin" ? "bg-amber-500/20 text-amber-400" : "bg-slate-700 text-slate-300";' +
'        var roleText = u.role === "admin" ? "Admin" : "Kullanici";' +
'        var delBtn = u.role !== "admin" ? \'<button onclick="deleteUser(\\\'\' + u.id + \'\\\')" class="text-red-400 hover:text-red-300 text-sm">Sil</button>\' : "";' +
'        html += \'<tr class="border-b border-slate-800">\' +' +
'          \'<td class="py-4 px-6"><div class="flex items-center gap-3"><div class="w-10 h-10 rounded-full bg-gradient-to-br from-primary-500 to-secondary-500 flex items-center justify-center text-white font-bold">\' + u.full_name.charAt(0).toUpperCase() + \'</div><span class="text-slate-200">\' + u.full_name + \'</span></div></td>\' +' +
'          \'<td class="py-4 px-6 text-slate-400">\' + u.username + \'</td>\' +' +
'          \'<td class="py-4 px-6"><span class="px-2 py-1 rounded-full text-xs \' + roleClass + \'">\' + roleText + \'</span></td>\' +' +
'          \'<td class="py-4 px-6 text-right">\' + delBtn + \'</td></tr>\';' +
'      }' +
'      document.getElementById("usersTable").innerHTML = html;' +
'      document.getElementById("userForm").addEventListener("submit", handleAddUser);' +
'    });' +
'  }' +
'  ' +
'  if (currentPage === "templates") {' +
'    api("/api/templates").then(function(templates) {' +
'      document.getElementById("templateCount").textContent = templates.length + " taslak";' +
'      var html = "";' +
'      if (templates.length === 0) {' +
'        html = \'<div class="glass rounded-xl p-6 text-slate-400">Henuz taslak yok</div>\';' +
'      } else {' +
'        for (var i = 0; i < templates.length; i++) {' +
'          var t = templates[i];' +
'          var vars = "";' +
'          if (t.variables && t.variables.length > 0) {' +
'            for (var j = 0; j < Math.min(t.variables.length, 3); j++) {' +
'              vars += \'<span class="px-2 py-1 rounded bg-slate-700/50 text-xs text-slate-400">\' + t.variables[j] + \'</span> \';' +
'            }' +
'          }' +
'          html += \'<div class="glass rounded-xl p-6">\' +' +
'            \'<div class="flex items-start justify-between mb-3">\' +' +
'            \'<div class="p-2 rounded-lg bg-amber-500/20 text-amber-400">T</div>\' +' +
'            \'<button onclick="deleteTemplate(\\\'\' + t.id + \'\\\')" class="text-slate-400 hover:text-red-400">X</button></div>\' +' +
'            \'<h3 class="font-semibold text-slate-200 mb-2">\' + t.name + \'</h3>\' +' +
'            \'<p class="text-sm text-slate-400 mb-4 truncate">\' + t.subject + \'</p>\' +' +
'            \'<div class="flex flex-wrap gap-1">\' + vars + \'</div></div>\';' +
'        }' +
'      }' +
'      document.getElementById("templatesGrid").innerHTML = html;' +
'      document.getElementById("templateForm").addEventListener("submit", handleAddTemplate);' +
'    });' +
'  }' +
'}' +
'' +
'function updateSendForm() {' +
'  var templateId = document.getElementById("templateSelect").value;' +
'  var template = null;' +
'  for (var i = 0; i < currentTemplates.length; i++) {' +
'    if (currentTemplates[i].id === templateId) { template = currentTemplates[i]; break; }' +
'  }' +
'  if (!template) return;' +
'  ' +
'  var varsHtml = "";' +
'  if (template.variables && template.variables.length > 0) {' +
'    varsHtml = \'<div class="space-y-3"><label class="block text-sm font-medium text-slate-300">Degiskenler</label>\';' +
'    for (var i = 0; i < template.variables.length; i++) {' +
'      var v = template.variables[i];' +
'      varsHtml += \'<div><label class="block text-xs text-slate-400 mb-1">\' + v + \'</label>\' +' +
'        \'<input type="text" data-var="\' + v + \'" class="var-input w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-2 text-slate-200 text-sm"></div>\';' +
'    }' +
'    varsHtml += \'</div>\';' +
'  }' +
'  document.getElementById("variablesContainer").innerHTML = varsHtml;' +
'  ' +
'  var varInputs = document.querySelectorAll(".var-input");' +
'  for (var j = 0; j < varInputs.length; j++) {' +
'    varInputs[j].addEventListener("input", updatePreview);' +
'  }' +
'  updatePreview();' +
'}' +
'' +
'function updatePreview() {' +
'  var templateId = document.getElementById("templateSelect").value;' +
'  var template = null;' +
'  for (var i = 0; i < currentTemplates.length; i++) {' +
'    if (currentTemplates[i].id === templateId) { template = currentTemplates[i]; break; }' +
'  }' +
'  if (!template) return;' +
'  ' +
'  var body = template.body;' +
'  var varInputs = document.querySelectorAll(".var-input");' +
'  for (var j = 0; j < varInputs.length; j++) {' +
'    var input = varInputs[j];' +
'    var varName = input.getAttribute("data-var");' +
'    var value = input.value || "[" + varName + "]";' +
'    body = body.split("{" + varName + "}").join(value);' +
'  }' +
'  document.getElementById("previewContainer").innerHTML = \'<div class="p-4">\' + body + \'</div>\';' +
'}' +
'' +
'function handleLogin(e) {' +
'  e.preventDefault();' +
'  var username = document.getElementById("username").value;' +
'  var password = document.getElementById("password").value;' +
'  api("/api/auth/login", { method: "POST", body: JSON.stringify({ username: username, password: password }) })' +
'    .then(function(data) {' +
'      setToken(data.token);' +
'      setUser(data.user);' +
'      showToast("Giris basarili!");' +
'      navigate("dashboard");' +
'    })' +
'    .catch(function(err) { showToast(err.message, "error"); });' +
'}' +
'' +
'function handleSendEmail(e) {' +
'  e.preventDefault();' +
'  var variables = {};' +
'  var varInputs = document.querySelectorAll(".var-input");' +
'  for (var i = 0; i < varInputs.length; i++) {' +
'    var input = varInputs[i];' +
'    variables[input.getAttribute("data-var")] = input.value;' +
'  }' +
'  var data = {' +
'    template_id: document.getElementById("templateSelect").value,' +
'    recipient_email: document.getElementById("recipientEmail").value,' +
'    recipient_name: document.getElementById("recipientName").value,' +
'    variables: variables' +
'  };' +
'  api("/api/emails/send", { method: "POST", body: JSON.stringify(data) })' +
'    .then(function() { showToast("Mail basariyla gonderildi!"); navigate("emails"); })' +
'    .catch(function(err) { showToast(err.message, "error"); });' +
'}' +
'' +
'function showUserModal() { document.getElementById("userModal").classList.remove("hidden"); }' +
'function hideUserModal() { document.getElementById("userModal").classList.add("hidden"); }' +
'function showTemplateModal() { document.getElementById("templateModal").classList.remove("hidden"); }' +
'function hideTemplateModal() { document.getElementById("templateModal").classList.add("hidden"); }' +
'' +
'function handleAddUser(e) {' +
'  e.preventDefault();' +
'  var data = {' +
'    username: document.getElementById("newUsername").value,' +
'    full_name: document.getElementById("newFullName").value,' +
'    password: document.getElementById("newPassword").value' +
'  };' +
'  api("/api/users", { method: "POST", body: JSON.stringify(data) })' +
'    .then(function() { showToast("Kullanici olusturuldu!"); hideUserModal(); loadPageData(); })' +
'    .catch(function(err) { showToast(err.message, "error"); });' +
'}' +
'' +
'function deleteUser(id) {' +
'  if (!confirm("Bu kullaniciyi silmek istediginize emin misiniz?")) return;' +
'  api("/api/users/" + id, { method: "DELETE" })' +
'    .then(function() { showToast("Kullanici silindi"); loadPageData(); })' +
'    .catch(function(err) { showToast(err.message, "error"); });' +
'}' +
'' +
'function handleAddTemplate(e) {' +
'  e.preventDefault();' +
'  var varsStr = document.getElementById("tplVariables").value;' +
'  var variables = varsStr ? varsStr.split(",").map(function(v) { return v.trim(); }).filter(function(v) { return v; }) : [];' +
'  var data = {' +
'    name: document.getElementById("tplName").value,' +
'    subject: document.getElementById("tplSubject").value,' +
'    body: document.getElementById("tplBody").value,' +
'    variables: variables' +
'  };' +
'  api("/api/templates", { method: "POST", body: JSON.stringify(data) })' +
'    .then(function() { showToast("Taslak olusturuldu!"); hideTemplateModal(); loadPageData(); })' +
'    .catch(function(err) { showToast(err.message, "error"); });' +
'}' +
'' +
'function deleteTemplate(id) {' +
'  if (!confirm("Bu taslagi silmek istediginize emin misiniz?")) return;' +
'  api("/api/templates/" + id, { method: "DELETE" })' +
'    .then(function() { showToast("Taslak silindi"); loadPageData(); })' +
'    .catch(function(err) { showToast(err.message, "error"); });' +
'}' +
'' +
'function logout() { clearToken(); currentUser = null; navigate("login"); }' +
'' +
'function init() {' +
'  var token = getToken();' +
'  var user = getUser();' +
'  if (token && user) { currentUser = user; navigate("dashboard"); }' +
'  else navigate("login");' +
'}' +
'' +
'init();' +
'<\/script>' +
'</body>' +
'</html>';
}
