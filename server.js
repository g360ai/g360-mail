const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Environment variables
const GMAIL_USER = process.env.GMAIL_USER || 'burak@g360.ai';
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || '';
const JWT_SECRET = process.env.JWT_SECRET || 'g360-mail-secret-key-change-this';

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Database setup - use /tmp for Render.com (persistent disk can be added later)
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'mail_system.db');
const db = new Database(dbPath);

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    variables TEXT,
    created_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER DEFAULT 1,
    FOREIGN KEY (created_by) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS sent_emails (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    template_id TEXT,
    recipient_email TEXT NOT NULL,
    recipient_name TEXT,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    variables_used TEXT,
    status TEXT DEFAULT 'pending',
    error_message TEXT,
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (template_id) REFERENCES templates(id)
  );
`);

// Create admin user if not exists
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('burakkaan48');
if (!adminExists) {
  const hashedPassword = bcrypt.hashSync('admin123', 10);
  db.prepare(`
    INSERT INTO users (id, username, password, full_name, role)
    VALUES (?, ?, ?, ?, ?)
  `).run(uuidv4(), 'burakkaan48', hashedPassword, 'Burak Kaan', 'admin');
  console.log('Admin user created: burakkaan48 / admin123');
}

// Create default template
const templateExists = db.prepare('SELECT id FROM templates LIMIT 1').get();
if (!templateExists) {
  const adminUser = db.prepare('SELECT id FROM users WHERE username = ?').get('burakkaan48');
  const defaultTemplate = {
    id: uuidv4(),
    name: 'Google Street View Teklif',
    subject: 'Google Street View 360° Çekim Teklifi - {isletme_adi}',
    body: `<div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 700px; margin: 0 auto; padding: 30px; background: #ffffff;">
  <div style="text-align: center; margin-bottom: 30px;">
    <img src="https://g360.ai/logo.png" alt="G360 AI" style="height: 60px;" />
  </div>
  
  <p style="font-size: 16px; color: #333;">Sayın <strong>{alici_adi}</strong>,</p>
  
  <p style="font-size: 15px; color: #444; line-height: 1.7;">
    Geçtiğimiz görüşmemiz doğrultusunda, <strong>{isletme_adi}</strong> için Google Street View kapsamında sunabileceğimiz 360° iç mekân çekim hizmetiyle ilgili teklifimizi aşağıda bilgilerinize sunarız.
  </p>
  
  <p style="font-size: 15px; color: #444; line-height: 1.7;">
    Google onaylı bu çekimler sayesinde işletmenizin dijital görünürlüğü, Google Haritalar ve Arama sonuçlarında doğrudan artacak; müşterileriniz tesisinizi çevrim içi ortamda detaylı şekilde gezebilecektir.
  </p>
  
  <div style="background: linear-gradient(135deg, #0d9488 0%, #0891b2 100%); color: white; padding: 20px; border-radius: 10px; margin: 25px 0;">
    <h3 style="margin: 0 0 15px 0; font-size: 18px;">📸 Hizmet İçeriği</h3>
    <ul style="margin: 0; padding-left: 20px; line-height: 1.8;">
      <li>İşletme genelinde iç ve dış mekânların tamamı 360° çekim ile belgelenir</li>
      <li>Tüm görseller Google Street View standartlarına uygun şekilde optimize edilir</li>
      <li>SEO uyumlu, mobil cihazlarla tam uyumlu dijital sanal tur</li>
      <li>Dijital vitrin güçlendirilerek potansiyel müşterilerin karar sürecine etki edilir</li>
    </ul>
  </div>
  
  <div style="background: #f8fafc; border: 2px solid #e2e8f0; border-radius: 10px; padding: 20px; margin: 25px 0;">
    <h3 style="margin: 0 0 15px 0; color: #1e293b; font-size: 18px;">💰 Teklif Detayları</h3>
    <table style="width: 100%; border-collapse: collapse;">
      <tr style="background: #0d9488; color: white;">
        <th style="padding: 12px; text-align: left; border-radius: 5px 0 0 0;">Sahne Sayısı</th>
        <th style="padding: 12px; text-align: right; border-radius: 0 5px 0 0;">Fiyat</th>
      </tr>
      <tr>
        <td style="padding: 12px; border-bottom: 1px solid #e2e8f0;">30 sahneye kadar</td>
        <td style="padding: 12px; border-bottom: 1px solid #e2e8f0; text-align: right; font-weight: bold; color: #0d9488;">{fiyat_30} + KDV</td>
      </tr>
      <tr>
        <td style="padding: 12px; border-bottom: 1px solid #e2e8f0;">30-50 sahne arası</td>
        <td style="padding: 12px; border-bottom: 1px solid #e2e8f0; text-align: right; font-weight: bold; color: #0d9488;">{fiyat_50} + KDV</td>
      </tr>
      <tr>
        <td style="padding: 12px;">50 sahne ve üzeri</td>
        <td style="padding: 12px; text-align: right; font-weight: bold; color: #0d9488;">{fiyat_50_ustu} + KDV</td>
      </tr>
    </table>
    <p style="font-size: 13px; color: #64748b; margin: 15px 0 0 0; font-style: italic;">
      * Her sahne, işletmenizin bir alanını temsil eden 360° bir panorama çekimini ifade eder.
    </p>
  </div>
  
  <p style="font-size: 15px; color: #444; line-height: 1.7;">
    Sahadaki keşif ve planlama süreci sonrasında, toplam sahne sayısı netleştirilerek çekime başlanacaktır.
  </p>
  
  <p style="font-size: 15px; color: #444; line-height: 1.7;">
    İş birliği için şimdiden teşekkür eder, işletmenizin dijital görünürlüğünü birlikte güçlendirmekten mutluluk duyarız.
  </p>
  
  <p style="font-size: 15px; color: #333; margin-top: 30px;">
    Saygılarımızla,
  </p>
  
  <div style="margin-top: 30px; padding-top: 20px; border-top: 2px solid #e2e8f0;">
    <p style="margin: 0; font-weight: bold; color: #0d9488;">G360 AI</p>
    <p style="margin: 5px 0 0 0; font-size: 13px; color: #64748b;">
      🌐 <a href="https://g360.ai" style="color: #0891b2; text-decoration: none;">g360.ai</a>
    </p>
  </div>
</div>`,
    variables: JSON.stringify(['alici_adi', 'isletme_adi', 'fiyat_30', 'fiyat_50', 'fiyat_50_ustu']),
    created_by: adminUser?.id
  };
  
  db.prepare(`
    INSERT INTO templates (id, name, subject, body, variables, created_by)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(defaultTemplate.id, defaultTemplate.name, defaultTemplate.subject, defaultTemplate.body, defaultTemplate.variables, defaultTemplate.created_by);
  console.log('Default template created');
}

// Email transporter
const createTransporter = () => {
  if (!GMAIL_APP_PASSWORD) {
    console.warn('Gmail App Password not configured!');
    return null;
  }
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: GMAIL_USER,
      pass: GMAIL_APP_PASSWORD
    }
  });
};

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Token gerekli' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Geçersiz token' });
    }
    req.user = user;
    next();
  });
};

// Admin middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin yetkisi gerekli' });
  }
  next();
};

// ============ AUTH ROUTES ============

app.post('/api/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ? AND is_active = 1').get(username);
    
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
    }
    
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, full_name: user.full_name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      token,
      user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Giriş yapılırken hata oluştu' });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = db.prepare('SELECT id, username, full_name, role FROM users WHERE id = ?').get(req.user.id);
  res.json(user);
});

// ============ USER ROUTES ============

app.get('/api/users', authenticateToken, requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id, username, full_name, role, created_at, is_active FROM users ORDER BY created_at DESC').all();
  res.json(users);
});

app.post('/api/users', authenticateToken, requireAdmin, (req, res) => {
  try {
    const { username, password, full_name } = req.body;
    const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (exists) {
      return res.status(400).json({ error: 'Bu kullanıcı adı zaten kullanılıyor' });
    }
    const hashedPassword = bcrypt.hashSync(password, 10);
    const id = uuidv4();
    db.prepare('INSERT INTO users (id, username, password, full_name, role) VALUES (?, ?, ?, ?, ?)').run(id, username, hashedPassword, full_name, 'user');
    res.json({ id, username, full_name, role: 'user' });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: 'Kullanıcı oluşturulurken hata oluştu' });
  }
});

app.put('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const { full_name, password, is_active } = req.body;
    if (password) {
      const hashedPassword = bcrypt.hashSync(password, 10);
      db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedPassword, id);
    }
    if (full_name !== undefined) {
      db.prepare('UPDATE users SET full_name = ? WHERE id = ?').run(full_name, id);
    }
    if (is_active !== undefined) {
      db.prepare('UPDATE users SET is_active = ? WHERE id = ?').run(is_active ? 1 : 0, id);
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'Kullanıcı güncellenirken hata oluştu' });
  }
});

app.delete('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const user = db.prepare('SELECT role FROM users WHERE id = ?').get(id);
    if (user?.role === 'admin') {
      return res.status(400).json({ error: 'Admin kullanıcı silinemez' });
    }
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Kullanıcı silinirken hata oluştu' });
  }
});

// ============ TEMPLATE ROUTES ============

app.get('/api/templates', authenticateToken, (req, res) => {
  const templates = db.prepare(`
    SELECT t.*, u.full_name as created_by_name 
    FROM templates t 
    LEFT JOIN users u ON t.created_by = u.id 
    WHERE t.is_active = 1
    ORDER BY t.created_at DESC
  `).all();
  templates.forEach(t => { t.variables = JSON.parse(t.variables || '[]'); });
  res.json(templates);
});

app.get('/api/templates/:id', authenticateToken, (req, res) => {
  const template = db.prepare('SELECT * FROM templates WHERE id = ?').get(req.params.id);
  if (template) { template.variables = JSON.parse(template.variables || '[]'); }
  res.json(template);
});

app.post('/api/templates', authenticateToken, requireAdmin, (req, res) => {
  try {
    const { name, subject, body, variables } = req.body;
    const id = uuidv4();
    db.prepare('INSERT INTO templates (id, name, subject, body, variables, created_by) VALUES (?, ?, ?, ?, ?, ?)').run(id, name, subject, body, JSON.stringify(variables || []), req.user.id);
    res.json({ id, name, subject, body, variables });
  } catch (error) {
    console.error('Create template error:', error);
    res.status(500).json({ error: 'Taslak oluşturulurken hata oluştu' });
  }
});

app.put('/api/templates/:id', authenticateToken, requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const { name, subject, body, variables } = req.body;
    db.prepare('UPDATE templates SET name = ?, subject = ?, body = ?, variables = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(name, subject, body, JSON.stringify(variables || []), id);
    res.json({ success: true });
  } catch (error) {
    console.error('Update template error:', error);
    res.status(500).json({ error: 'Taslak güncellenirken hata oluştu' });
  }
});

app.delete('/api/templates/:id', authenticateToken, requireAdmin, (req, res) => {
  try {
    db.prepare('UPDATE templates SET is_active = 0 WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete template error:', error);
    res.status(500).json({ error: 'Taslak silinirken hata oluştu' });
  }
});

// ============ EMAIL ROUTES ============

app.get('/api/emails', authenticateToken, (req, res) => {
  let emails;
  if (req.user.role === 'admin') {
    emails = db.prepare(`
      SELECT e.*, u.full_name as sender_name, t.name as template_name
      FROM sent_emails e
      LEFT JOIN users u ON e.user_id = u.id
      LEFT JOIN templates t ON e.template_id = t.id
      ORDER BY e.sent_at DESC
    `).all();
  } else {
    emails = db.prepare(`
      SELECT e.*, t.name as template_name
      FROM sent_emails e
      LEFT JOIN templates t ON e.template_id = t.id
      WHERE e.user_id = ?
      ORDER BY e.sent_at DESC
    `).all(req.user.id);
  }
  emails.forEach(e => { e.variables_used = JSON.parse(e.variables_used || '{}'); });
  res.json(emails);
});

app.get('/api/emails/:id', authenticateToken, (req, res) => {
  const email = db.prepare(`
    SELECT e.*, u.full_name as sender_name, t.name as template_name
    FROM sent_emails e
    LEFT JOIN users u ON e.user_id = u.id
    LEFT JOIN templates t ON e.template_id = t.id
    WHERE e.id = ?
  `).get(req.params.id);
  
  if (!email) return res.status(404).json({ error: 'Mail bulunamadı' });
  if (req.user.role !== 'admin' && email.user_id !== req.user.id) {
    return res.status(403).json({ error: 'Bu maili görüntüleme yetkiniz yok' });
  }
  email.variables_used = JSON.parse(email.variables_used || '{}');
  res.json(email);
});

app.post('/api/emails/send', authenticateToken, async (req, res) => {
  try {
    const { template_id, recipient_email, recipient_name, variables } = req.body;
    const template = db.prepare('SELECT * FROM templates WHERE id = ?').get(template_id);
    if (!template) return res.status(404).json({ error: 'Taslak bulunamadı' });
    
    let subject = template.subject;
    let body = template.body;
    for (const [key, value] of Object.entries(variables || {})) {
      const regex = new RegExp(`{${key}}`, 'g');
      subject = subject.replace(regex, value);
      body = body.replace(regex, value);
    }
    
    const emailId = uuidv4();
    db.prepare('INSERT INTO sent_emails (id, user_id, template_id, recipient_email, recipient_name, subject, body, variables_used, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(emailId, req.user.id, template_id, recipient_email, recipient_name, subject, body, JSON.stringify(variables), 'sending');
    
    const transporter = createTransporter();
    if (!transporter) {
      db.prepare('UPDATE sent_emails SET status = ?, error_message = ? WHERE id = ?').run('failed', 'Gmail yapılandırılmamış', emailId);
      return res.status(500).json({ error: 'Gmail yapılandırılmamış. Lütfen admin ile iletişime geçin.' });
    }
    
    try {
      await transporter.sendMail({
        from: `"G360 AI" <${GMAIL_USER}>`,
        to: recipient_email,
        subject: subject,
        html: body
      });
      db.prepare('UPDATE sent_emails SET status = ? WHERE id = ?').run('sent', emailId);
      res.json({ success: true, message: 'Mail başarıyla gönderildi', emailId });
    } catch (emailError) {
      db.prepare('UPDATE sent_emails SET status = ?, error_message = ? WHERE id = ?').run('failed', emailError.message, emailId);
      res.status(500).json({ error: 'Mail gönderilemedi', details: emailError.message, emailId });
    }
  } catch (error) {
    console.error('Send email error:', error);
    res.status(500).json({ error: 'Mail gönderilirken hata oluştu' });
  }
});

// ============ STATS ROUTE ============

app.get('/api/stats', authenticateToken, requireAdmin, (req, res) => {
  const totalEmails = db.prepare('SELECT COUNT(*) as count FROM sent_emails').get().count;
  const sentEmails = db.prepare("SELECT COUNT(*) as count FROM sent_emails WHERE status = 'sent'").get().count;
  const failedEmails = db.prepare("SELECT COUNT(*) as count FROM sent_emails WHERE status = 'failed'").get().count;
  const totalUsers = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'user'").get().count;
  const totalTemplates = db.prepare('SELECT COUNT(*) as count FROM templates WHERE is_active = 1').get().count;
  const recentEmails = db.prepare(`SELECT e.*, u.full_name as sender_name FROM sent_emails e LEFT JOIN users u ON e.user_id = u.id ORDER BY e.sent_at DESC LIMIT 5`).all();
  res.json({ totalEmails, sentEmails, failedEmails, totalUsers, totalTemplates, recentEmails });
});

// ============ FRONTEND ============

const FRONTEND_HTML = `<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>G360 AI - Mail Sistemi</title>
  <link rel="icon" href="https://g360.ai/favicon.ico">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            primary: { 50:'#f0fdfa',100:'#ccfbf1',200:'#99f6e4',300:'#5eead4',400:'#2dd4bf',500:'#14b8a6',600:'#0d9488',700:'#0f766e',800:'#115e59',900:'#134e4a' },
            secondary: { 50:'#ecfeff',100:'#cffafe',200:'#a5f3fc',300:'#67e8f9',400:'#22d3ee',500:'#06b6d4',600:'#0891b2',700:'#0e7490',800:'#155e75',900:'#164e63' }
          },
          fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] }
        }
      }
    }
  </script>
  <style>
    body { font-family: 'Inter', sans-serif; background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%); min-height: 100vh; }
    .glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(71, 85, 105, 0.3); }
    .gradient-text { background: linear-gradient(135deg, #14b8a6 0%, #0891b2 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .btn-primary { background: linear-gradient(135deg, #0d9488 0%, #0891b2 100%); }
    .btn-primary:hover { box-shadow: 0 10px 40px -10px rgba(13, 148, 136, 0.5); transform: translateY(-1px); }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    .animate-fadeIn { animation: fadeIn 0.3s ease-out forwards; }
    ::-webkit-scrollbar { width: 8px; }
    ::-webkit-scrollbar-track { background: #1e293b; }
    ::-webkit-scrollbar-thumb { background: #475569; border-radius: 4px; }
  </style>
</head>
<body>
  <div id="app"></div>
  <script>
    const API = '';
    let currentUser = null;
    let currentPage = 'login';
    
    // Auth
    function getToken() { return localStorage.getItem('token'); }
    function setToken(token) { localStorage.setItem('token', token); }
    function clearToken() { localStorage.removeItem('token'); localStorage.removeItem('user'); }
    function getUser() { const u = localStorage.getItem('user'); return u ? JSON.parse(u) : null; }
    function setUser(user) { localStorage.setItem('user', JSON.stringify(user)); currentUser = user; }
    function isAdmin() { return currentUser?.role === 'admin'; }
    
    async function api(endpoint, options = {}) {
      const token = getToken();
      const headers = { 'Content-Type': 'application/json', ...(token ? { 'Authorization': 'Bearer ' + token } : {}) };
      const res = await fetch(API + endpoint, { ...options, headers });
      if (res.status === 401 || res.status === 403) { clearToken(); navigate('login'); throw new Error('Unauthorized'); }
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Bir hata oluştu');
      return data;
    }
    
    // Router
    function navigate(page, params = {}) {
      currentPage = page;
      window.currentParams = params;
      render();
    }
    
    // Toast
    function showToast(message, type = 'success') {
      const toast = document.createElement('div');
      toast.className = 'fixed top-4 right-4 px-6 py-3 rounded-lg text-white z-50 animate-fadeIn ' + (type === 'error' ? 'bg-red-500' : 'bg-emerald-500');
      toast.textContent = message;
      document.body.appendChild(toast);
      setTimeout(() => toast.remove(), 3000);
    }
    
    // Pages
    function renderLogin() {
      return \`
        <div class="min-h-screen flex items-center justify-center p-4">
          <div class="fixed inset-0 overflow-hidden pointer-events-none">
            <div class="absolute top-1/4 -left-1/4 w-96 h-96 bg-primary-500/20 rounded-full blur-3xl"></div>
            <div class="absolute bottom-1/4 -right-1/4 w-96 h-96 bg-secondary-500/20 rounded-full blur-3xl"></div>
          </div>
          <div class="w-full max-w-md animate-fadeIn">
            <div class="text-center mb-8">
              <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-primary-500 to-secondary-500 flex items-center justify-center">
                <svg class="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
              </div>
              <h1 class="text-3xl font-bold gradient-text">G360 AI</h1>
              <p class="text-slate-400 mt-2">Mail Sistemine Giriş Yapın</p>
            </div>
            <div class="glass rounded-2xl p-8">
              <form id="loginForm" class="space-y-5">
                <div>
                  <label class="block text-sm font-medium text-slate-300 mb-2">Kullanıcı Adı</label>
                  <input type="text" id="username" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 focus:outline-none focus:border-primary-500" placeholder="Kullanıcı adınız" required>
                </div>
                <div>
                  <label class="block text-sm font-medium text-slate-300 mb-2">Şifre</label>
                  <input type="password" id="password" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 focus:outline-none focus:border-primary-500" placeholder="••••••••" required>
                </div>
                <button type="submit" class="w-full btn-primary text-white font-medium py-3 rounded-lg transition-all duration-200">Giriş Yap</button>
              </form>
            </div>
            <p class="text-center text-slate-500 text-sm mt-6">© 2024 G360 AI</p>
          </div>
        </div>
      \`;
    }
    
    function renderDashboard() {
      return \`
        <div class="space-y-6 animate-fadeIn">
          <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h1 class="text-2xl lg:text-3xl font-bold text-slate-100">Hoş Geldin, \${currentUser?.full_name?.split(' ')[0]} 👋</h1>
              <p class="text-slate-400 mt-1">Mail gönderim durumunu buradan takip edebilirsin</p>
            </div>
            <button onclick="navigate('send')" class="btn-primary text-white px-5 py-2.5 rounded-lg flex items-center gap-2 w-fit transition-all duration-200">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"></path></svg>
              Yeni Mail Gönder
            </button>
          </div>
          <div id="statsContainer" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="glass rounded-xl p-6"><div class="text-slate-400 text-sm">Yükleniyor...</div></div>
          </div>
          <div class="glass rounded-xl p-6">
            <div class="flex items-center justify-between mb-4">
              <h2 class="text-lg font-semibold text-slate-100">Son Gönderilen Mailler</h2>
              <button onclick="navigate('emails')" class="text-sm text-primary-400 hover:text-primary-300">Tümünü Gör →</button>
            </div>
            <div id="recentEmails">Yükleniyor...</div>
          </div>
        </div>
      \`;
    }
    
    function renderSend() {
      return \`
        <div class="max-w-4xl mx-auto space-y-6 animate-fadeIn">
          <div>
            <h1 class="text-2xl lg:text-3xl font-bold text-slate-100">Mail Gönder</h1>
            <p class="text-slate-400 mt-1">Taslak seçip değişkenleri doldurarak mail gönderin</p>
          </div>
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div class="glass rounded-xl p-6">
              <form id="sendForm" class="space-y-5">
                <div>
                  <label class="block text-sm font-medium text-slate-300 mb-2">Mail Taslağı</label>
                  <select id="templateSelect" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 focus:outline-none focus:border-primary-500">
                    <option>Yükleniyor...</option>
                  </select>
                </div>
                <div class="grid grid-cols-2 gap-4">
                  <div>
                    <label class="block text-sm font-medium text-slate-300 mb-2">Alıcı E-posta *</label>
                    <input type="email" id="recipientEmail" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 focus:outline-none focus:border-primary-500" placeholder="ornek@firma.com" required>
                  </div>
                  <div>
                    <label class="block text-sm font-medium text-slate-300 mb-2">Alıcı Adı</label>
                    <input type="text" id="recipientName" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 focus:outline-none focus:border-primary-500" placeholder="Ahmet Bey">
                  </div>
                </div>
                <div id="variablesContainer"></div>
                <button type="submit" class="w-full btn-primary text-white font-medium py-3 rounded-lg transition-all duration-200 flex items-center justify-center gap-2">
                  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"></path></svg>
                  Mail Gönder
                </button>
              </form>
            </div>
            <div class="glass rounded-xl p-6">
              <h3 class="font-semibold text-slate-200 mb-4 flex items-center gap-2">
                <svg class="w-5 h-5 text-primary-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>
                Mail Önizlemesi
              </h3>
              <div id="previewContainer" class="bg-white rounded-lg overflow-hidden max-h-96 overflow-y-auto">
                <div class="p-4 text-gray-500">Taslak seçin...</div>
              </div>
            </div>
          </div>
        </div>
      \`;
    }
    
    function renderEmails() {
      return \`
        <div class="space-y-6 animate-fadeIn">
          <div>
            <h1 class="text-2xl lg:text-3xl font-bold text-slate-100">\${isAdmin() ? 'Tüm Mailler' : 'Gönderdiğim Mailler'}</h1>
            <p class="text-slate-400 mt-1" id="emailCount">Yükleniyor...</p>
          </div>
          <div class="glass rounded-xl overflow-hidden">
            <div class="overflow-x-auto">
              <table class="w-full">
                <thead>
                  <tr class="border-b border-slate-700 bg-slate-800/50">
                    <th class="text-left py-4 px-6 text-sm font-medium text-slate-400">Alıcı</th>
                    \${isAdmin() ? '<th class="text-left py-4 px-6 text-sm font-medium text-slate-400">Gönderen</th>' : ''}
                    <th class="text-left py-4 px-6 text-sm font-medium text-slate-400">Konu</th>
                    <th class="text-left py-4 px-6 text-sm font-medium text-slate-400">Durum</th>
                    <th class="text-left py-4 px-6 text-sm font-medium text-slate-400">Tarih</th>
                  </tr>
                </thead>
                <tbody id="emailsTable">
                  <tr><td colspan="5" class="py-8 text-center text-slate-400">Yükleniyor...</td></tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      \`;
    }
    
    function renderUsers() {
      return \`
        <div class="space-y-6 animate-fadeIn">
          <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h1 class="text-2xl lg:text-3xl font-bold text-slate-100">Kullanıcılar</h1>
              <p class="text-slate-400 mt-1" id="userCount">Yükleniyor...</p>
            </div>
            <button onclick="showAddUserModal()" class="btn-primary text-white px-5 py-2.5 rounded-lg flex items-center gap-2 w-fit">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
              Yeni Kullanıcı
            </button>
          </div>
          <div class="glass rounded-xl overflow-hidden">
            <table class="w-full">
              <thead>
                <tr class="border-b border-slate-700 bg-slate-800/50">
                  <th class="text-left py-4 px-6 text-sm font-medium text-slate-400">Kullanıcı</th>
                  <th class="text-left py-4 px-6 text-sm font-medium text-slate-400">Kullanıcı Adı</th>
                  <th class="text-left py-4 px-6 text-sm font-medium text-slate-400">Rol</th>
                  <th class="text-left py-4 px-6 text-sm font-medium text-slate-400">Durum</th>
                  <th class="text-right py-4 px-6 text-sm font-medium text-slate-400">İşlemler</th>
                </tr>
              </thead>
              <tbody id="usersTable">
                <tr><td colspan="5" class="py-8 text-center text-slate-400">Yükleniyor...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
        <div id="userModal" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 hidden">
          <div class="glass rounded-xl p-6 max-w-md w-full mx-4">
            <h3 class="text-lg font-semibold text-slate-100 mb-4" id="modalTitle">Yeni Kullanıcı</h3>
            <form id="userForm" class="space-y-4">
              <div>
                <label class="block text-sm font-medium text-slate-300 mb-2">Kullanıcı Adı *</label>
                <input type="text" id="newUsername" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 focus:outline-none focus:border-primary-500" required>
              </div>
              <div>
                <label class="block text-sm font-medium text-slate-300 mb-2">Ad Soyad *</label>
                <input type="text" id="newFullName" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 focus:outline-none focus:border-primary-500" required>
              </div>
              <div>
                <label class="block text-sm font-medium text-slate-300 mb-2">Şifre *</label>
                <input type="password" id="newPassword" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 focus:outline-none focus:border-primary-500" required>
              </div>
              <div class="flex gap-3 pt-2">
                <button type="button" onclick="hideUserModal()" class="flex-1 bg-slate-700 text-slate-200 py-3 rounded-lg hover:bg-slate-600 transition-colors">İptal</button>
                <button type="submit" class="flex-1 btn-primary text-white py-3 rounded-lg">Kaydet</button>
              </div>
            </form>
          </div>
        </div>
      \`;
    }
    
    function renderTemplates() {
      return \`
        <div class="space-y-6 animate-fadeIn">
          <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h1 class="text-2xl lg:text-3xl font-bold text-slate-100">Mail Taslakları</h1>
              <p class="text-slate-400 mt-1" id="templateCount">Yükleniyor...</p>
            </div>
            <button onclick="showTemplateModal()" class="btn-primary text-white px-5 py-2.5 rounded-lg flex items-center gap-2 w-fit">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
              Yeni Taslak
            </button>
          </div>
          <div id="templatesGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div class="glass rounded-xl p-6 text-slate-400">Yükleniyor...</div>
          </div>
        </div>
        <div id="templateModal" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 hidden overflow-y-auto py-8">
          <div class="glass rounded-xl p-6 max-w-2xl w-full mx-4">
            <h3 class="text-lg font-semibold text-slate-100 mb-4" id="templateModalTitle">Yeni Taslak</h3>
            <form id="templateForm" class="space-y-4">
              <div>
                <label class="block text-sm font-medium text-slate-300 mb-2">Taslak Adı *</label>
                <input type="text" id="tplName" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 focus:outline-none focus:border-primary-500" required>
              </div>
              <div>
                <label class="block text-sm font-medium text-slate-300 mb-2">Mail Konusu *</label>
                <input type="text" id="tplSubject" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 focus:outline-none focus:border-primary-500" placeholder="Örn: Teklif - {isletme_adi}" required>
              </div>
              <div>
                <label class="block text-sm font-medium text-slate-300 mb-2">Değişkenler (virgülle ayırın)</label>
                <input type="text" id="tplVariables" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 focus:outline-none focus:border-primary-500" placeholder="alici_adi, isletme_adi, fiyat">
              </div>
              <div>
                <label class="block text-sm font-medium text-slate-300 mb-2">Mail İçeriği (HTML) *</label>
                <textarea id="tplBody" rows="10" class="w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-3 text-slate-200 focus:outline-none focus:border-primary-500 font-mono text-sm" required></textarea>
              </div>
              <div class="flex gap-3 pt-2">
                <button type="button" onclick="hideTemplateModal()" class="flex-1 bg-slate-700 text-slate-200 py-3 rounded-lg hover:bg-slate-600 transition-colors">İptal</button>
                <button type="submit" class="flex-1 btn-primary text-white py-3 rounded-lg">Kaydet</button>
              </div>
            </form>
          </div>
        </div>
      \`;
    }
    
    function renderLayout(content) {
      const navItems = [
        { id: 'dashboard', icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path>', label: 'Dashboard' },
        { id: 'send', icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"></path>', label: 'Mail Gönder' },
        { id: 'emails', icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>', label: 'Gönderilen Mailler' }
      ];
      const adminItems = [
        { id: 'templates', icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>', label: 'Taslaklar' },
        { id: 'users', icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"></path>', label: 'Kullanıcılar' }
      ];
      
      return \`
        <div class="min-h-screen flex">
          <aside class="w-64 bg-slate-900/95 border-r border-slate-800 hidden lg:block">
            <div class="flex flex-col h-full">
              <div class="p-6 border-b border-slate-800">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-secondary-500 flex items-center justify-center">
                    <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                  </div>
                  <div>
                    <h1 class="text-xl font-bold gradient-text">G360 AI</h1>
                    <p class="text-xs text-slate-500">Mail Sistemi</p>
                  </div>
                </div>
              </div>
              <nav class="flex-1 p-4 space-y-1">
                <p class="text-xs font-semibold text-slate-500 uppercase tracking-wider px-4 mb-2">Ana Menü</p>
                \${navItems.map(item => \`
                  <button onclick="navigate('\${item.id}')" class="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all \${currentPage === item.id ? 'bg-gradient-to-r from-primary-600/20 to-secondary-600/20 text-primary-400' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">\${item.icon}</svg>
                    <span class="font-medium">\${item.label}</span>
                  </button>
                \`).join('')}
                \${isAdmin() ? \`
                  <p class="text-xs font-semibold text-slate-500 uppercase tracking-wider px-4 mt-6 mb-2">Yönetim</p>
                  \${adminItems.map(item => \`
                    <button onclick="navigate('\${item.id}')" class="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all \${currentPage === item.id ? 'bg-gradient-to-r from-primary-600/20 to-secondary-600/20 text-primary-400' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}">
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">\${item.icon}</svg>
                      <span class="font-medium">\${item.label}</span>
                    </button>
                  \`).join('')}
                \` : ''}
              </nav>
              <div class="p-4 border-t border-slate-800">
                <div class="flex items-center gap-3 px-4 py-3 rounded-lg bg-slate-800/50">
                  <div class="w-10 h-10 rounded-full bg-gradient-to-br from-primary-500 to-secondary-500 flex items-center justify-center text-white font-bold">
                    \${currentUser?.full_name?.charAt(0).toUpperCase()}
                  </div>
                  <div class="flex-1">
                    <p class="font-medium text-slate-200 truncate">\${currentUser?.full_name}</p>
                    <p class="text-xs text-slate-500">\${isAdmin() ? 'Yönetici' : 'Kullanıcı'}</p>
                  </div>
                  <button onclick="logout()" class="p-2 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-500/10" title="Çıkış">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg>
                  </button>
                </div>
              </div>
            </div>
          </aside>
          <main class="flex-1 p-4 lg:p-8 overflow-y-auto">\${content}</main>
        </div>
      \`;
    }
    
    // Main render
    function render() {
      const app = document.getElementById('app');
      if (currentPage === 'login') {
        app.innerHTML = renderLogin();
        document.getElementById('loginForm')?.addEventListener('submit', handleLogin);
      } else {
        let content = '';
        switch(currentPage) {
          case 'dashboard': content = renderDashboard(); break;
          case 'send': content = renderSend(); break;
          case 'emails': content = renderEmails(); break;
          case 'users': content = renderUsers(); break;
          case 'templates': content = renderTemplates(); break;
          default: content = renderDashboard();
        }
        app.innerHTML = renderLayout(content);
        loadPageData();
      }
    }
    
    async function loadPageData() {
      try {
        if (currentPage === 'dashboard') {
          const stats = isAdmin() ? await api('/api/stats') : { totalEmails: 0, sentEmails: 0, failedEmails: 0 };
          const emails = await api('/api/emails');
          if (!isAdmin()) {
            stats.totalEmails = emails.length;
            stats.sentEmails = emails.filter(e => e.status === 'sent').length;
            stats.failedEmails = emails.filter(e => e.status === 'failed').length;
          }
          document.getElementById('statsContainer').innerHTML = \`
            <div class="glass rounded-xl p-6"><p class="text-slate-400 text-sm">Toplam Mail</p><p class="text-3xl font-bold text-slate-100 mt-1">\${stats.totalEmails}</p></div>
            <div class="glass rounded-xl p-6"><p class="text-slate-400 text-sm">Başarılı</p><p class="text-3xl font-bold text-emerald-400 mt-1">\${stats.sentEmails}</p></div>
            <div class="glass rounded-xl p-6"><p class="text-slate-400 text-sm">Başarısız</p><p class="text-3xl font-bold text-red-400 mt-1">\${stats.failedEmails}</p></div>
            \${isAdmin() ? \`<div class="glass rounded-xl p-6"><p class="text-slate-400 text-sm">Kullanıcılar</p><p class="text-3xl font-bold text-purple-400 mt-1">\${stats.totalUsers || 0}</p></div>\` : ''}
          \`;
          const recentEmails = emails.slice(0, 5);
          document.getElementById('recentEmails').innerHTML = recentEmails.length ? recentEmails.map(e => \`
            <div class="flex items-center justify-between py-3 border-b border-slate-700 last:border-0">
              <div><p class="text-slate-200">\${e.recipient_name || e.recipient_email}</p><p class="text-xs text-slate-500">\${e.subject}</p></div>
              <span class="px-2 py-1 rounded-full text-xs \${e.status === 'sent' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}">\${e.status === 'sent' ? 'Gönderildi' : 'Başarısız'}</span>
            </div>
          \`).join('') : '<p class="text-slate-500 text-center py-4">Henüz mail gönderilmemiş</p>';
        }
        
        if (currentPage === 'send') {
          const templates = await api('/api/templates');
          window.currentTemplates = templates;
          const select = document.getElementById('templateSelect');
          select.innerHTML = templates.map(t => \`<option value="\${t.id}">\${t.name}</option>\`).join('');
          select.addEventListener('change', updateSendForm);
          document.getElementById('sendForm').addEventListener('submit', handleSendEmail);
          updateSendForm();
        }
        
        if (currentPage === 'emails') {
          const emails = await api('/api/emails');
          document.getElementById('emailCount').textContent = emails.length + ' mail';
          document.getElementById('emailsTable').innerHTML = emails.length ? emails.map(e => \`
            <tr class="border-b border-slate-800 hover:bg-slate-800/30">
              <td class="py-4 px-6"><p class="text-slate-200">\${e.recipient_name || '-'}</p><p class="text-xs text-slate-500">\${e.recipient_email}</p></td>
              \${isAdmin() ? \`<td class="py-4 px-6 text-slate-300">\${e.sender_name || '-'}</td>\` : ''}
              <td class="py-4 px-6 text-slate-300 max-w-xs truncate">\${e.subject}</td>
              <td class="py-4 px-6"><span class="px-2 py-1 rounded-full text-xs \${e.status === 'sent' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}">\${e.status === 'sent' ? 'Gönderildi' : 'Başarısız'}</span></td>
              <td class="py-4 px-6 text-slate-400 text-sm">\${new Date(e.sent_at).toLocaleString('tr-TR')}</td>
            </tr>
          \`).join('') : '<tr><td colspan="5" class="py-8 text-center text-slate-400">Henüz mail gönderilmemiş</td></tr>';
        }
        
        if (currentPage === 'users') {
          const users = await api('/api/users');
          document.getElementById('userCount').textContent = users.filter(u => u.role !== 'admin').length + ' kullanıcı';
          document.getElementById('usersTable').innerHTML = users.map(u => \`
            <tr class="border-b border-slate-800 hover:bg-slate-800/30">
              <td class="py-4 px-6"><div class="flex items-center gap-3"><div class="w-10 h-10 rounded-full bg-gradient-to-br \${u.role === 'admin' ? 'from-amber-500 to-orange-500' : 'from-primary-500 to-secondary-500'} flex items-center justify-center text-white font-bold">\${u.full_name?.charAt(0).toUpperCase()}</div><span class="text-slate-200">\${u.full_name}</span></div></td>
              <td class="py-4 px-6 text-slate-400">\${u.username}</td>
              <td class="py-4 px-6"><span class="px-2 py-1 rounded-full text-xs \${u.role === 'admin' ? 'bg-amber-500/20 text-amber-400' : 'bg-slate-700 text-slate-300'}">\${u.role === 'admin' ? 'Admin' : 'Kullanıcı'}</span></td>
              <td class="py-4 px-6"><span class="text-sm \${u.is_active ? 'text-emerald-400' : 'text-slate-500'}">\${u.is_active ? 'Aktif' : 'Pasif'}</span></td>
              <td class="py-4 px-6 text-right">\${u.role !== 'admin' ? \`<button onclick="deleteUser('\${u.id}')" class="text-red-400 hover:text-red-300 text-sm">Sil</button>\` : ''}</td>
            </tr>
          \`).join('');
          document.getElementById('userForm').addEventListener('submit', handleAddUser);
        }
        
        if (currentPage === 'templates') {
          const templates = await api('/api/templates');
          document.getElementById('templateCount').textContent = templates.length + ' taslak';
          document.getElementById('templatesGrid').innerHTML = templates.length ? templates.map(t => \`
            <div class="glass rounded-xl p-6">
              <div class="flex items-start justify-between mb-3">
                <div class="p-2 rounded-lg bg-amber-500/20 text-amber-400">
                  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                </div>
                <button onclick="deleteTemplate('\${t.id}')" class="text-slate-400 hover:text-red-400">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                </button>
              </div>
              <h3 class="font-semibold text-slate-200 mb-2">\${t.name}</h3>
              <p class="text-sm text-slate-400 mb-4 truncate">\${t.subject}</p>
              <div class="flex flex-wrap gap-1">\${(t.variables || []).slice(0, 3).map(v => \`<span class="px-2 py-1 rounded bg-slate-700/50 text-xs text-slate-400">\${v}</span>\`).join('')}</div>
            </div>
          \`).join('') : '<div class="glass rounded-xl p-6 text-slate-400">Henüz taslak yok</div>';
          document.getElementById('templateForm').addEventListener('submit', handleAddTemplate);
        }
      } catch (error) {
        console.error('Load error:', error);
      }
    }
    
    function updateSendForm() {
      const templateId = document.getElementById('templateSelect').value;
      const template = window.currentTemplates?.find(t => t.id === templateId);
      if (!template) return;
      
      const container = document.getElementById('variablesContainer');
      container.innerHTML = template.variables?.length ? \`
        <div class="space-y-3">
          <label class="block text-sm font-medium text-slate-300">Değişkenler</label>
          \${template.variables.map(v => \`
            <div>
              <label class="block text-xs text-slate-400 mb-1">\${v}</label>
              <input type="text" data-var="\${v}" class="var-input w-full bg-slate-800/50 border border-slate-600 rounded-lg px-4 py-2 text-slate-200 text-sm focus:outline-none focus:border-primary-500" placeholder="\${v} girin...">
            </div>
          \`).join('')}
        </div>
      \` : '';
      
      document.querySelectorAll('.var-input').forEach(input => {
        input.addEventListener('input', updatePreview);
      });
      document.getElementById('recipientEmail').addEventListener('input', updatePreview);
      updatePreview();
    }
    
    function updatePreview() {
      const templateId = document.getElementById('templateSelect').value;
      const template = window.currentTemplates?.find(t => t.id === templateId);
      if (!template) return;
      
      let body = template.body;
      document.querySelectorAll('.var-input').forEach(input => {
        const varName = input.dataset.var;
        const value = input.value || \`[\${varName}]\`;
        body = body.replace(new RegExp(\`{\${varName}}\`, 'g'), value);
      });
      
      document.getElementById('previewContainer').innerHTML = \`<div class="p-4">\${body}</div>\`;
    }
    
    async function handleLogin(e) {
      e.preventDefault();
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      try {
        const data = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
        setToken(data.token);
        setUser(data.user);
        showToast('Giriş başarılı!');
        navigate('dashboard');
      } catch (error) {
        showToast(error.message, 'error');
      }
    }
    
    async function handleSendEmail(e) {
      e.preventDefault();
      const templateId = document.getElementById('templateSelect').value;
      const recipientEmail = document.getElementById('recipientEmail').value;
      const recipientName = document.getElementById('recipientName').value;
      const variables = {};
      document.querySelectorAll('.var-input').forEach(input => {
        variables[input.dataset.var] = input.value;
      });
      try {
        await api('/api/emails/send', { method: 'POST', body: JSON.stringify({ template_id: templateId, recipient_email: recipientEmail, recipient_name: recipientName, variables }) });
        showToast('Mail başarıyla gönderildi!');
        navigate('emails');
      } catch (error) {
        showToast(error.message, 'error');
      }
    }
    
    function showAddUserModal() { document.getElementById('userModal').classList.remove('hidden'); }
    function hideUserModal() { document.getElementById('userModal').classList.add('hidden'); }
    function showTemplateModal() { document.getElementById('templateModal').classList.remove('hidden'); }
    function hideTemplateModal() { document.getElementById('templateModal').classList.add('hidden'); }
    
    async function handleAddUser(e) {
      e.preventDefault();
      try {
        await api('/api/users', { method: 'POST', body: JSON.stringify({ username: document.getElementById('newUsername').value, full_name: document.getElementById('newFullName').value, password: document.getElementById('newPassword').value }) });
        showToast('Kullanıcı oluşturuldu!');
        hideUserModal();
        loadPageData();
      } catch (error) {
        showToast(error.message, 'error');
      }
    }
    
    async function deleteUser(id) {
      if (!confirm('Bu kullanıcıyı silmek istediğinize emin misiniz?')) return;
      try {
        await api('/api/users/' + id, { method: 'DELETE' });
        showToast('Kullanıcı silindi');
        loadPageData();
      } catch (error) {
        showToast(error.message, 'error');
      }
    }
    
    async function handleAddTemplate(e) {
      e.preventDefault();
      try {
        const variables = document.getElementById('tplVariables').value.split(',').map(v => v.trim()).filter(v => v);
        await api('/api/templates', { method: 'POST', body: JSON.stringify({ name: document.getElementById('tplName').value, subject: document.getElementById('tplSubject').value, body: document.getElementById('tplBody').value, variables }) });
        showToast('Taslak oluşturuldu!');
        hideTemplateModal();
        loadPageData();
      } catch (error) {
        showToast(error.message, 'error');
      }
    }
    
    async function deleteTemplate(id) {
      if (!confirm('Bu taslağı silmek istediğinize emin misiniz?')) return;
      try {
        await api('/api/templates/' + id, { method: 'DELETE' });
        showToast('Taslak silindi');
        loadPageData();
      } catch (error) {
        showToast(error.message, 'error');
      }
    }
    
    function logout() {
      clearToken();
      currentUser = null;
      navigate('login');
    }
    
    // Init
    function init() {
      const token = getToken();
      const user = getUser();
      if (token && user) {
        currentUser = user;
        navigate('dashboard');
      } else {
        navigate('login');
      }
    }
    
    init();
  </script>
</body>
</html>`;

// Serve frontend
app.get('/', (req, res) => {
  res.send(FRONTEND_HTML);
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', gmail: GMAIL_USER, configured: !!GMAIL_APP_PASSWORD });
});

// Start server
app.listen(PORT, () => {
  console.log(\`🚀 G360 Mail System running on port \${PORT}\`);
  console.log(\`📧 Gmail: \${GMAIL_USER}\`);
  console.log(\`🔐 Gmail configured: \${!!GMAIL_APP_PASSWORD}\`);
});
