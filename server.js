const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Supabase
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_KEY || '';
const supabase = SUPABASE_URL && SUPABASE_KEY ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;

// Other env
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const FROM_EMAIL = process.env.FROM_EMAIL || 'bilgi@g360.ai';
const FROM_NAME = process.env.FROM_NAME || 'G360 AI';
const JWT_SECRET = process.env.JWT_SECRET || 'g360-secret-2024';

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Database helpers
async function getAll(table) {
  if (!supabase) return [];
  const { data, error } = await supabase.from(table).select('*').eq('is_deleted', false);
  return error ? [] : data;
}

async function getAllIncludeDeleted(table) {
  if (!supabase) return [];
  const { data, error } = await supabase.from(table).select('*');
  return error ? [] : data;
}

async function getById(table, id) {
  if (!supabase) return null;
  const { data, error } = await supabase.from(table).select('*').eq('id', id).single();
  return error ? null : data;
}

async function insert(table, record) {
  if (!supabase) return null;
  record.id = record.id || uuidv4();
  record.created_at = record.created_at || new Date().toISOString();
  record.is_deleted = false;
  const { data, error } = await supabase.from(table).insert(record).select().single();
  return error ? null : data;
}

async function update(table, id, updates) {
  if (!supabase) return null;
  const { data, error } = await supabase.from(table).update(updates).eq('id', id).select().single();
  return error ? null : data;
}

async function softDelete(table, id) {
  if (!supabase) return false;
  const { error } = await supabase.from(table).update({ is_deleted: true }).eq('id', id);
  return !error;
}

async function getByField(table, field, value) {
  if (!supabase) return null;
  const { data, error } = await supabase.from(table).select('*').eq(field, value).eq('is_deleted', false).single();
  return error ? null : data;
}

async function getSetting(key) {
  if (!supabase) return null;
  const { data } = await supabase.from('settings').select('value').eq('key', key).single();
  return data?.value || null;
}

async function setSetting(key, value) {
  if (!supabase) return;
  const existing = await getSetting(key);
  if (existing !== null) {
    await supabase.from('settings').update({ value }).eq('key', key);
  } else {
    await supabase.from('settings').insert({ key, value });
  }
}

// Initialize default data
async function initData() {
  if (!supabase) {
    console.log('WARNING: Supabase not configured!');
    return;
  }
  
  // Check if admin exists
  const admin = await getByField('users', 'username', 'burakkaan48');
  if (!admin) {
    await insert('users', {
      username: 'burakkaan48',
      password: bcrypt.hashSync('admin123', 10),
      full_name: 'Burak Kaan',
      role: 'admin',
      team_id: null,
      is_active: true
    });
    console.log('Admin user created');
  }
  
  // Check if teams exist
  const teams = await getAll('teams');
  if (teams.length === 0) {
    const defaultTeams = ['Ankara', 'Istanbul', 'Izmir', 'Antalya', 'Kayseri', 'Mugla'];
    for (const name of defaultTeams) {
      await insert('teams', { name });
    }
    console.log('Default teams created');
  }
  
  // Check if templates exist
  const templates = await getAll('templates');
  if (templates.length === 0) {
    await insert('templates', {
      name: 'Google Street View Teklif',
      subject: '{{firma}} için Google Street View 360° İç Mekân Çekim Teklifi',
      body: '<p>Sayın <strong>{{isim}}</strong>,</p><p>Daha önce yaptığımız görüşme doğrultusunda, <strong>{{firma}}</strong> için <strong>küçük ölçekli oteller</strong> özelinde sunabileceğimiz <strong>Google Street View 360° iç mekân çekim hizmeti</strong>ne ilişkin teklifimizi bilgilerinize sunarız.</p><p>Google onaylı 360° çekimler sayesinde oteliniz; Google Haritalar ve Google Arama sonuçlarında daha görünür hale gelir. Potansiyel misafirleriniz, rezervasyon öncesinde tesisinizi çevrimiçi olarak gezebilir ve karar süreci netleşir.</p><p>🎯 <strong>Hizmet Kapsamı</strong></p><p>Otelinizin iç ve dış alanlarının 360° panorama çekimi<br>Tüm görsellerin Google Street View standartlarına uygun şekilde optimize edilmesi ve yayınlanması<br>Mobil uyumlu, SEO destekli dijital sanal tur<br>Küçük oteller için hızlı, sade ve maliyet-verimli kurulum</p><p>💼 <strong>Fiyatlandırma</strong></p><p><strong>Sahne başı {{fiyat}} ₺ + KDV</strong></p><p>Her sahne; lobi, oda, resepsiyon, restoran veya ortak alan gibi otelinizin bir bölümünü temsil eden <strong>tek bir 360° panorama çekimini</strong> ifade eder.<br>Toplam ücret, çekim sonunda netleşen sahne sayısına göre hesaplanır.</p><p>Kısa bir saha keşfi sonrasında sahne sayısı netleştirilerek çekim planlaması yapılır.</p><p>İş birliği için teşekkür eder, {{firma}} \'nın dijital görünürlüğünü birlikte güçlendirmekten memnuniyet duyarız.</p>',
      variables: ['isim', 'firma', 'fiyat'],
      is_active: true
    });
    console.log('Default template created');
  }
  
  // Default signature
  const sig = await getSetting('signature');
  if (!sig) {
    await setSetting('signature', '<p style="margin-top:20px;padding-top:15px;border-top:1px solid #ddd;color:#666;">Saygılarımızla,<br><strong style="color:#0d9488;">G360 AI Ekibi</strong><br><a href="https://g360.ai" style="color:#0d9488;">g360.ai</a></p>');
  }
}

// Send email
async function sendMail(to, subject, html) {
  if (!RESEND_API_KEY) throw new Error('RESEND_API_KEY ayarlanmamis');
  
  const sig = await getSetting('signature');
  if (sig) html += sig;
  
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

// Auth middleware
function auth(req, res, next) {
  const h = req.headers.authorization;
  const t = h && h.split(' ')[1];
  if (!t) return res.status(401).json({ error: 'Token gerekli' });
  jwt.verify(t, JWT_SECRET, (e, u) => {
    if (e) return res.status(403).json({ error: 'Gecersiz token' });
    req.user = u;
    next();
  });
}

function admin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetki yok' });
  next();
}

// AUTH ROUTES
app.post('/api/auth/login', async (req, res) => {
  const u = await getByField('users', 'username', req.body.username);
  if (!u || !u.is_active || !bcrypt.compareSync(req.body.password, u.password)) {
    return res.status(401).json({ error: 'Hatali giris' });
  }
  const teams = await getAll('teams');
  const team = teams.find(t => t.id === u.team_id);
  const token = jwt.sign({ id: u.id, username: u.username, role: u.role, full_name: u.full_name, team_id: u.team_id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { ...u, password: undefined, team_name: team?.name } });
});

app.get('/api/auth/me', auth, async (req, res) => {
  const u = await getById('users', req.user.id);
  if (!u) return res.status(404).json({ error: 'Bulunamadi' });
  const teams = await getAll('teams');
  const team = teams.find(t => t.id === u.team_id);
  res.json({ ...u, password: undefined, team_name: team?.name });
});

app.post('/api/auth/change-password', auth, async (req, res) => {
  const u = await getById('users', req.user.id);
  if (!u) return res.status(404).json({ error: 'Bulunamadi' });
  if (!bcrypt.compareSync(req.body.current, u.password)) {
    return res.status(400).json({ error: 'Mevcut sifre yanlis' });
  }
  await update('users', u.id, { password: bcrypt.hashSync(req.body.newpass, 10) });
  res.json({ ok: true });
});

// TEAMS
app.get('/api/teams', auth, async (req, res) => {
  res.json(await getAll('teams'));
});

app.post('/api/teams', auth, admin, async (req, res) => {
  const t = await insert('teams', { name: req.body.name });
  res.json(t);
});

app.put('/api/teams/:id', auth, admin, async (req, res) => {
  const t = await update('teams', req.params.id, { name: req.body.name });
  res.json(t);
});

app.delete('/api/teams/:id', auth, admin, async (req, res) => {
  const users = await getAll('users');
  if (users.some(u => u.team_id === req.params.id)) {
    return res.status(400).json({ error: 'Ekipte kullanici var' });
  }
  await softDelete('teams', req.params.id);
  res.json({ ok: true });
});

// USERS
app.get('/api/users', auth, async (req, res) => {
  let users = await getAll('users');
  const teams = await getAll('teams');
  
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

app.post('/api/users', auth, admin, async (req, res) => {
  const existing = await getByField('users', 'username', req.body.username);
  if (existing) return res.status(400).json({ error: 'Kullanici adi mevcut' });
  
  const u = await insert('users', {
    username: req.body.username,
    password: bcrypt.hashSync(req.body.password, 10),
    full_name: req.body.full_name,
    role: req.body.role || 'sales',
    team_id: req.body.team_id || null,
    is_active: true
  });
  res.json({ ...u, password: undefined });
});

app.put('/api/users/:id', auth, admin, async (req, res) => {
  const updates = {
    full_name: req.body.full_name,
    role: req.body.role,
    team_id: req.body.team_id || null
  };
  if (req.body.password) updates.password = bcrypt.hashSync(req.body.password, 10);
  await update('users', req.params.id, updates);
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth, admin, async (req, res) => {
  const u = await getById('users', req.params.id);
  if (u?.role === 'admin') return res.status(400).json({ error: 'Admin silinemez' });
  await softDelete('users', req.params.id);
  res.json({ ok: true });
});

// TEMPLATES
app.get('/api/templates', auth, async (req, res) => {
  const templates = await getAll('templates');
  res.json(templates.filter(t => t.is_active));
});

app.post('/api/templates', auth, admin, async (req, res) => {
  const matches = (req.body.subject + ' ' + req.body.body).match(/\{\{(\w+)\}\}/g) || [];
  const variables = [...new Set(matches.map(m => m.slice(2, -2)))];
  
  const t = await insert('templates', {
    name: req.body.name,
    subject: req.body.subject,
    body: req.body.body,
    variables,
    is_active: true
  });
  res.json(t);
});

app.put('/api/templates/:id', auth, admin, async (req, res) => {
  const matches = (req.body.subject + ' ' + req.body.body).match(/\{\{(\w+)\}\}/g) || [];
  const variables = [...new Set(matches.map(m => m.slice(2, -2)))];
  
  const t = await update('templates', req.params.id, {
    name: req.body.name,
    subject: req.body.subject,
    body: req.body.body,
    variables
  });
  res.json(t);
});

app.delete('/api/templates/:id', auth, admin, async (req, res) => {
  await update('templates', req.params.id, { is_active: false });
  res.json({ ok: true });
});

// SETTINGS
app.get('/api/settings', auth, async (req, res) => {
  const signature = await getSetting('signature');
  res.json({ signature: signature || '' });
});

app.post('/api/settings', auth, admin, async (req, res) => {
  if (req.body.signature !== undefined) {
    await setSetting('signature', req.body.signature);
  }
  res.json({ ok: true });
});

// EMAILS
app.get('/api/emails', auth, async (req, res) => {
  let emails = await getAll('emails');
  const users = await getAll('users');
  const teams = await getAll('teams');
  
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

app.get('/api/emails/:id', auth, async (req, res) => {
  const e = await getById('emails', req.params.id);
  if (!e) return res.status(404).json({ error: 'Bulunamadi' });
  
  if (req.user.role === 'sales' && e.user_id !== req.user.id) {
    return res.status(403).json({ error: 'Yetki yok' });
  }
  if (req.user.role === 'manager') {
    const users = await getAll('users');
    const teamUserIds = users.filter(u => u.team_id === req.user.team_id).map(u => u.id);
    if (!teamUserIds.includes(e.user_id)) return res.status(403).json({ error: 'Yetki yok' });
  }
  
  const users = await getAll('users');
  const sender = users.find(u => u.id === e.user_id);
  res.json({ ...e, sender_name: sender?.full_name });
});

app.post('/api/emails/send', auth, async (req, res) => {
  const templates = await getAll('templates');
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
  
  const emailData = {
    user_id: req.user.id,
    template_id: req.body.template_id,
    template_name: t.name,
    recipient_email: req.body.recipient_email,
    recipient_name: req.body.recipient_name,
    subject,
    body,
    variables_used: vars,
    status: 'sending',
    sent_at: new Date().toISOString()
  };
  
  const savedEmail = await insert('emails', emailData);
  
  try {
    const result = await sendMail(req.body.recipient_email, subject, body);
    await update('emails', savedEmail.id, { status: 'sent', resend_id: result.id });
    res.json({ ok: true, id: result.id });
  } catch (err) {
    await update('emails', savedEmail.id, { status: 'failed', error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// STATS
app.get('/api/stats', auth, async (req, res) => {
  let emails = await getAll('emails');
  const users = await getAll('users');
  const teams = await getAll('teams');
  
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

// Health & Frontend
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/health', (req, res) => res.json({ ok: true, v: '4.0', supabase: !!supabase }));

// Start
app.listen(PORT, async () => {
  console.log('G360 Mail v4.0 | Port:', PORT);
  console.log('Supabase:', supabase ? 'Connected' : 'NOT CONFIGURED');
  if (supabase) await initData();
});
