const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;

// Environment
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_KEY || '';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const FROM_EMAIL = process.env.FROM_EMAIL || 'bilgi@g360.ai';
const FROM_NAME = process.env.FROM_NAME || 'G360 AI';
const JWT_SECRET = process.env.JWT_SECRET || 'g360-crm-secret-2024';
const GOOGLE_MAPS_API_KEY = process.env.GOOGLE_MAPS_API_KEY || '';

// Supabase client
const supabase = SUPABASE_URL && SUPABASE_KEY ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// =====================================================
// SABİT VERİLER (22 Kategori + 6 Durum)
// =====================================================

const CATEGORIES = [
  { id: 1, name: 'Otel' },
  { id: 2, name: 'Restoran' },
  { id: 3, name: 'Mobilya' },
  { id: 4, name: 'Kafe / Kahve Dükkanı' },
  { id: 5, name: 'Eğitim' },
  { id: 6, name: 'Güzellik Salonu' },
  { id: 7, name: 'Kuyumcu' },
  { id: 8, name: 'Kırtasiye' },
  { id: 9, name: 'Pet Shop' },
  { id: 10, name: 'Spor Salonu' },
  { id: 11, name: 'Optik' },
  { id: 12, name: 'Klinik' },
  { id: 13, name: 'Beyaz Eşya' },
  { id: 14, name: 'Market' },
  { id: 15, name: 'Otomotiv' },
  { id: 16, name: 'Yapı Market' },
  { id: 17, name: 'Cep Telefonu' },
  { id: 18, name: 'Eczane' },
  { id: 19, name: 'Giyim' },
  { id: 20, name: 'Pub / Bar' },
  { id: 21, name: 'Aydınlatma' },
  { id: 22, name: 'Çiçekçi' }
];

const STATUSES = [
  { id: 1, name: 'Müşteri Bilgilendirildi', color: '#eab308' },
  { id: 2, name: 'Çekim Tarihi Belirlendi', color: '#3b82f6' },
  { id: 3, name: 'Çekim Yapıldı', color: '#8b5cf6' },
  { id: 4, name: 'Müşteri Çekimi Onayladı', color: '#f97316' },
  { id: 5, name: 'İlgilenmiyor', color: '#ef4444' },
  { id: 6, name: 'Tamamlandı', color: '#22c55e' }
];

// =====================================================
// DATABASE HELPERS
// =====================================================

async function getAll(table) {
  if (!supabase) return [];
  const { data, error } = await supabase.from(table).select('*').eq('is_deleted', false);
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
  record.created_at = new Date().toISOString();
  record.is_deleted = false;
  const { data, error } = await supabase.from(table).insert(record).select().single();
  if (error) console.error('Insert error:', table, error);
  return error ? null : data;
}

async function update(table, id, updates) {
  if (!supabase) return null;
  updates.updated_at = new Date().toISOString();
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

// =====================================================
// INIT DEFAULT DATA
// =====================================================

async function initData() {
  if (!supabase) {
    console.log('⚠️  Supabase bağlantısı yok!');
    return;
  }
  
  // Admin user
  const admin = await getByField('users', 'username', 'burakkaan48');
  if (!admin) {
    await insert('users', {
      username: 'burakkaan48',
      password: bcrypt.hashSync('admin123', 10),
      full_name: 'Burak Kaan Kök',
      role: 'admin',
      team_id: null,
      is_active: true
    });
    console.log('✓ Admin kullanıcı oluşturuldu');
  }
  
  // Default teams
  const teams = await getAll('teams');
  if (teams.length === 0) {
    for (const name of ['İstanbul Avrupa', 'İstanbul Anadolu', 'Ankara', 'İzmir']) {
      await insert('teams', { name });
    }
    console.log('✓ Varsayılan ekipler oluşturuldu');
  }
  
  // Default template
  const templates = await getAll('templates');
  if (templates.length === 0) {
    await insert('templates', {
      name: 'Google Street View Teklif',
      subject: '{{firma}} için Google Street View 360° Teklifi',
      body: '<p>Sayın <strong>{{isim}}</strong>,</p><p><strong>{{firma}}</strong> için Google Street View 360° iç mekân çekim teklifimizi sunarız.</p><p>💼 <strong>Fiyatlandırma:</strong> <strong>{{fiyat}} ₺</strong></p><p>Detaylı bilgi ve sorularınız için bizimle iletişime geçebilirsiniz.</p>',
      variables: ['isim', 'firma', 'fiyat'],
      is_active: true
    });
    console.log('✓ Varsayılan taslak oluşturuldu');
  }
  
  // Default signature
  const sig = await getSetting('signature');
  if (!sig) {
    await setSetting('signature', '<p style="margin-top:20px;padding-top:15px;border-top:1px solid #e5e7eb;color:#6b7280;font-size:14px;">Saygılarımızla,<br><strong style="color:#0d9488;">G360 AI Ekibi</strong><br><a href="https://g360.ai" style="color:#0d9488;">g360.ai</a></p>');
    console.log('✓ Varsayılan imza oluşturuldu');
  }
}

// =====================================================
// AUTH MIDDLEWARE
// =====================================================

function auth(req, res, next) {
  const h = req.headers.authorization;
  const t = h && h.split(' ')[1];
  if (!t) return res.status(401).json({ error: 'Token gerekli' });
  jwt.verify(t, JWT_SECRET, (e, u) => {
    if (e) return res.status(403).json({ error: 'Geçersiz token' });
    req.user = u;
    next();
  });
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetki yok' });
  next();
}

// =====================================================
// SEND EMAIL (Resend API)
// =====================================================

async function sendMail(to, subject, html) {
  if (!RESEND_API_KEY) throw new Error('RESEND_API_KEY ayarlanmamış');
  
  const sig = await getSetting('signature');
  if (sig) html += sig;
  
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 
      'Authorization': 'Bearer ' + RESEND_API_KEY, 
      'Content-Type': 'application/json' 
    },
    body: JSON.stringify({
      from: `${FROM_NAME} <${FROM_EMAIL}>`,
      reply_to: FROM_EMAIL,
      to: [to],
      subject,
      html,
      text: html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim()
    })
  });
  
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Mail gönderilemedi');
  return data;
}

// =====================================================
// AUTH ROUTES
// =====================================================

app.post('/api/auth/login', async (req, res) => {
  const u = await getByField('users', 'username', req.body.username);
  if (!u || !u.is_active || !bcrypt.compareSync(req.body.password, u.password)) {
    return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı' });
  }
  const teams = await getAll('teams');
  const team = teams.find(t => t.id === u.team_id);
  const token = jwt.sign(
    { id: u.id, username: u.username, role: u.role, full_name: u.full_name, team_id: u.team_id },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.json({ token, user: { ...u, password: undefined, team_name: team?.name } });
});

app.get('/api/auth/me', auth, async (req, res) => {
  const u = await getById('users', req.user.id);
  if (!u) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
  const teams = await getAll('teams');
  const team = teams.find(t => t.id === u.team_id);
  res.json({ ...u, password: undefined, team_name: team?.name });
});

app.put('/api/auth/password', auth, async (req, res) => {
  const { current_password, new_password } = req.body;
  const u = await getById('users', req.user.id);
  
  if (!u || !bcrypt.compareSync(current_password, u.password)) {
    return res.status(400).json({ error: 'Mevcut şifre hatalı' });
  }
  
  await update('users', req.user.id, { password: bcrypt.hashSync(new_password, 10) });
  res.json({ ok: true, message: 'Şifre güncellendi' });
});

// =====================================================
// TEAMS ROUTES
// =====================================================

app.get('/api/teams', auth, async (req, res) => {
  res.json(await getAll('teams'));
});

app.post('/api/teams', auth, adminOnly, async (req, res) => {
  res.json(await insert('teams', { name: req.body.name }));
});

app.put('/api/teams/:id', auth, adminOnly, async (req, res) => {
  res.json(await update('teams', req.params.id, { name: req.body.name }));
});

app.delete('/api/teams/:id', auth, adminOnly, async (req, res) => {
  await softDelete('teams', req.params.id);
  res.json({ ok: true });
});

// =====================================================
// USERS ROUTES
// =====================================================

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

app.post('/api/users', auth, adminOnly, async (req, res) => {
  const existing = await getByField('users', 'username', req.body.username);
  if (existing) return res.status(400).json({ error: 'Bu kullanıcı adı zaten mevcut' });
  
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

app.put('/api/users/:id', auth, adminOnly, async (req, res) => {
  const updates = {
    full_name: req.body.full_name,
    role: req.body.role,
    team_id: req.body.team_id || null,
    is_active: req.body.is_active !== undefined ? req.body.is_active : true
  };
  if (req.body.password) updates.password = bcrypt.hashSync(req.body.password, 10);
  await update('users', req.params.id, updates);
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth, adminOnly, async (req, res) => {
  await softDelete('users', req.params.id);
  res.json({ ok: true });
});

// =====================================================
// TEMPLATES ROUTES
// =====================================================

app.get('/api/templates', auth, async (req, res) => {
  const templates = await getAll('templates');
  res.json(templates.filter(t => t.is_active));
});

app.get('/api/templates/:id', auth, async (req, res) => {
  const t = await getById('templates', req.params.id);
  if (!t) return res.status(404).json({ error: 'Taslak bulunamadı' });
  res.json(t);
});

app.post('/api/templates', auth, adminOnly, async (req, res) => {
  const matches = (req.body.subject + ' ' + req.body.body).match(/\{\{(\w+)\}\}/g) || [];
  const variables = [...new Set(matches.map(m => m.slice(2, -2)))];
  res.json(await insert('templates', { 
    name: req.body.name, 
    subject: req.body.subject, 
    body: req.body.body, 
    variables, 
    is_active: true 
  }));
});

app.put('/api/templates/:id', auth, adminOnly, async (req, res) => {
  const matches = (req.body.subject + ' ' + req.body.body).match(/\{\{(\w+)\}\}/g) || [];
  const variables = [...new Set(matches.map(m => m.slice(2, -2)))];
  res.json(await update('templates', req.params.id, { 
    name: req.body.name, 
    subject: req.body.subject, 
    body: req.body.body, 
    variables 
  }));
});

app.delete('/api/templates/:id', auth, adminOnly, async (req, res) => {
  await update('templates', req.params.id, { is_active: false });
  res.json({ ok: true });
});

// =====================================================
// SETTINGS ROUTES
// =====================================================

app.get('/api/settings', auth, async (req, res) => {
  res.json({ signature: await getSetting('signature') || '' });
});

app.post('/api/settings', auth, adminOnly, async (req, res) => {
  if (req.body.signature !== undefined) await setSetting('signature', req.body.signature);
  res.json({ ok: true });
});

// =====================================================
// CATEGORIES & STATUSES ROUTES
// =====================================================

app.get('/api/categories', auth, (req, res) => res.json(CATEGORIES));
app.get('/api/statuses', auth, (req, res) => res.json(STATUSES));

// =====================================================
// CUSTOMERS ROUTES
// =====================================================

app.get('/api/customers', auth, async (req, res) => {
  if (!supabase) return res.json([]);
  
  let query = supabase.from('customers').select('*').eq('is_deleted', false);
  
  // Role-based filtering
  if (req.user.role === 'sales') {
    query = query.eq('user_id', req.user.id);
  } else if (req.user.role === 'manager') {
    const users = await getAll('users');
    const teamUserIds = users.filter(u => u.team_id === req.user.team_id).map(u => u.id);
    query = query.in('user_id', teamUserIds);
  }
  
  const { data, error } = await query.order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  
  // Enrich with user names
  const users = await getAll('users');
  const enriched = data.map(c => ({
    ...c,
    user_name: users.find(u => u.id === c.user_id)?.full_name,
    category: CATEGORIES.find(cat => cat.id === c.category_id),
    status_info: STATUSES.find(s => s.id === c.status)
  }));
  
  res.json(enriched);
});

app.get('/api/customers/:id', auth, async (req, res) => {
  const c = await getById('customers', req.params.id);
  if (!c) return res.status(404).json({ error: 'Müşteri bulunamadı' });
  
  const users = await getAll('users');
  res.json({
    ...c,
    user_name: users.find(u => u.id === c.user_id)?.full_name,
    category: CATEGORIES.find(cat => cat.id === c.category_id),
    status_info: STATUSES.find(s => s.id === c.status)
  });
});

app.post('/api/customers', auth, async (req, res) => {
  const { 
    category_id, business_name, place_id, address, city, district, 
    contact_name, phone, email, tax_number, price, is_invoiced, scene_count, notes 
  } = req.body;
  
  // KDV hesaplama
  let priceVal = parseFloat(price) || 0;
  let priceWithoutVat = priceVal;
  let vatAmount = 0;
  
  if (is_invoiced && priceVal > 0) {
    priceWithoutVat = priceVal / 1.20;
    vatAmount = priceVal - priceWithoutVat;
  }
  
  const customer = await insert('customers', {
    user_id: req.user.id,
    category_id: parseInt(category_id),
    business_name,
    place_id: place_id || null,
    address: address || null,
    city: city || null,
    district: district || null,
    contact_name: contact_name || null,
    phone: phone || null,
    email: email || null,
    tax_number: tax_number || null,
    price: priceVal,
    price_without_vat: Math.round(priceWithoutVat * 100) / 100,
    vat_amount: Math.round(vatAmount * 100) / 100,
    is_invoiced: is_invoiced || false,
    scene_count: parseInt(scene_count) || 1,
    status: 1,
    notes: notes || null
  });
  
  if (!customer) {
    return res.status(500).json({ error: 'Müşteri oluşturulamadı' });
  }
  
  // Return enriched customer
  const users = await getAll('users');
  res.json({
    ...customer,
    user_name: users.find(u => u.id === customer.user_id)?.full_name,
    category: CATEGORIES.find(cat => cat.id === customer.category_id),
    status_info: STATUSES.find(s => s.id === customer.status)
  });
});

app.put('/api/customers/:id', auth, async (req, res) => {
  const c = await getById('customers', req.params.id);
  if (!c) return res.status(404).json({ error: 'Müşteri bulunamadı' });
  
  // Permission check
  if (req.user.role !== 'admin' && c.user_id !== req.user.id) {
    return res.status(403).json({ error: 'Bu müşteriyi düzenleme yetkiniz yok' });
  }
  
  const { 
    category_id, business_name, place_id, address, city, district,
    contact_name, phone, email, tax_number, price, is_invoiced, scene_count, notes, status 
  } = req.body;
  
  let priceVal = parseFloat(price) || 0;
  let priceWithoutVat = priceVal;
  let vatAmount = 0;
  
  if (is_invoiced && priceVal > 0) {
    priceWithoutVat = priceVal / 1.20;
    vatAmount = priceVal - priceWithoutVat;
  }
  
  const updated = await update('customers', req.params.id, {
    category_id: parseInt(category_id),
    business_name,
    place_id: place_id || null,
    address: address || null,
    city: city || null,
    district: district || null,
    contact_name: contact_name || null,
    phone: phone || null,
    email: email || null,
    tax_number: tax_number || null,
    price: priceVal,
    price_without_vat: Math.round(priceWithoutVat * 100) / 100,
    vat_amount: Math.round(vatAmount * 100) / 100,
    is_invoiced: is_invoiced || false,
    scene_count: parseInt(scene_count) || 1,
    status: parseInt(status) || c.status,
    notes: notes || null
  });
  
  const users = await getAll('users');
  res.json({
    ...updated,
    user_name: users.find(u => u.id === updated.user_id)?.full_name,
    category: CATEGORIES.find(cat => cat.id === updated.category_id),
    status_info: STATUSES.find(s => s.id === updated.status)
  });
});

app.patch('/api/customers/:id/status', auth, async (req, res) => {
  const c = await getById('customers', req.params.id);
  if (!c) return res.status(404).json({ error: 'Müşteri bulunamadı' });
  
  if (req.user.role !== 'admin' && c.user_id !== req.user.id) {
    return res.status(403).json({ error: 'Yetki yok' });
  }
  
  const newStatus = parseInt(req.body.status);
  if (!STATUSES.find(s => s.id === newStatus)) {
    return res.status(400).json({ error: 'Geçersiz durum' });
  }
  
  const updated = await update('customers', req.params.id, { status: newStatus });
  res.json({
    ...updated,
    status_info: STATUSES.find(s => s.id === updated.status)
  });
});

app.delete('/api/customers/:id', auth, async (req, res) => {
  const c = await getById('customers', req.params.id);
  if (!c) return res.status(404).json({ error: 'Müşteri bulunamadı' });
  
  if (req.user.role !== 'admin' && c.user_id !== req.user.id) {
    return res.status(403).json({ error: 'Yetki yok' });
  }
  
  await softDelete('customers', req.params.id);
  res.json({ ok: true });
});

// =====================================================
// EMAILS ROUTES
// =====================================================

app.get('/api/emails', auth, async (req, res) => {
  let emails = await getAll('emails');
  const users = await getAll('users');
  
  if (req.user.role === 'manager') {
    const teamUserIds = users.filter(u => u.team_id === req.user.team_id).map(u => u.id);
    emails = emails.filter(e => teamUserIds.includes(e.user_id));
  } else if (req.user.role === 'sales') {
    emails = emails.filter(e => e.user_id === req.user.id);
  }
  
  res.json(
    emails
      .map(e => ({ ...e, sender_name: users.find(u => u.id === e.user_id)?.full_name }))
      .sort((a, b) => new Date(b.sent_at) - new Date(a.sent_at))
  );
});

app.get('/api/emails/:id', auth, async (req, res) => {
  const e = await getById('emails', req.params.id);
  if (!e) return res.status(404).json({ error: 'Mail bulunamadı' });
  res.json(e);
});

app.post('/api/emails/send', auth, async (req, res) => {
  const templates = await getAll('templates');
  const t = templates.find(x => x.id === req.body.template_id);
  if (!t) return res.status(404).json({ error: 'Taslak bulunamadı' });
  
  let subject = t.subject;
  let body = t.body;
  const vars = req.body.variables || {};
  
  // Replace variables
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
    recipient_name: req.body.recipient_name || null,
    subject,
    body,
    variables_used: vars,
    status: 'sending',
    customer_id: req.body.customer_id || null,
    sent_at: new Date().toISOString()
  };
  
  const savedEmail = await insert('emails', emailData);
  
  try {
    const result = await sendMail(req.body.recipient_email, subject, body);
    await update('emails', savedEmail.id, { status: 'sent', resend_id: result.id });
    res.json({ ok: true, id: result.id, email_id: savedEmail.id });
  } catch (err) {
    await update('emails', savedEmail.id, { status: 'failed', error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// =====================================================
// STATS ROUTE
// =====================================================

app.get('/api/stats', auth, async (req, res) => {
  let customers = await getAll('customers');
  let emails = await getAll('emails');
  const users = await getAll('users');
  
  // Role filter
  if (req.user.role === 'manager') {
    const teamUserIds = users.filter(u => u.team_id === req.user.team_id).map(u => u.id);
    customers = customers.filter(c => teamUserIds.includes(c.user_id));
    emails = emails.filter(e => teamUserIds.includes(e.user_id));
  } else if (req.user.role === 'sales') {
    customers = customers.filter(c => c.user_id === req.user.id);
    emails = emails.filter(e => e.user_id === req.user.id);
  }
  
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
  const monthAgo = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);
  
  const completed = customers.filter(c => c.status === 6);
  
  res.json({
    totalCustomers: customers.length,
    newToday: customers.filter(c => new Date(c.created_at) >= today).length,
    completedCount: completed.length,
    totalEmails: emails.length,
    sentEmails: emails.filter(e => e.status === 'sent').length,
    
    todayRevenue: completed.filter(c => new Date(c.updated_at || c.created_at) >= today).reduce((s, c) => s + (c.price || 0), 0),
    weekRevenue: completed.filter(c => new Date(c.updated_at || c.created_at) >= weekAgo).reduce((s, c) => s + (c.price || 0), 0),
    monthRevenue: completed.filter(c => new Date(c.updated_at || c.created_at) >= monthAgo).reduce((s, c) => s + (c.price || 0), 0),
    totalRevenue: completed.reduce((s, c) => s + (c.price || 0), 0),
    
    byStatus: STATUSES.map(s => ({ 
      ...s, 
      count: customers.filter(c => c.status === s.id).length 
    })),
    
    recentCustomers: customers.slice(0, 5).map(c => ({
      id: c.id,
      business_name: c.business_name,
      city: c.city,
      price: c.price,
      status: c.status,
      status_info: STATUSES.find(s => s.id === c.status)
    }))
  });
});

// =====================================================
// GOOGLE PLACES PROXY
// =====================================================

app.get('/api/places/autocomplete', auth, async (req, res) => {
  if (!GOOGLE_MAPS_API_KEY) return res.json({ predictions: [] });
  
  const { input } = req.query;
  if (!input || input.length < 2) return res.json({ predictions: [] });
  
  try {
    const url = `https://maps.googleapis.com/maps/api/place/autocomplete/json?input=${encodeURIComponent(input)}&types=establishment&components=country:tr&language=tr&key=${GOOGLE_MAPS_API_KEY}`;
    const response = await fetch(url);
    res.json(await response.json());
  } catch (err) {
    console.error('Places autocomplete error:', err);
    res.json({ predictions: [] });
  }
});

app.get('/api/places/details', auth, async (req, res) => {
  if (!GOOGLE_MAPS_API_KEY) return res.json({ result: null });
  
  const { place_id } = req.query;
  if (!place_id) return res.json({ result: null });
  
  try {
    const url = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${place_id}&fields=name,formatted_address,address_components,formatted_phone_number&language=tr&key=${GOOGLE_MAPS_API_KEY}`;
    const response = await fetch(url);
    const data = await response.json();
    
    let city = '', district = '';
    if (data.result?.address_components) {
      data.result.address_components.forEach(c => {
        if (c.types.includes('administrative_area_level_1')) city = c.long_name;
        if (c.types.includes('administrative_area_level_2') || c.types.includes('locality')) district = c.long_name;
      });
    }
    
    res.json({ ...data, parsed: { city, district } });
  } catch (err) {
    console.error('Places details error:', err);
    res.json({ result: null });
  }
});

// =====================================================
// HEALTH & STATIC (Uptime Monitor için)
// =====================================================

app.get('/health', (req, res) => res.json({ 
  ok: true, 
  version: '6.0.0',
  service: 'G360 CRM',
  db: !!supabase,
  timestamp: new Date().toISOString()
}));

app.get('/ping', (req, res) => res.send('pong'));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// =====================================================
// START SERVER
// =====================================================

app.listen(PORT, async () => {
  console.log('════════════════════════════════════════');
  console.log('   G360 CRM + Mail v6.0');
  console.log('   c.g360.ai');
  console.log('════════════════════════════════════════');
  console.log(`   Port: ${PORT}`);
  console.log(`   Supabase: ${supabase ? '✓ Bağlı' : '✗ Bağlantı yok'}`);
  console.log(`   Resend: ${RESEND_API_KEY ? '✓ Aktif' : '✗ Ayarlanmamış'}`);
  console.log(`   Google Maps: ${GOOGLE_MAPS_API_KEY ? '✓ Aktif' : '✗ Ayarlanmamış'}`);
  console.log('════════════════════════════════════════');
  await initData();
});
