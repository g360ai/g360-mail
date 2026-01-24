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
const JWT_SECRET = process.env.JWT_SECRET || 'g360-secret-2024';
const GOOGLE_MAPS_API_KEY = process.env.GOOGLE_MAPS_API_KEY || '';

// Supabase client
const supabase = SUPABASE_URL && SUPABASE_KEY ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// SABİT VERİLER
const CATEGORIES = [
  { id: 1, name: 'Otel' }, { id: 2, name: 'Restoran' }, { id: 3, name: 'Mobilya' },
  { id: 4, name: 'Kafe / Kahve Dükkanı' }, { id: 5, name: 'Eğitim' }, { id: 6, name: 'Güzellik Salonu' },
  { id: 7, name: 'Kuyumcu' }, { id: 8, name: 'Kırtasiye' }, { id: 9, name: 'Pet Shop' },
  { id: 10, name: 'Spor Salonu' }, { id: 11, name: 'Optik' }, { id: 12, name: 'Klinik' },
  { id: 13, name: 'Beyaz Eşya' }, { id: 14, name: 'Market' }, { id: 15, name: 'Otomotiv' },
  { id: 16, name: 'Yapı Market' }, { id: 17, name: 'Cep Telefonu' }, { id: 18, name: 'Eczane' },
  { id: 19, name: 'Giyim' }, { id: 20, name: 'Pub / Bar' }, { id: 21, name: 'Aydınlatma' }, { id: 22, name: 'Çiçekçi' }
];

const STATUSES = [
  { id: 1, name: 'Müşteri Bilgilendirildi', color: '#eab308' },
  { id: 2, name: 'Çekim Tarihi Belirlendi', color: '#3b82f6' },
  { id: 3, name: 'Çekim Yapıldı', color: '#8b5cf6' },
  { id: 4, name: 'Müşteri Çekimi Onayladı', color: '#f97316' },
  { id: 5, name: 'İlgilenmiyor', color: '#ef4444' },
  { id: 6, name: 'Tamamlandı', color: '#22c55e' }
];

// DATABASE HELPERS
async function getAll(table, useIsDeleted = true) {
  if (!supabase) return [];
  try {
    let query = supabase.from(table).select('*');
    if (useIsDeleted) {
      query = query.or('is_deleted.is.null,is_deleted.eq.false');
    }
    const { data, error } = await query;
    if (error) { console.error(`getAll ${table}:`, error.message); return []; }
    return data || [];
  } catch (err) { console.error(`getAll ${table}:`, err.message); return []; }
}

async function getById(table, id) {
  if (!supabase) return null;
  try {
    const { data, error } = await supabase.from(table).select('*').eq('id', id).single();
    return error ? null : data;
  } catch { return null; }
}

async function insert(table, record) {
  if (!supabase) return null;
  try {
    record.id = record.id || uuidv4();
    record.created_at = new Date().toISOString();
    // is_deleted kolonunu yalnızca açıkça belirtilmişse ekle
    if (record.is_deleted === undefined) {
      record.is_deleted = false;
    }
    const { data, error } = await supabase.from(table).insert(record).select().single();
    if (error) { 
      console.error(`Insert ${table}:`, error.message);
      // is_deleted kolonu yoksa tekrar dene
      if (error.message.includes('is_deleted')) {
        delete record.is_deleted;
        const { data: data2, error: error2 } = await supabase.from(table).insert(record).select().single();
        if (error2) { console.error(`Insert ${table} retry:`, error2.message); return null; }
        return data2;
      }
      return null; 
    }
    return data;
  } catch (err) { console.error(`Insert ${table}:`, err.message); return null; }
}

async function update(table, id, updates) {
  if (!supabase) return null;
  try {
    updates.updated_at = new Date().toISOString();
    const { data, error } = await supabase.from(table).update(updates).eq('id', id).select().single();
    if (error) { console.error(`Update ${table}:`, error.message); return null; }
    return data;
  } catch (err) { console.error(`Update ${table}:`, err.message); return null; }
}

async function softDelete(table, id) {
  if (!supabase) return false;
  const { error } = await supabase.from(table).update({ is_deleted: true, updated_at: new Date().toISOString() }).eq('id', id);
  return !error;
}

async function getByField(table, field, value) {
  if (!supabase) return null;
  try {
    const { data, error } = await supabase.from(table).select('*').eq(field, value).or('is_deleted.is.null,is_deleted.eq.false').single();
    return error ? null : data;
  } catch { return null; }
}

async function getSetting(key) {
  if (!supabase) return null;
  try {
    const { data } = await supabase.from('settings').select('value').eq('key', key).single();
    return data?.value || null;
  } catch { return null; }
}

async function setSetting(key, value) {
  if (!supabase) return;
  const existing = await getSetting(key);
  if (existing !== null) {
    await supabase.from('settings').update({ value, updated_at: new Date().toISOString() }).eq('key', key);
  } else {
    await supabase.from('settings').insert({ key, value, created_at: new Date().toISOString() });
  }
}

// INIT
async function initData() {
  if (!supabase) { console.log('⚠️  Supabase yok!'); return; }
  try {
    const { error } = await supabase.from('users').select('id').limit(1);
    if (error) { console.log('⚠️  Tablolar bulunamadı. supabase-setup.sql çalıştırın.'); return; }
    const admin = await getByField('users', 'username', 'burakkaan48');
    if (!admin) {
      await insert('users', { username: 'burakkaan48', password: bcrypt.hashSync('admin123', 10), full_name: 'Burak Kaan Kök', role: 'admin', team_id: null, is_active: true });
      console.log('✓ Admin oluşturuldu');
    }
    console.log('✓ Veritabanı hazır');
  } catch (err) { console.error('initData:', err.message); }
}

// AUTH MIDDLEWARE
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

// SEND EMAIL
async function sendMail(to, subject, html) {
  if (!RESEND_API_KEY) throw new Error('RESEND_API_KEY ayarlanmamış');
  const sig = await getSetting('signature');
  if (sig) html += sig;
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: `${FROM_NAME} <${FROM_EMAIL}>`, reply_to: FROM_EMAIL, to: [to], subject, html, text: html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim() })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Mail gönderilemedi');
  return data;
}

// AUTH ROUTES
app.post('/api/auth/login', async (req, res) => {
  try {
    const u = await getByField('users', 'username', req.body.username);
    if (!u || !u.is_active || !bcrypt.compareSync(req.body.password, u.password)) return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı' });
    const teams = await getAll('teams');
    const team = teams.find(t => t.id === u.team_id);
    const token = jwt.sign({ id: u.id, username: u.username, role: u.role, full_name: u.full_name, team_id: u.team_id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { ...u, password: undefined, team_name: team?.name } });
  } catch (err) { res.status(500).json({ error: 'Giriş yapılamadı' }); }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const u = await getById('users', req.user.id);
  if (!u) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
  const teams = await getAll('teams');
  res.json({ ...u, password: undefined, team_name: teams.find(t => t.id === u.team_id)?.name });
});

app.put('/api/auth/password', auth, async (req, res) => {
  const u = await getById('users', req.user.id);
  if (!u || !bcrypt.compareSync(req.body.current_password, u.password)) return res.status(400).json({ error: 'Mevcut şifre hatalı' });
  await update('users', req.user.id, { password: bcrypt.hashSync(req.body.new_password, 10) });
  res.json({ ok: true });
});

// TEAMS
app.get('/api/teams', auth, async (req, res) => res.json(await getAll('teams')));
app.post('/api/teams', auth, adminOnly, async (req, res) => { const r = await insert('teams', { name: req.body.name }); r ? res.json(r) : res.status(500).json({ error: 'Ekip oluşturulamadı' }); });
app.delete('/api/teams/:id', auth, adminOnly, async (req, res) => { await softDelete('teams', req.params.id); res.json({ ok: true }); });

// USERS
app.get('/api/users', auth, async (req, res) => {
  let users = await getAll('users');
  const teams = await getAll('teams');
  if (req.user.role === 'manager') users = users.filter(u => u.team_id === req.user.team_id);
  else if (req.user.role === 'sales') users = users.filter(u => u.id === req.user.id);
  res.json(users.map(u => ({ ...u, password: undefined, team_name: teams.find(t => t.id === u.team_id)?.name })));
});

app.post('/api/users', auth, adminOnly, async (req, res) => {
  if (await getByField('users', 'username', req.body.username)) return res.status(400).json({ error: 'Kullanıcı adı mevcut' });
  const u = await insert('users', { username: req.body.username, password: bcrypt.hashSync(req.body.password, 10), full_name: req.body.full_name, role: req.body.role || 'sales', team_id: req.body.team_id || null, is_active: true });
  u ? res.json({ ...u, password: undefined }) : res.status(500).json({ error: 'Kullanıcı oluşturulamadı' });
});

app.put('/api/users/:id', auth, adminOnly, async (req, res) => {
  const updates = { full_name: req.body.full_name, role: req.body.role, team_id: req.body.team_id || null, is_active: req.body.is_active !== undefined ? req.body.is_active : true };
  if (req.body.password) updates.password = bcrypt.hashSync(req.body.password, 10);
  await update('users', req.params.id, updates);
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth, adminOnly, async (req, res) => { await softDelete('users', req.params.id); res.json({ ok: true }); });

// TEMPLATES
app.get('/api/templates', auth, async (req, res) => res.json((await getAll('templates')).filter(t => t.is_active)));
app.get('/api/templates/:id', auth, async (req, res) => { const t = await getById('templates', req.params.id); t ? res.json(t) : res.status(404).json({ error: 'Taslak bulunamadı' }); });

app.post('/api/templates', auth, adminOnly, async (req, res) => {
  const matches = (req.body.subject + ' ' + req.body.body).match(/\{\{(\w+)\}\}/g) || [];
  const variables = [...new Set(matches.map(m => m.slice(2, -2)))];
  const r = await insert('templates', { name: req.body.name, subject: req.body.subject, body: req.body.body, variables, is_active: true });
  r ? res.json(r) : res.status(500).json({ error: 'Taslak oluşturulamadı' });
});

app.put('/api/templates/:id', auth, adminOnly, async (req, res) => {
  const matches = (req.body.subject + ' ' + req.body.body).match(/\{\{(\w+)\}\}/g) || [];
  const variables = [...new Set(matches.map(m => m.slice(2, -2)))];
  const r = await update('templates', req.params.id, { name: req.body.name, subject: req.body.subject, body: req.body.body, variables });
  r ? res.json(r) : res.status(500).json({ error: 'Taslak güncellenemedi' });
});

app.delete('/api/templates/:id', auth, adminOnly, async (req, res) => { await update('templates', req.params.id, { is_active: false }); res.json({ ok: true }); });

// SETTINGS
app.get('/api/settings', auth, async (req, res) => res.json({ signature: await getSetting('signature') || '' }));
app.post('/api/settings', auth, adminOnly, async (req, res) => { if (req.body.signature !== undefined) await setSetting('signature', req.body.signature); res.json({ ok: true }); });

// CATEGORIES & STATUSES
app.get('/api/categories', auth, (req, res) => res.json(CATEGORIES));
app.get('/api/statuses', auth, (req, res) => res.json(STATUSES));

// CUSTOMERS
app.get('/api/customers', auth, async (req, res) => {
  if (!supabase) return res.json([]);
  try {
    let query = supabase.from('customers').select('*').or('is_deleted.is.null,is_deleted.eq.false');
    if (req.user.role === 'sales') query = query.eq('user_id', req.user.id);
    else if (req.user.role === 'manager') {
      const users = await getAll('users');
      const ids = users.filter(u => u.team_id === req.user.team_id).map(u => u.id);
      if (ids.length) query = query.in('user_id', ids);
    }
    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    const users = await getAll('users');
    res.json((data || []).map(c => ({ ...c, user_name: users.find(u => u.id === c.user_id)?.full_name, category: CATEGORIES.find(cat => cat.id === c.category_id), status_info: STATUSES.find(s => s.id === c.status) })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/customers/:id', auth, async (req, res) => {
  const c = await getById('customers', req.params.id);
  if (!c) return res.status(404).json({ error: 'Müşteri bulunamadı' });
  const users = await getAll('users');
  res.json({ ...c, user_name: users.find(u => u.id === c.user_id)?.full_name, category: CATEGORIES.find(cat => cat.id === c.category_id), status_info: STATUSES.find(s => s.id === c.status) });
});

app.post('/api/customers', auth, async (req, res) => {
  try {
    const { category_id, business_name, place_id, address, city, district, contact_name, phone, email, tax_number, price, is_invoiced, scene_count, notes } = req.body;
    let priceVal = parseFloat(price) || 0, priceWithoutVat = priceVal, vatAmount = 0;
    if (is_invoiced && priceVal > 0) { priceWithoutVat = priceVal / 1.20; vatAmount = priceVal - priceWithoutVat; }
    const customer = await insert('customers', { user_id: req.user.id, category_id: parseInt(category_id), business_name, place_id: place_id || null, address: address || null, city: city || null, district: district || null, contact_name: contact_name || null, phone: phone || null, email: email || null, tax_number: tax_number || null, price: priceVal, price_without_vat: Math.round(priceWithoutVat * 100) / 100, vat_amount: Math.round(vatAmount * 100) / 100, is_invoiced: is_invoiced || false, scene_count: parseInt(scene_count) || 1, status: 1, notes: notes || null });
    if (!customer) return res.status(500).json({ error: 'Müşteri oluşturulamadı. Veritabanı tablolarını kontrol edin.' });
    res.json({ ...customer, category: CATEGORIES.find(cat => cat.id === customer.category_id), status_info: STATUSES.find(s => s.id === customer.status) });
  } catch (err) { console.error('Create customer:', err); res.status(500).json({ error: err.message }); }
});

app.put('/api/customers/:id', auth, async (req, res) => {
  try {
    const c = await getById('customers', req.params.id);
    if (!c) return res.status(404).json({ error: 'Müşteri bulunamadı' });
    if (req.user.role !== 'admin' && c.user_id !== req.user.id) return res.status(403).json({ error: 'Yetki yok' });
    const { category_id, business_name, place_id, address, city, district, contact_name, phone, email, tax_number, price, is_invoiced, scene_count, notes, status } = req.body;
    let priceVal = parseFloat(price) || 0, priceWithoutVat = priceVal, vatAmount = 0;
    if (is_invoiced && priceVal > 0) { priceWithoutVat = priceVal / 1.20; vatAmount = priceVal - priceWithoutVat; }
    const updated = await update('customers', req.params.id, { category_id: parseInt(category_id), business_name, place_id: place_id || null, address: address || null, city: city || null, district: district || null, contact_name: contact_name || null, phone: phone || null, email: email || null, tax_number: tax_number || null, price: priceVal, price_without_vat: Math.round(priceWithoutVat * 100) / 100, vat_amount: Math.round(vatAmount * 100) / 100, is_invoiced: is_invoiced || false, scene_count: parseInt(scene_count) || 1, status: parseInt(status) || c.status, notes: notes || null });
    if (!updated) return res.status(500).json({ error: 'Müşteri güncellenemedi' });
    res.json({ ...updated, category: CATEGORIES.find(cat => cat.id === updated.category_id), status_info: STATUSES.find(s => s.id === updated.status) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/customers/:id/status', auth, async (req, res) => {
  const c = await getById('customers', req.params.id);
  if (!c) return res.status(404).json({ error: 'Müşteri bulunamadı' });
  if (req.user.role !== 'admin' && c.user_id !== req.user.id) return res.status(403).json({ error: 'Yetki yok' });
  const newStatus = parseInt(req.body.status);
  if (!STATUSES.find(s => s.id === newStatus)) return res.status(400).json({ error: 'Geçersiz durum' });
  const updated = await update('customers', req.params.id, { status: newStatus });
  res.json({ ...updated, status_info: STATUSES.find(s => s.id === updated.status) });
});

app.delete('/api/customers/:id', auth, adminOnly, async (req, res) => {
  const c = await getById('customers', req.params.id);
  if (!c) return res.status(404).json({ error: 'Müşteri bulunamadı' });
  await softDelete('customers', req.params.id);
  res.json({ ok: true });
});

// Soft delete endpoint (sadece admin)
app.patch('/api/customers/:id/soft-delete', auth, adminOnly, async (req, res) => {
  const c = await getById('customers', req.params.id);
  if (!c) return res.status(404).json({ error: 'Müşteri bulunamadı' });
  const updated = await update('customers', req.params.id, { 
    is_deleted: true, 
    deleted_at: new Date().toISOString() 
  });
  if (!updated) return res.status(500).json({ error: 'Müşteri silinemedi' });
  res.json({ ok: true });
});

// Silinen müşterileri listele (sadece admin)
app.get('/api/customers/deleted', auth, adminOnly, async (req, res) => {
  if (!supabase) return res.json([]);
  try {
    const { data, error } = await supabase.from('customers')
      .select('*')
      .eq('is_deleted', true)
      .order('deleted_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    const users = await getAll('users');
    // 30 günden eski silinenleri filtrele (kalıcı silme için)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const filtered = (data || []).filter(c => {
      if (!c.deleted_at) return true;
      return new Date(c.deleted_at) > thirtyDaysAgo;
    });
    res.json(filtered.map(c => ({ 
      ...c, 
      user_name: users.find(u => u.id === c.user_id)?.full_name, 
      category: CATEGORIES.find(cat => cat.id === c.category_id), 
      status_info: STATUSES.find(s => s.id === c.status) 
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Müşteriyi geri al (sadece admin)
app.patch('/api/customers/:id/restore', auth, adminOnly, async (req, res) => {
  if (!supabase) return res.status(500).json({ error: 'Veritabanı bağlantısı yok' });
  try {
    const { data: c, error: fetchError } = await supabase.from('customers')
      .select('*')
      .eq('id', req.params.id)
      .single();
    if (fetchError || !c) return res.status(404).json({ error: 'Müşteri bulunamadı' });
    
    // 30 gün kontrolü
    if (c.deleted_at) {
      const deletedDate = new Date(c.deleted_at);
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      if (deletedDate < thirtyDaysAgo) {
        return res.status(400).json({ error: '30 günden fazla geçmiş, geri alınamaz' });
      }
    }
    
    const updated = await update('customers', req.params.id, { 
      is_deleted: false, 
      deleted_at: null 
    });
    if (!updated) return res.status(500).json({ error: 'Müşteri geri alınamadı' });
    res.json({ ok: true, customer: updated });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// EMAILS
app.get('/api/emails', auth, async (req, res) => {
  let emails = await getAll('emails');
  const users = await getAll('users');
  if (req.user.role === 'manager') { const ids = users.filter(u => u.team_id === req.user.team_id).map(u => u.id); emails = emails.filter(e => ids.includes(e.user_id)); }
  else if (req.user.role === 'sales') emails = emails.filter(e => e.user_id === req.user.id);
  res.json(emails.map(e => ({ ...e, sender_name: users.find(u => u.id === e.user_id)?.full_name })).sort((a, b) => new Date(b.sent_at) - new Date(a.sent_at)));
});

app.get('/api/emails/:id', auth, async (req, res) => { const e = await getById('emails', req.params.id); e ? res.json(e) : res.status(404).json({ error: 'Mail bulunamadı' }); });

app.post('/api/emails/send', auth, async (req, res) => {
  try {
    const templates = await getAll('templates');
    const t = templates.find(x => x.id === req.body.template_id);
    if (!t) return res.status(404).json({ error: 'Taslak bulunamadı' });
    let subject = t.subject, body = t.body;
    const vars = req.body.variables || {};
    Object.keys(vars).forEach(k => { const re = new RegExp('\\{\\{' + k + '\\}\\}', 'g'); subject = subject.replace(re, vars[k]); body = body.replace(re, vars[k]); });
    
    let resendResult = null, sendError = null;
    try { resendResult = await sendMail(req.body.recipient_email, subject, body); } catch (err) { sendError = err.message; }
    
    // Email kaydı - customer_id opsiyonel
    const emailData = { 
      user_id: req.user.id, 
      template_id: req.body.template_id, 
      template_name: t.name, 
      recipient_email: req.body.recipient_email, 
      recipient_name: req.body.recipient_name || null, 
      subject, 
      body, 
      variables_used: vars, 
      status: resendResult ? 'sent' : 'failed', 
      resend_id: resendResult?.id || null, 
      error: sendError,
      sent_at: new Date().toISOString() 
    };
    
    // customer_id varsa ekle (kolon varsa)
    if (req.body.customer_id) {
      emailData.customer_id = req.body.customer_id;
    }
    
    const savedEmail = await insert('emails', emailData);
    
    if (sendError) return res.status(500).json({ error: sendError });
    res.json({ ok: true, id: resendResult?.id, email_id: savedEmail?.id });
  } catch (err) { console.error('Send email:', err); res.status(500).json({ error: err.message }); }
});

// STATS
app.get('/api/stats', auth, async (req, res) => {
  try {
    let customers = await getAll('customers'), emails = await getAll('emails');
    const users = await getAll('users');
    if (req.user.role === 'manager') { const ids = users.filter(u => u.team_id === req.user.team_id).map(u => u.id); customers = customers.filter(c => ids.includes(c.user_id)); emails = emails.filter(e => ids.includes(e.user_id)); }
    else if (req.user.role === 'sales') { customers = customers.filter(c => c.user_id === req.user.id); emails = emails.filter(e => e.user_id === req.user.id); }
    const now = new Date(), today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000), monthAgo = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);
    const completed = customers.filter(c => c.status === 6);
    res.json({
      totalCustomers: customers.length, newToday: customers.filter(c => new Date(c.created_at) >= today).length,
      completedCount: completed.length, totalEmails: emails.length, sentEmails: emails.filter(e => e.status === 'sent').length,
      todayRevenue: completed.filter(c => new Date(c.updated_at || c.created_at) >= today).reduce((s, c) => s + (c.price || 0), 0),
      weekRevenue: completed.filter(c => new Date(c.updated_at || c.created_at) >= weekAgo).reduce((s, c) => s + (c.price || 0), 0),
      monthRevenue: completed.filter(c => new Date(c.updated_at || c.created_at) >= monthAgo).reduce((s, c) => s + (c.price || 0), 0),
      totalRevenue: completed.reduce((s, c) => s + (c.price || 0), 0),
      byStatus: STATUSES.map(s => ({ ...s, count: customers.filter(c => c.status === s.id).length })),
      recentCustomers: customers.slice(0, 5).map(c => ({ id: c.id, business_name: c.business_name, city: c.city, price: c.price, status: c.status, status_info: STATUSES.find(s => s.id === c.status) }))
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GOOGLE PLACES
app.get('/api/places/autocomplete', auth, async (req, res) => {
  if (!GOOGLE_MAPS_API_KEY) return res.json({ predictions: [] });
  const { input } = req.query;
  if (!input || input.length < 2) return res.json({ predictions: [] });
  try {
    const url = `https://maps.googleapis.com/maps/api/place/autocomplete/json?input=${encodeURIComponent(input)}&types=establishment&components=country:tr&language=tr&key=${GOOGLE_MAPS_API_KEY}`;
    const response = await fetch(url);
    res.json(await response.json());
  } catch { res.json({ predictions: [] }); }
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
  } catch { res.json({ result: null }); }
});

// HEALTH
app.get('/health', (req, res) => res.json({ ok: true, version: '6.0.0', db: !!supabase, timestamp: new Date().toISOString() }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// START
app.listen(PORT, async () => {
  console.log('════════════════════════════════════════');
  console.log('   G360 CRM + Mail v6.0');
  console.log('════════════════════════════════════════');
  console.log(`   Port: ${PORT}`);
  console.log(`   Supabase: ${supabase ? '✓' : '✗'}`);
  console.log(`   Resend: ${RESEND_API_KEY ? '✓' : '✗'}`);
  console.log(`   Google Maps: ${GOOGLE_MAPS_API_KEY ? '✓' : '✗'}`);
  console.log('════════════════════════════════════════');
  await initData();
});
