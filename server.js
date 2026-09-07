import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import pg from 'pg';
import crypto from 'crypto';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import webpush from 'web-push';

dotenv.config();
const { Pool } = pg;
const app = express();
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET || '';
if (!JWT_SECRET) console.warn('WARNING: JWT_SECRET is missing. Set a strong secret in Render.');
const STRIPE_SECRET_KEY = String(process.env.STRIPE_SECRET_KEY || '').trim();
const STRIPE_WEBHOOK_SECRET = String(process.env.STRIPE_WEBHOOK_SECRET || '').trim();
const PAYPAL_CLIENT_ID = String(process.env.PAYPAL_CLIENT_ID || '').trim();
const PAYPAL_CLIENT_SECRET = String(process.env.PAYPAL_CLIENT_SECRET || '').trim();
const PAYPAL_ENV = String(process.env.PAYPAL_ENV || 'sandbox').toLowerCase() === 'live' ? 'live' : 'sandbox';
const PAYPAL_BASE = PAYPAL_ENV === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
const VAPID_PUBLIC_KEY = String(process.env.VAPID_PUBLIC_KEY || '').trim();
const VAPID_PRIVATE_KEY = String(process.env.VAPID_PRIVATE_KEY || '').trim();
const VAPID_SUBJECT = String(process.env.VAPID_SUBJECT || 'mailto:admin@zhuomarket.com').trim();
if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

const allowed = (process.env.CORS_ORIGINS || '*').split(',').map(s => s.trim()).filter(Boolean);
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet());
app.use(cors({
  origin(origin, cb) {
    if (!origin || allowed.includes('*') || allowed.includes(origin)) return cb(null, true);
    return cb(new Error('CORS origin not allowed'));
  },
  credentials: true
}));

// Stripe webhooks need the raw body for signature verification.
app.post('/api/webhooks/stripe', express.raw({type:'application/json',limit:'2mb'}), async (req,res)=>{
  try{
    if(!STRIPE_WEBHOOK_SECRET)return res.status(503).send('Stripe webhook not configured');
    const sig=String(req.headers['stripe-signature']||'');
    const payload=req.body instanceof Buffer?req.body:Buffer.from(String(req.body||''));
    const parts=Object.fromEntries(sig.split(',').map(x=>x.split('=').map(String)));
    const timestamp=Number(parts.t||0); const v1=parts.v1||'';
    if(!timestamp||!v1||Math.abs(Date.now()/1000-timestamp)>300)return res.status(400).send('Invalid signature');
    const signed=`${timestamp}.${payload.toString('utf8')}`;
    const expected=crypto.createHmac('sha256',STRIPE_WEBHOOK_SECRET).update(signed).digest('hex');
    if(!crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(v1)))return res.status(400).send('Invalid signature');
    const event=JSON.parse(payload.toString('utf8'));
    const obj=event?.data?.object||{};
    const orderId=obj?.metadata?.order_id||obj?.client_reference_id||null;
    if(event.type==='checkout.session.completed' && orderId){
      const ref=obj.payment_intent||obj.id;
      const r=await q("UPDATE orders SET payment_status='paid',payment_reference=$1,paid_at=now(),updated_at=now() WHERE id=$2 RETURNING *",[String(ref||''),orderId]);
      if(r.rowCount&&r.rows[0].user_id)await insertNotification({userId:r.rows[0].user_id,title:'Paiement confirmé',message:`Le paiement de ta commande ${orderId.slice(0,8)} est confirmé.`,type:'payment',severity:'normal',entityType:'order',entityId:orderId,force:true});
    }
    if(event.type==='payment_intent.payment_failed' && orderId){
      await q("UPDATE orders SET payment_status='failed',updated_at=now() WHERE id=$1",[orderId]);
      try{await restoreOrderStock(orderId)}catch(e){console.warn('stock restore after Stripe failure:',e.message)}
      const o=await q('SELECT user_id FROM orders WHERE id=$1',[orderId]);if(o.rowCount&&o.rows[0].user_id)await insertNotification({userId:o.rows[0].user_id,title:'Paiement échoué',message:`Le paiement de ta commande ${orderId.slice(0,8)} a échoué.`,type:'payment',severity:'high',entityType:'order',entityId:orderId,force:true});
    }
    res.json({received:true});
  }catch(e){console.error('Stripe webhook:',e.message);res.status(400).send('Webhook error');}
});
app.use(express.json({ limit: '2mb', strict: true }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 80, standardHeaders: true, legacyHeaders: false, message: { message: 'Trop de tentatives. Réessaie plus tard.' } });
const publicLimiter = rateLimit({ windowMs: 60 * 1000, limit: 240, standardHeaders: true, legacyHeaders: false, message: { message: 'Trop de requêtes. Réessaie dans un instant.' } });
app.use(publicLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/chatbot', rateLimit({ windowMs: 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));

if (!process.env.DATABASE_URL) console.warn('DATABASE_URL is missing. Render must provide a PostgreSQL connection string.');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: Number(process.env.DB_POOL_MAX || 10),
  idleTimeoutMillis: 30000
});

const q = (text, params = []) => pool.query(text, params);
const id = () => crypto.randomUUID();
const now = () => new Date();
const clean = (v, max = 500) => String(v ?? '').trim().slice(0, max);
const num = (v, d = 0) => Number.isFinite(Number(v)) ? Number(v) : d;
const bool = (v, d = false) => typeof v === 'boolean' ? v : (v == null ? d : String(v).toLowerCase() === 'true');
function parseJson(v, fallback) { try { return typeof v === 'string' ? JSON.parse(v) : (v ?? fallback); } catch { return fallback; } }
function publicUser(r) { return { id: r.id, name: r.name, email: r.email, role: r.role, isAdmin: ['admin','owner'].includes(String(r.role||'').toLowerCase()), avatar: r.avatar || null, createdAt: r.created_at }; }
function sign(user) { return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES || '7d' }); }
function productOut(r) { return {
  id: r.id, brand: r.brand, model: r.model, name: r.model, image: r.image || '', images: parseJson(r.images, []),
  price: num(r.price), currency: String(r.currency || 'USD').toUpperCase() === 'HTG' ? 'HTG' : 'USD', oldPrice: num(r.old_price), discount: num(r.discount), stock: Number(r.stock || 0),
  storage: parseJson(r.storage, []), capacities: parseJson(r.storage, []), colors: parseJson(r.colors, []),
  specifications: parseJson(r.specifications, {}), specs: parseJson(r.specifications, {}), description: r.description || '',
  createdAt: r.created_at, updatedAt: r.updated_at, tradeEnabled: !!r.trade_enabled
}; }
function notificationOut(r) { return { ...r, createdAt: r.created_at, seenAt: r.seen_at, lastRemindedAt: r.last_reminded_at, remindEveryMinutes: Number(r.remind_every_minutes || 10) }; }
async function sendPushToUser(userId,payload){
  if(!VAPID_PUBLIC_KEY||!VAPID_PRIVATE_KEY||!userId)return;
  try{
    const r=await q('SELECT id,endpoint,p256dh,auth FROM push_subscriptions WHERE user_id=$1',[userId]);
    for(const sub of r.rows){
      try{await webpush.sendNotification({endpoint:sub.endpoint,keys:{p256dh:sub.p256dh,auth:sub.auth}},JSON.stringify(payload),{TTL:300});}
      catch(e){if([404,410].includes(e.statusCode))await q('DELETE FROM push_subscriptions WHERE id=$1',[sub.id]);else console.warn('push send failed:',e.message);}
    }
  }catch(e){console.warn('push lookup failed:',e.message)}
}


async function ensureColumn(table, column, sqlType) {
  await q(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${column} ${sqlType}`);
}

async function initDb() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY, name text NOT NULL, email text UNIQUE NOT NULL, password_hash text NOT NULL,
    role text NOT NULL DEFAULT 'customer', avatar text, created_at timestamptz NOT NULL DEFAULT now()
  )`);
  await ensureColumn('users', 'updated_at', 'timestamptz NOT NULL DEFAULT now()');

  await q(`CREATE TABLE IF NOT EXISTS products (
    id uuid PRIMARY KEY, brand text NOT NULL, model text NOT NULL, image text, images jsonb NOT NULL DEFAULT '[]',
    price numeric NOT NULL DEFAULT 0, currency text NOT NULL DEFAULT 'USD', old_price numeric NOT NULL DEFAULT 0, discount numeric NOT NULL DEFAULT 0,
    stock integer NOT NULL DEFAULT 0, storage jsonb NOT NULL DEFAULT '[]', colors jsonb NOT NULL DEFAULT '[]',
    specifications jsonb NOT NULL DEFAULT '{}', description text DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
  )`);
  await ensureColumn('products', 'currency', "text NOT NULL DEFAULT 'USD'");
  await ensureColumn('products', 'trade_enabled', "boolean NOT NULL DEFAULT false");

  await q(`CREATE TABLE IF NOT EXISTS promotions (
    id uuid PRIMARY KEY, product_id uuid REFERENCES products(id) ON DELETE SET NULL, title text NOT NULL, description text DEFAULT '', image text DEFAULT '',
    images jsonb NOT NULL DEFAULT '[]', price numeric NOT NULL DEFAULT 0, old_price numeric NOT NULL DEFAULT 0,
    discount numeric NOT NULL DEFAULT 0, start_date date, end_date date, status text NOT NULL DEFAULT 'published', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
  )`);
  await ensureColumn('promotions', 'product_id', 'uuid');
  await ensureColumn('promotions', 'images', "jsonb NOT NULL DEFAULT '[]'");
  await ensureColumn('promotions', 'price', 'numeric NOT NULL DEFAULT 0');
  await ensureColumn('promotions', 'old_price', 'numeric NOT NULL DEFAULT 0');
  await ensureColumn('promotions', 'start_date', 'date');
  await ensureColumn('promotions', 'end_date', 'date');
  await ensureColumn('promotions', 'updated_at', 'timestamptz NOT NULL DEFAULT now()');
  await ensureColumn('promotions', 'duration_seconds', 'integer NOT NULL DEFAULT 6');
  await q(`CREATE TABLE IF NOT EXISTS orders (
    id uuid PRIMARY KEY, user_id uuid REFERENCES users(id) ON DELETE SET NULL, items jsonb NOT NULL DEFAULT '[]',
    customer jsonb NOT NULL DEFAULT '{}', payment_method text DEFAULT 'cash_on_delivery', payment_status text DEFAULT 'pending',
    payment_reference text, paid_at timestamptz, total numeric NOT NULL DEFAULT 0, currency text NOT NULL DEFAULT 'USD', service_order jsonb DEFAULT NULL,
    status text NOT NULL DEFAULT 'En préparation', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
  )`);
  await ensureColumn('orders', 'payment_status', "text DEFAULT 'pending'");
  await ensureColumn('orders', 'payment_reference', 'text');
  await ensureColumn('orders', 'paid_at', 'timestamptz');
  await ensureColumn('orders', 'updated_at', 'timestamptz NOT NULL DEFAULT now()');
  await ensureColumn('orders', 'currency', "text NOT NULL DEFAULT 'USD'");
  await ensureColumn('orders', 'service_order', 'jsonb');
  await ensureColumn('orders', 'stock_restored', 'boolean NOT NULL DEFAULT false');

  await q(`CREATE TABLE IF NOT EXISTS order_events (
    id uuid PRIMARY KEY, order_id uuid REFERENCES orders(id) ON DELETE CASCADE, user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    event_type text NOT NULL, old_status text, new_status text, message text DEFAULT '', created_at timestamptz NOT NULL DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS notifications (
    id uuid PRIMARY KEY, user_id uuid REFERENCES users(id) ON DELETE CASCADE, title text NOT NULL,
    message text NOT NULL, type text DEFAULT 'info', severity text DEFAULT 'normal', read boolean NOT NULL DEFAULT false,
    seen_at timestamptz, last_reminded_at timestamptz, remind_every_minutes integer NOT NULL DEFAULT 10,
    entity_type text, entity_id text, action_url text, created_at timestamptz NOT NULL DEFAULT now()
  )`);
  await ensureColumn('notifications', 'seen_at', 'timestamptz');
  await ensureColumn('notifications', 'last_reminded_at', 'timestamptz');
  await ensureColumn('notifications', 'remind_every_minutes', 'integer NOT NULL DEFAULT 10');
  await ensureColumn('notifications', 'entity_type', 'text');
  await ensureColumn('notifications', 'entity_id', 'text');
  await ensureColumn('notifications', 'action_url', 'text');

  await q(`CREATE TABLE IF NOT EXISTS notification_preferences (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    order_updates boolean NOT NULL DEFAULT true, payment_updates boolean NOT NULL DEFAULT true,
    messages boolean NOT NULL DEFAULT true, promotions boolean NOT NULL DEFAULT true,
    security boolean NOT NULL DEFAULT true, reminder_minutes integer NOT NULL DEFAULT 10,
    updated_at timestamptz NOT NULL DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS trades (
    id uuid PRIMARY KEY, user_id uuid REFERENCES users(id) ON DELETE SET NULL, device text, storage text,
    condition text, wanted_product_id uuid REFERENCES products(id) ON DELETE SET NULL, message text,
    images jsonb NOT NULL DEFAULT '[]', status text DEFAULT 'new', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
  )`);
  await ensureColumn('trades', 'images', "jsonb NOT NULL DEFAULT '[]'");
  await ensureColumn('trades', 'updated_at', 'timestamptz NOT NULL DEFAULT now()');

  await q(`CREATE TABLE IF NOT EXISTS conversations (
    id uuid PRIMARY KEY, user_id uuid REFERENCES users(id) ON DELETE SET NULL, name text, email text,
    unread integer NOT NULL DEFAULT 0, unread_for_user integer NOT NULL DEFAULT 0, last_message text DEFAULT '',
    last_message_at timestamptz NOT NULL DEFAULT now(), created_at timestamptz NOT NULL DEFAULT now()
  )`);
  await ensureColumn('conversations', 'unread_for_user', 'integer NOT NULL DEFAULT 0');
  await q(`CREATE TABLE IF NOT EXISTS messages (
    id uuid PRIMARY KEY, conversation_id uuid REFERENCES conversations(id) ON DELETE CASCADE,
    sender text NOT NULL, sender_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    message text NOT NULL, severity text DEFAULT 'normal', urgent boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
  )`);
  await ensureColumn('messages', 'sender_user_id', 'uuid');

  await q(`CREATE TABLE IF NOT EXISTS admin_chats (
    id uuid PRIMARY KEY, admin_a_id uuid REFERENCES users(id) ON DELETE CASCADE, admin_b_id uuid REFERENCES users(id) ON DELETE CASCADE,
    unread_for_a integer NOT NULL DEFAULT 0, unread_for_b integer NOT NULL DEFAULT 0, last_message text DEFAULT '',
    last_message_at timestamptz NOT NULL DEFAULT now(), created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(admin_a_id, admin_b_id)
  )`);
  await q(`CREATE TABLE IF NOT EXISTS admin_chat_messages (
    id uuid PRIMARY KEY, chat_id uuid REFERENCES admin_chats(id) ON DELETE CASCADE, sender_id uuid REFERENCES users(id) ON DELETE SET NULL,
    message text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS app_settings (
    key text PRIMARY KEY, value jsonb NOT NULL DEFAULT '{}'
  )`);
  await q(`INSERT INTO app_settings(key,value) VALUES('trade_enabled','true'::jsonb) ON CONFLICT(key) DO NOTHING`);
  await q(`INSERT INTO app_settings(key,value) VALUES('support_admin_phone','null'::jsonb) ON CONFLICT(key) DO NOTHING`);

  await q(`CREATE TABLE IF NOT EXISTS confirmation_codes (
    id uuid PRIMARY KEY, user_id uuid REFERENCES users(id) ON DELETE CASCADE, order_id uuid REFERENCES orders(id) ON DELETE CASCADE,
    code_hash text NOT NULL, purpose text NOT NULL DEFAULT 'order_confirmation', expires_at timestamptz NOT NULL,
    used_at timestamptz, created_by uuid REFERENCES users(id) ON DELETE SET NULL, created_at timestamptz NOT NULL DEFAULT now()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS payment_methods (
    id text PRIMARY KEY, name text NOT NULL, description text DEFAULT '', enabled boolean NOT NULL DEFAULT true,
    instructions text DEFAULT '', config jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
  )`);
  await ensureColumn('payment_methods', 'instructions', "text DEFAULT ''");
  await ensureColumn('payment_methods', 'config', "jsonb NOT NULL DEFAULT '{}'");
  await ensureColumn('payment_methods', 'updated_at', 'timestamptz NOT NULL DEFAULT now()');
  await ensureColumn('payment_methods', 'provider', "text NOT NULL DEFAULT 'cash'");
  await ensureColumn('payment_methods', 'logo', "text NOT NULL DEFAULT 'cash'");
  await ensureColumn('payment_methods', 'sort_order', 'integer NOT NULL DEFAULT 100');
  await q(`INSERT INTO payment_methods(id,name,description,enabled,instructions,provider,logo,sort_order) VALUES
    ('cash_on_delivery','Paiement à la livraison','Payez à la réception.',true,'Prépare le montant exact à la livraison.','cash','cash',10),
    ('stripe_card','Carte bancaire','Visa, Mastercard et cartes prises en charge par Stripe.',${STRIPE_SECRET_KEY ? 'true' : 'false'},'Paiement sécurisé via Stripe Checkout.','stripe','stripe',20),
    ('paypal','PayPal','Payez avec votre compte PayPal.',${PAYPAL_CLIENT_ID && PAYPAL_CLIENT_SECRET ? 'true' : 'false'},'Vous serez redirigé vers PayPal pour approuver le paiement.','paypal','paypal',30),
    ('moncash','MonCash','Paiement mobile MonCash — intégration marchand à configurer.',false,'Après paiement, indique la référence de transaction pour vérification.','moncash','moncash',40),
    ('natcash','NatCash','Paiement mobile NatCash — intégration marchand à configurer.',false,'Après paiement, indique la référence de transaction pour vérification.','natcash','natcash',50)
    ON CONFLICT (id) DO UPDATE SET provider=EXCLUDED.provider,logo=EXCLUDED.logo,sort_order=EXCLUDED.sort_order`);

  await q(`CREATE TABLE IF NOT EXISTS uploads (
    id uuid PRIMARY KEY, mime_type text NOT NULL, data text NOT NULL, owner_id uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
  )`);
  await ensureColumn('uploads', 'owner_id', 'uuid');

  await q(`CREATE TABLE IF NOT EXISTS referrals (
    id uuid PRIMARY KEY, user_id uuid REFERENCES users(id) ON DELETE SET NULL, code text UNIQUE NOT NULL,
    clicks integer NOT NULL DEFAULT 0, signups integer NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS security_events (
    id uuid PRIMARY KEY, user_id uuid REFERENCES users(id) ON DELETE SET NULL, ip text, event_type text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS user_state (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, cart jsonb NOT NULL DEFAULT '[]', wishlist jsonb NOT NULL DEFAULT '[]', updated_at timestamptz NOT NULL DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS streaming_plans (
    id uuid PRIMARY KEY, service text NOT NULL CHECK (service IN ('netflix','disney')), name text NOT NULL, description text DEFAULT '', price numeric NOT NULL DEFAULT 0, currency text NOT NULL DEFAULT 'HTG', enabled boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS push_subscriptions (
    id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, endpoint text UNIQUE NOT NULL, p256dh text NOT NULL, auth text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
  )`);

  const adminEmail = clean(process.env.ADMIN_EMAIL, 200).toLowerCase();
  const ownerEmail = clean(process.env.OWNER_EMAIL || adminEmail, 200).toLowerCase();
  const adminPassword = String(process.env.ADMIN_PASSWORD || '');
  if (adminEmail && adminPassword) {
    const exists = await q('SELECT id FROM users WHERE email=$1', [adminEmail]);
    if (!exists.rowCount) {
      const hash = await bcrypt.hash(adminPassword, 12);
      await q('INSERT INTO users(id,name,email,password_hash,role) VALUES($1,$2,$3,$4,$5)', [id(), 'ZhuoMarket Admin', adminEmail, hash, adminEmail === ownerEmail ? 'owner' : 'admin']);
      console.log('Admin account created:', adminEmail);
    } else {
      await q("UPDATE users SET role=$1, updated_at=now() WHERE email=$2", [adminEmail === ownerEmail ? 'owner' : 'admin', adminEmail]);
    }
  }
}

async function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    if (!h.startsWith('Bearer ')) return res.status(401).json({ message: 'Authentification requise' });
    const payload = jwt.verify(h.slice(7), JWT_SECRET);
    const r = await q('SELECT * FROM users WHERE id=$1', [payload.id]);
    if (!r.rowCount) return res.status(401).json({ message: 'Session invalide' });
    req.user = r.rows[0];
    next();
  } catch { return res.status(401).json({ message: 'Session invalide ou expirée' }); }
}
function admin(req, res, next) { if (!['admin','owner'].includes(String(req.user?.role||'').toLowerCase())) return res.status(403).json({ message: 'Accès administrateur refusé' }); next(); }
function optAuth(req, res, next) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return next();
  try {
    const p = jwt.verify(h.slice(7), JWT_SECRET);
    q('SELECT * FROM users WHERE id=$1', [p.id]).then(r => { req.user = r.rows[0] || null; next(); }).catch(() => next());
  } catch { next(); }
}

async function insertNotification({ userId = null, title, message, type = 'info', severity = 'normal', entityType = null, entityId = null, actionUrl = null, remindEveryMinutes = null, force = false }) {
  let reminder = Number(remindEveryMinutes || 0);
  if (userId) {
    const meta = await q(`SELECT u.role,p.order_updates,p.payment_updates,p.messages,p.promotions,p.security,p.reminder_minutes FROM users u LEFT JOIN notification_preferences p ON p.user_id=u.id WHERE u.id=$1 LIMIT 1`, [userId]);
    if (meta.rowCount) {
      const row=meta.rows[0]; const role=String(row.role||'').toLowerCase();
      if (!['admin','owner'].includes(role)) {
        const key=({order:'order_updates',payment:'payment_updates',message:'messages',support:'messages',promotion:'promotions',security:'security',trade:'messages'})[String(type||'').toLowerCase()];
        if (key && row[key] === false && !force) return null;
      }
      if (!reminder) reminder=Number(row.reminder_minutes||10);
    }
  }
  if (!reminder) reminder=10;
  const r = await q(`INSERT INTO notifications(id,user_id,title,message,type,severity,read,remind_every_minutes,entity_type,entity_id,action_url)
    VALUES($1,$2,$3,$4,$5,$6,false,$7,$8,$9,$10) RETURNING *`, [id(), userId, clean(title, 160), clean(message, 800), clean(type, 50), clean(severity, 30), Math.max(1, Math.min(1440, reminder)), entityType, entityId ? String(entityId) : null, actionUrl]);
  if(userId) void sendPushToUser(userId,{title:clean(title,120),body:clean(message,300),tag:entityId?String(entityId):String(type),data:{entityType,entityId,actionUrl}});
  return r.rows[0];
}
async function notifyAllAdmins(title, message, type = 'admin', severity = 'normal', entityType = null, entityId = null) {
  const r = await q("SELECT id FROM users WHERE role IN ('admin','owner')");
  for (const row of r.rows) await insertNotification({ userId: row.id, title, message, type, severity, entityType, entityId });
}
async function ensurePrefs(userId) { await q('INSERT INTO notification_preferences(user_id) VALUES($1) ON CONFLICT(user_id) DO NOTHING', [userId]); }

app.get('/health', async (req, res) => {
  try { await q('SELECT 1'); res.json({ ok: true, service: 'zhuomarket-backend', db: 'ok', time: now().toISOString() }); }
  catch { res.status(503).json({ ok: false, service: 'zhuomarket-backend', db: 'down' }); }
});

// AUTH
app.post('/api/auth/register', async (req, res) => {
  try {
    const name = clean(req.body?.name, 120); const email = clean(req.body?.email, 200).toLowerCase(); const password = String(req.body?.password || '');
    if (!name || !/^\S+@\S+\.\S+$/.test(email) || password.length < 8) return res.status(400).json({ message: 'Nom, email valide et mot de passe (8 caractères minimum) requis' });
    const exists = await q('SELECT id FROM users WHERE email=$1', [email]); if (exists.rowCount) return res.status(409).json({ message: 'Cet email existe déjà' });
    const u = { id: id(), name, email, password_hash: await bcrypt.hash(password, 12), role: 'customer' };
    const r = await q('INSERT INTO users(id,name,email,password_hash,role) VALUES($1,$2,$3,$4,$5) RETURNING *', [u.id, u.name, u.email, u.password_hash, u.role]);
    await ensurePrefs(u.id);
    await q('INSERT INTO referrals(id,user_id,code) VALUES($1,$2,$3)', [id(), u.id, `ZM-${crypto.randomBytes(5).toString('hex').toUpperCase()}`]);
    await q('INSERT INTO security_events(id,user_id,ip,event_type,metadata) VALUES($1,$2,$3,$4,$5)', [id(), u.id, req.ip, 'register', JSON.stringify({ email })]);
    res.status(201).json({ token: sign(r.rows[0]), user: publicUser(r.rows[0]) });
  } catch { res.status(500).json({ message: 'Erreur inscription' }); }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    const email = clean(req.body?.email, 200).toLowerCase(); const password = String(req.body?.password || '');
    const r = await q('SELECT * FROM users WHERE email=$1', [email]);
    if (!r.rowCount || !(await bcrypt.compare(password, r.rows[0].password_hash))) {
      await q('INSERT INTO security_events(id,ip,event_type,metadata) VALUES($1,$2,$3,$4)', [id(), req.ip, 'login_failed', JSON.stringify({ email })]);
      return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
    }
    await ensurePrefs(r.rows[0].id);
    await q('INSERT INTO security_events(id,user_id,ip,event_type,metadata) VALUES($1,$2,$3,$4,$5)', [id(), r.rows[0].id, req.ip, 'login', JSON.stringify({})]);
    res.json({ token: sign(r.rows[0]), user: publicUser(r.rows[0]) });
  } catch { res.status(500).json({ message: 'Erreur connexion' }); }
});
app.get('/api/auth/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));
app.patch('/api/auth/me', auth, async (req, res) => {
  // Profile updates are ALWAYS scoped to the authenticated user id from the JWT; clients cannot choose another user id.

  try {
    const nameProvided = Object.prototype.hasOwnProperty.call(req.body || {}, 'name');
    const avatarProvided = Object.prototype.hasOwnProperty.call(req.body || {}, 'avatar');
    let name = nameProvided ? clean(req.body.name, 120) : req.user.name;
    let avatar = avatarProvided ? String(req.body.avatar || '').trim() : req.user.avatar;
    if (!name) return res.status(400).json({ message: 'Le nom est requis' });
    if (avatar && avatar.length > 700000) return res.status(400).json({ message: 'Photo trop volumineuse' });
    if (avatar && !/^data:image\/(png|jpe?g|webp);base64,/i.test(avatar)) return res.status(400).json({ message: 'Format de photo non supporté' });
    const r = await q('UPDATE users SET name=$1,avatar=$2,updated_at=now() WHERE id=$3 RETURNING *', [name, avatar || null, req.user.id]);
    res.json({ user: publicUser(r.rows[0]) });
  } catch { res.status(500).json({ message: 'Impossible d’enregistrer le profil' }); }
});
app.post('/api/auth/logout', (req, res) => res.json({ ok: true }));
app.post('/api/auth/refresh', auth, (req, res) => res.json({ token: sign(req.user), user: publicUser(req.user) }));

// USER STATE (cloud cart + wishlist, isolated per authenticated account)
app.get('/api/user-state', auth, async (req,res)=>{try{const r=await q('SELECT cart,wishlist FROM user_state WHERE user_id=$1',[req.user.id]);const row=r.rows[0]||{};res.json({cart:parseJson(row.cart,[]),wishlist:parseJson(row.wishlist,[])});}catch{res.status(500).json({message:'Etat utilisateur indisponible'});}});
app.put('/api/user-state', auth, async (req,res)=>{try{const cart=Array.isArray(req.body?.cart)?req.body.cart.slice(0,100):[];const wishlist=Array.isArray(req.body?.wishlist)?req.body.wishlist.slice(0,200):[];await q(`INSERT INTO user_state(user_id,cart,wishlist,updated_at) VALUES($1,$2,$3,now()) ON CONFLICT(user_id) DO UPDATE SET cart=EXCLUDED.cart,wishlist=EXCLUDED.wishlist,updated_at=now()`,[req.user.id,JSON.stringify(cart),JSON.stringify(wishlist)]);res.json({ok:true});}catch{res.status(500).json({message:'Etat utilisateur impossible à enregistrer'});}});

// WEB PUSH
app.get('/api/push/public-key',(req,res)=>res.json({publicKey:VAPID_PUBLIC_KEY||null,enabled:!!(VAPID_PUBLIC_KEY&&VAPID_PRIVATE_KEY)}));
app.post('/api/push/subscribe',auth,async(req,res)=>{try{const sub=req.body||{};const endpoint=clean(sub.endpoint,2000),p256dh=clean(sub.keys?.p256dh,1000),authKey=clean(sub.keys?.auth,1000);if(!endpoint||!p256dh||!authKey)return res.status(400).json({message:'Subscription push invalide'});await q(`INSERT INTO push_subscriptions(id,user_id,endpoint,p256dh,auth,updated_at) VALUES($1,$2,$3,$4,$5,now()) ON CONFLICT(endpoint) DO UPDATE SET user_id=EXCLUDED.user_id,p256dh=EXCLUDED.p256dh,auth=EXCLUDED.auth,updated_at=now()`,[id(),req.user.id,endpoint,p256dh,authKey]);res.status(201).json({ok:true});}catch{res.status(500).json({message:'Push impossible'});}});
app.delete('/api/push/subscribe',auth,async(req,res)=>{try{await q('DELETE FROM push_subscriptions WHERE endpoint=$1 AND user_id=$2',[clean(req.body?.endpoint,2000),req.user.id]);res.json({ok:true});}catch{res.status(500).json({message:'Push impossible'});}});

// STREAMING PLANS — only database values, no local/demo prices.
app.get('/api/streaming-plans',async(req,res)=>{try{const r=await q("SELECT * FROM streaming_plans WHERE enabled=true ORDER BY service,created_at");const plans={netflix:[],disney:[]};for(const x of r.rows)plans[x.service].push({id:x.id,service:x.service,name:x.name,description:x.description||'',price:num(x.price),currency:String(x.currency||'HTG').toUpperCase()==='USD'?'USD':'HTG',enabled:true,createdAt:x.created_at,updatedAt:x.updated_at});res.json({plans});}catch{res.status(500).json({message:'Plans indisponibles'});}});
app.get('/api/admin/streaming-plans',auth,admin,async(req,res)=>{const r=await q('SELECT * FROM streaming_plans ORDER BY service,created_at');res.json({plans:r.rows.map(x=>({id:x.id,service:x.service,name:x.name,description:x.description||'',price:num(x.price),currency:String(x.currency||'HTG').toUpperCase()==='USD'?'USD':'HTG',enabled:x.enabled,createdAt:x.created_at,updatedAt:x.updated_at}))});});
app.post('/api/admin/streaming-plans',auth,admin,async(req,res)=>{try{const service=String(req.body?.service||'').toLowerCase();if(!['netflix','disney'].includes(service))return res.status(400).json({message:'Service invalide'});const name=clean(req.body?.name,160);if(!name)return res.status(400).json({message:'Nom requis'});const cur=String(req.body?.currency||'HTG').toUpperCase()==='USD'?'USD':'HTG';const r=await q('INSERT INTO streaming_plans(id,service,name,description,price,currency,enabled) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[id(),service,name,clean(req.body?.description,500),num(req.body?.price),cur,bool(req.body?.enabled,true)]);res.status(201).json({plan:r.rows[0]});}catch{res.status(500).json({message:'Création plan impossible'});}});
app.patch('/api/admin/streaming-plans/:id',auth,admin,async(req,res)=>{try{const b=req.body||{};const r=await q('UPDATE streaming_plans SET name=COALESCE($1,name),description=COALESCE($2,description),price=COALESCE($3,price),currency=COALESCE($4,currency),enabled=COALESCE($5,enabled),updated_at=now() WHERE id=$6 RETURNING *',[b.name??null,b.description??null,b.price!=null?num(b.price):null,b.currency!=null?(String(b.currency).toUpperCase()==='USD'?'USD':'HTG'):null,b.enabled!=null?bool(b.enabled):null,req.params.id]);if(!r.rowCount)return res.status(404).json({message:'Plan introuvable'});res.json({plan:r.rows[0]});}catch{res.status(500).json({message:'Modification plan impossible'});}});
app.delete('/api/admin/streaming-plans/:id',auth,admin,async(req,res)=>{const r=await q('DELETE FROM streaming_plans WHERE id=$1 RETURNING id',[req.params.id]);if(!r.rowCount)return res.status(404).json({message:'Plan introuvable'});res.json({ok:true,id:req.params.id});});

// PRODUCTS
app.get('/api/products', async (req, res) => {
  try {
    let sql = 'SELECT * FROM products'; const params = []; const where = [];
    if (String(req.query.available || '') === 'true') where.push('stock>0');
    if (req.query.brand) { params.push(clean(req.query.brand, 100)); where.push(`brand=$${params.length}`); }
    if (where.length) sql += ` WHERE ${where.join(' AND ')}`;
    sql += ' ORDER BY created_at DESC';
    const r = await q(sql, params); res.json({ products: r.rows.map(productOut) });
  } catch { res.status(500).json({ message: 'Erreur produits' }); }
});
app.post('/api/products', auth, admin, async (req, res) => {
  try {
    const b = req.body || {}; const brand = clean(b.brand, 100); const model = clean(b.model || b.name, 160);
    if (!brand || !model) return res.status(400).json({ message: 'Marque et nom requis' });
    const r = await q(`INSERT INTO products(id,brand,model,image,images,price,currency,old_price,discount,stock,storage,colors,specifications,description,trade_enabled)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`, [id(), brand, model, clean(b.image, 700000), JSON.stringify(Array.isArray(b.images) ? b.images.slice(0, 10) : []), num(b.price), String(b.currency||'USD').toUpperCase()==='HTG'?'HTG':'USD', num(b.oldPrice ?? b.old_price), num(b.discount), Math.max(0, Math.floor(num(b.stock))), JSON.stringify(Array.isArray(b.storage) ? b.storage : []), JSON.stringify(Array.isArray(b.colors) ? b.colors : []), JSON.stringify(b.specifications || b.specs || {}), clean(b.description, 5000), bool(b.tradeEnabled,false)]);
    res.status(201).json({ product: productOut(r.rows[0]) });
  } catch { res.status(500).json({ message: 'Erreur création produit' }); }
});
app.put('/api/products/:id', auth, admin, async (req, res) => {
  try {
    const b = req.body || {}; const r = await q(`UPDATE products SET brand=COALESCE($1,brand),model=COALESCE($2,model),image=COALESCE($3,image),
      images=COALESCE($4,images),price=COALESCE($5,price),currency=COALESCE($6,currency),old_price=COALESCE($7,old_price),discount=COALESCE($8,discount),stock=COALESCE($9,stock),
      storage=COALESCE($10,storage),colors=COALESCE($11,colors),specifications=COALESCE($12,specifications),description=COALESCE($13,description),trade_enabled=COALESCE($14,trade_enabled),updated_at=now()
      WHERE id=$15 RETURNING *`, [b.brand ?? null, b.model ?? b.name ?? null, b.image ?? null, b.images ? JSON.stringify(b.images.slice(0, 10)) : null, b.price ?? null, b.currency != null ? (String(b.currency).toUpperCase()==='HTG'?'HTG':'USD') : null, b.oldPrice ?? b.old_price ?? null, b.discount ?? null, b.stock ?? null, b.storage ? JSON.stringify(b.storage) : null, b.colors ? JSON.stringify(b.colors) : null, (b.specifications || b.specs) ? JSON.stringify(b.specifications || b.specs) : null, b.description ?? null, b.tradeEnabled != null ? bool(b.tradeEnabled) : null, req.params.id]);
    if (!r.rowCount) return res.status(404).json({ message: 'Produit introuvable' }); res.json({ product: productOut(r.rows[0]) });
  } catch { res.status(500).json({ message: 'Erreur modification produit' }); }
});
app.delete('/api/products/:id', auth, admin, async (req, res) => {
  try { const r = await q('DELETE FROM products WHERE id=$1 RETURNING id', [req.params.id]); if (!r.rowCount) return res.status(404).json({ message: 'Produit introuvable' }); res.json({ ok: true, id: req.params.id }); }
  catch { res.status(500).json({ message: 'Erreur suppression produit' }); }
});
app.get('/api/health', async (req,res)=>{res.json({ok:true,service:'zhuomarket-backend',time:new Date().toISOString()})});

app.get('/api/brands', async (req, res) => { try { const r = await q('SELECT brand,COUNT(*)::int count FROM products GROUP BY brand ORDER BY brand'); res.json({ brands: r.rows.map(x => ({ id: x.brand, name: x.brand, count: x.count })) }); } catch { res.json({ brands: [] }); } });

// PROMOTIONS / REFERRALS
app.get('/api/promotions', async (req, res) => {
  try {
    const r = await q(`SELECT p.*, pr.brand AS product_brand, pr.model AS product_model, pr.image AS product_image, pr.price AS product_price, pr.old_price AS product_old_price, pr.stock AS product_stock
      FROM promotions p LEFT JOIN products pr ON pr.id=p.product_id ORDER BY p.created_at DESC`);
    res.json({ promotions: r.rows.map(x => ({ ...x, productId:x.product_id, image:x.image || '', images:parseJson(x.images, x.image?[x.image]:[]), price:num(x.price || x.product_price), oldPrice:num(x.old_price || x.product_old_price), discount:num(x.discount), startDate:x.start_date, endDate:x.end_date, createdAt:x.created_at, updatedAt:x.updated_at, durationSeconds:Number(x.duration_seconds||6), product:x.product_id?{id:x.product_id,brand:x.product_brand,model:x.product_model,image:x.product_image,price:num(x.product_price),oldPrice:num(x.product_old_price),stock:Number(x.product_stock||0)}:null })) });
  } catch { res.json({ promotions: [] }); }
});
app.post('/api/promotions', auth, admin, async (req, res) => {
  try { const b=req.body||{}; const pid=b.productId||null; const r=await q(`INSERT INTO promotions(id,product_id,title,description,image,images,price,old_price,discount,start_date,end_date,status,duration_seconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,[id(),pid,clean(b.title,160)||'Promotion',clean(b.description,1000),clean(b.image,700000),JSON.stringify(Array.isArray(b.images)?b.images.slice(0,10):(b.image?[b.image]:[])),num(b.price),num(b.oldPrice??b.old_price),Math.max(0,Math.min(100,num(b.discount))),b.startDate||null,b.endDate||null,clean(b.status,30)||'published',Math.max(2,Math.min(60,Math.floor(num(b.durationSeconds,6))))]); res.status(201).json({promotion:r.rows[0]}); } catch(e){ res.status(500).json({message:'Erreur promotion'}); }
});
app.patch('/api/promotions/:id', auth, admin, async (req,res)=>{
  try { const b=req.body||{}; const r=await q(`UPDATE promotions SET product_id=COALESCE($1,product_id),title=COALESCE($2,title),description=COALESCE($3,description),image=COALESCE($4,image),images=COALESCE($5,images),price=COALESCE($6,price),old_price=COALESCE($7,old_price),discount=COALESCE($8,discount),start_date=COALESCE($9,start_date),end_date=COALESCE($10,end_date),status=COALESCE($11,status),duration_seconds=COALESCE($12,duration_seconds),updated_at=now() WHERE id=$13 RETURNING *`,[b.productId??null,b.title??null,b.description??null,b.image??null,Array.isArray(b.images)?JSON.stringify(b.images.slice(0,10)):null,b.price??null,b.oldPrice??b.old_price??null,b.discount!=null?Math.max(0,Math.min(100,num(b.discount))):null,b.startDate??null,b.endDate??null,b.status??null,b.durationSeconds!=null?Math.max(2,Math.min(60,Math.floor(num(b.durationSeconds)))):null,req.params.id]); if(!r.rowCount)return res.status(404).json({message:'Promotion introuvable'}); res.json({promotion:r.rows[0]}); } catch { res.status(500).json({message:'Erreur modification promotion'}); }
});
app.put('/api/promotions/:id', auth, admin, async (req,res)=>{
  try { const b=req.body||{}; const r=await q(`UPDATE promotions SET product_id=$1,title=$2,description=$3,image=$4,images=$5,price=$6,old_price=$7,discount=$8,start_date=$9,end_date=$10,status=$11,duration_seconds=$12,updated_at=now() WHERE id=$13 RETURNING *`,[b.productId||null,clean(b.title,160)||'Promotion',clean(b.description,1000),clean(b.image,700000),JSON.stringify(Array.isArray(b.images)?b.images.slice(0,10):(b.image?[b.image]:[])),num(b.price),num(b.oldPrice??b.old_price),Math.max(0,Math.min(100,num(b.discount))),b.startDate||null,b.endDate||null,clean(b.status,30)||'published',Math.max(2,Math.min(60,Math.floor(num(b.durationSeconds,6)))),req.params.id]); if(!r.rowCount)return res.status(404).json({message:'Promotion introuvable'});res.json({promotion:r.rows[0]}); } catch {res.status(500).json({message:'Erreur modification promotion'});}
});
app.delete('/api/promotions/:id', auth, admin, async (req,res)=>{ try{const r=await q('DELETE FROM promotions WHERE id=$1 RETURNING id',[req.params.id]);if(!r.rowCount)return res.status(404).json({message:'Promotion introuvable'});res.json({ok:true,id:req.params.id});}catch{res.status(500).json({message:'Erreur suppression promotion'});} });
app.get('/api/referrals/me', auth, async (req, res) => { let r = await q('SELECT * FROM referrals WHERE user_id=$1 LIMIT 1', [req.user.id]); if (!r.rowCount) r = await q('INSERT INTO referrals(id,user_id,code) VALUES($1,$2,$3) RETURNING *', [id(), req.user.id, `ZM-${crypto.randomBytes(5).toString('hex').toUpperCase()}`]); res.json({ referral: r.rows[0] }); });
app.post('/api/referrals/:code/click', async (req, res) => { const r = await q('UPDATE referrals SET clicks=clicks+1 WHERE code=$1 RETURNING code', [clean(req.params.code, 50)]); res.json({ ok: !!r.rowCount }); });

// UPLOADS
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024, files: 1 } });
app.post('/api/uploads', auth, admin, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'file', maxCount: 1 }]), async (req, res) => {
  try {
    const f = (req.files?.image?.[0]) || (req.files?.file?.[0]);
    if (!f) return res.status(400).json({ message: 'Image manquante. Utilise le champ image ou file.' });
    if (!/^image\/(png|jpe?g|webp)$/i.test(f.mimetype || '')) return res.status(400).json({ message: 'Utilise PNG, JPG/JPEG ou WebP.' });
    const data = `data:${f.mimetype};base64,${f.buffer.toString('base64')}`; const uid = id();
    await q('INSERT INTO uploads(id,mime_type,data,owner_id) VALUES($1,$2,$3,$4)', [uid, f.mimetype, data, req.user.id]);
    res.status(201).json({ ok: true, url: data, imageUrl: data, image: data, path: data, id: uid });
  } catch (e) { console.error('Upload impossible:', e.message); res.status(500).json({ message: 'Upload impossible' }); }
});

// Restore reserved stock exactly once when an order is cancelled or its payment is permanently failed/refunded.
async function restoreOrderStock(orderId){
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const r=await client.query('SELECT id,items,stock_restored FROM orders WHERE id=$1 FOR UPDATE',[orderId]);
    if(!r.rowCount || r.rows[0].stock_restored){await client.query('ROLLBACK');return false;}
    const items=parseJson(r.rows[0].items,[]);
    for(const item of items){
      const pid=clean(item?.productId,80); const qty=Math.max(0,Math.min(99,Math.floor(num(item?.quantity,0))));
      if(pid&&qty) await client.query('UPDATE products SET stock=stock+$1,updated_at=now() WHERE id=$2',[qty,pid]);
    }
    await client.query('UPDATE orders SET stock_restored=true,updated_at=now() WHERE id=$1',[orderId]);
    await client.query('COMMIT'); return true;
  }catch(e){try{await client.query('ROLLBACK')}catch{};throw e}finally{client.release()}
}

// ORDERS / PAYMENTS
const ORDER_STATUSES = ['En attente', 'Confirmée', 'En préparation', 'Expédiée', 'Prête', 'Livrée', 'Terminée', 'Annulée'];
function paymentMethodPublic(x){return {id:x.id,name:x.name,description:x.description||'',enabled:!!x.enabled,instructions:x.instructions||'',provider:x.provider||x.id,logo:x.logo||x.provider||x.id};}
app.get('/api/payment-methods', async (req, res) => { try { const r = await q('SELECT id,name,description,enabled,instructions,provider,logo,sort_order FROM payment_methods WHERE enabled=true ORDER BY sort_order,created_at'); res.json({ paymentMethods: r.rows.map(paymentMethodPublic) }); } catch { res.json({ paymentMethods: [] }); } });

app.post('/api/orders', auth, async (req, res) => {
  const body = req.body || {};
  const hasProducts=Array.isArray(body.items)&&body.items.length;
  const hasService=body.serviceOrder&&body.serviceOrder.planId;
  if (!hasProducts && !hasService) return res.status(400).json({ message: 'Panier vide' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const normalized = [];
    let total = 0;
    let orderCurrency = null;
    if(hasProducts){
      for (const raw of body.items.slice(0, 50)) {
        const qty = Math.max(1, Math.min(99, Math.floor(num(raw.quantity, 1))));
        const pr = await client.query('SELECT id,brand,model,price,currency,stock FROM products WHERE id=$1 FOR UPDATE', [raw.productId]);
        if (!pr.rowCount) throw new Error('Produit introuvable');
        if (Number(pr.rows[0].stock) < qty) throw new Error(`Stock insuffisant pour ${pr.rows[0].model}`);
        await client.query('UPDATE products SET stock=stock-$1,updated_at=now() WHERE id=$2', [qty, raw.productId]);
        const unit = num(pr.rows[0].price); total += unit * qty;
        const cur=String(pr.rows[0].currency||'USD').toUpperCase()==='HTG'?'HTG':'USD'; orderCurrency=orderCurrency||cur;
        normalized.push({ productId: raw.productId, quantity: qty, storage: raw.storage ?? null, color: raw.color ?? null, unitPrice: unit, currency:cur, name: pr.rows[0].model, brand: pr.rows[0].brand });
        if(orderCurrency!==cur) throw new Error('Panier multi-devise interdit');
      }
    } else {
      const service=String(body.serviceOrder.service||'').toLowerCase();
      if(!['netflix','disney'].includes(service)) throw new Error('Service invalide');
      const plan=await client.query('SELECT id,service,name,description,price,currency FROM streaming_plans WHERE id=$1 AND service=$2 AND enabled=true',[body.serviceOrder.planId,service]);
      if(!plan.rowCount) throw new Error('Plan streaming indisponible');
      total=num(plan.rows[0].price); orderCurrency=String(plan.rows[0].currency||'HTG').toUpperCase()==='USD'?'USD':'HTG';
      normalized.push({type:'service',service,planId:plan.rows[0].id,quantity:1,unitPrice:total,currency:orderCurrency,name:plan.rows[0].name,brand:service==='netflix'?'Netflix':'Disney+',description:plan.rows[0].description||''});
    }
    const methodId = clean(body.paymentMethod || 'cash_on_delivery', 80);
    const pm = await client.query('SELECT * FROM payment_methods WHERE id=$1 AND enabled=true', [methodId]);
    if (!pm.rowCount) throw new Error('Méthode de paiement indisponible');
    if(['stripe_card','paypal'].includes(methodId) && orderCurrency!=='USD') throw new Error('Carte/PayPal: choisis un montant en USD');
    const currencies=[...new Set(normalized.map(x=>x.currency))]; if(currencies.length>1) throw new Error('Panier multi-devise interdit');
    const paymentStatus = 'pending';
    const oid = id();
    const order = await client.query(`INSERT INTO orders(id,user_id,items,customer,payment_method,payment_status,payment_reference,total,currency,service_order,status)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`, [oid, req.user.id, JSON.stringify(normalized), JSON.stringify(body.customer || {}), methodId, paymentStatus, clean(body.paymentReference, 200) || null, total, orderCurrency||'USD', hasService?JSON.stringify(body.serviceOrder):null, 'Confirmée']);
    await client.query('INSERT INTO order_events(id,order_id,user_id,event_type,new_status,message) VALUES($1,$2,$3,$4,$5,$6)', [id(), oid, req.user.id, 'status', 'Confirmée', hasService?'Commande service créée':'Commande créée']);
    const pref = await client.query('SELECT reminder_minutes FROM notification_preferences WHERE user_id=$1', [req.user.id]);
    const reminderMinutes = Number(pref.rows[0]?.reminder_minutes || 10);
    await client.query('INSERT INTO notifications(id,user_id,title,message,type,severity,read,remind_every_minutes,entity_type,entity_id) VALUES($1,$2,$3,$4,$5,$6,false,$7,$8,$9)', [id(), req.user.id, hasService?'Demande service reçue':'Commande confirmée', `Ta commande ${oid.slice(0, 8)} a été reçue.`, 'order', 'normal', Math.max(1,Math.min(1440,reminderMinutes)), 'order', oid]);
    const adminRows = await client.query("SELECT id FROM users WHERE role IN ('admin','owner')");
    for (const a of adminRows.rows) {
      await client.query('INSERT INTO notifications(id,user_id,title,message,type,severity,read,remind_every_minutes,entity_type,entity_id) VALUES($1,$2,$3,$4,$5,$6,false,$7,$8,$9)', [id(), a.id, hasService?'Nouvelle demande service':'Nouvelle commande', `Commande ${oid.slice(0, 8)} reçue — ${total.toFixed(2)} ${orderCurrency||'USD'}.`, 'order', 'high', 10, 'order', oid]);
    }
    await client.query('COMMIT');
    res.status(201).json({ order: { ...order.rows[0], total: num(order.rows[0].total), currency: order.rows[0].currency, items: normalized, serviceOrder: parseJson(order.rows[0].service_order,null), createdAt: order.rows[0].created_at } });
  } catch (e) { await client.query('ROLLBACK'); res.status(400).json({ message: e.message || 'Erreur commande' }); }
  finally { client.release(); }
});
app.get('/api/orders', auth, async (req, res) => {
  try { const adminView = req.query.admin === 'true' && ['admin','owner'].includes(String(req.user.role||'').toLowerCase()); const r = adminView ? await q('SELECT * FROM orders ORDER BY created_at DESC LIMIT 200') : await q('SELECT * FROM orders WHERE user_id=$1 ORDER BY created_at DESC', [req.user.id]); res.json({ orders: r.rows.map(x => ({ ...x, total: num(x.total), items: parseJson(x.items, []), customer: parseJson(x.customer, {}), currency: x.currency||'USD', serviceOrder: parseJson(x.service_order,null), createdAt: x.created_at, updatedAt: x.updated_at })) }); }
  catch { res.status(500).json({ message: 'Erreur commandes' }); }
});
app.get('/api/orders/:id', auth, async (req, res) => {
  try {
    const adminView = ['admin','owner'].includes(String(req.user.role||'').toLowerCase()); const r = await q(adminView ? 'SELECT * FROM orders WHERE id=$1' : 'SELECT * FROM orders WHERE id=$1 AND user_id=$2', adminView ? [req.params.id] : [req.params.id, req.user.id]);
    if (!r.rowCount) return res.status(404).json({ message: 'Commande introuvable' }); const e = await q('SELECT * FROM order_events WHERE order_id=$1 ORDER BY created_at ASC', [req.params.id]);
    res.json({ order: { ...r.rows[0], total: num(r.rows[0].total), items: parseJson(r.rows[0].items, []), customer: parseJson(r.rows[0].customer, {}), currency: r.rows[0].currency||'USD', serviceOrder: parseJson(r.rows[0].service_order,null), createdAt: r.rows[0].created_at, updatedAt: r.rows[0].updated_at }, events: e.rows });
  } catch { res.status(500).json({ message: 'Erreur commande' }); }
});
app.patch('/api/orders/:id/status', auth, admin, async (req, res) => {
  const newStatus = clean(req.body?.status, 50); if (!ORDER_STATUSES.includes(newStatus)) return res.status(400).json({ message: 'Statut invalide' });
  try {
    const old = await q('SELECT * FROM orders WHERE id=$1', [req.params.id]); if (!old.rowCount) return res.status(404).json({ message: 'Commande introuvable' });
    const r = await q('UPDATE orders SET status=$1,updated_at=now() WHERE id=$2 RETURNING *', [newStatus, req.params.id]);
    if(newStatus==='Annulée' && old.rows[0].status!=='Annulée') await restoreOrderStock(req.params.id);
    await q('INSERT INTO order_events(id,order_id,user_id,event_type,old_status,new_status,message) VALUES($1,$2,$3,$4,$5,$6,$7)', [id(), req.params.id, req.user.id, 'status', old.rows[0].status, newStatus, `Statut: ${newStatus}`]);
    const owner = old.rows[0].user_id; if (owner) await insertNotification({ userId: owner, title: `Commande ${newStatus}`, message: `Ta commande ${req.params.id.slice(0, 8)} est maintenant: ${newStatus}.`, type: 'order', severity: newStatus === 'Annulée' ? 'high' : 'normal', entityType: 'order', entityId: req.params.id });
    res.json({ order: { ...r.rows[0], total: num(r.rows[0].total), items: parseJson(r.rows[0].items, []), customer: parseJson(r.rows[0].customer, {}) } });
  } catch { res.status(500).json({ message: 'Impossible de changer le statut' }); }
});
app.patch('/api/orders/:id/payment', auth, admin, async (req, res) => {
  const status = clean(req.body?.status, 30); if (!['pending', 'paid', 'failed', 'refunded', 'cancelled'].includes(status)) return res.status(400).json({ message: 'Statut paiement invalide' });
  try {
    const r = await q('UPDATE orders SET payment_status=$1,payment_reference=COALESCE($2,payment_reference),paid_at=CASE WHEN $1=\'paid\' THEN now() ELSE paid_at END,updated_at=now() WHERE id=$3 RETURNING *', [status, clean(req.body?.reference, 200) || null, req.params.id]);
    if (!r.rowCount) return res.status(404).json({ message: 'Commande introuvable' });
    if(['failed','refunded','cancelled'].includes(status)) await restoreOrderStock(req.params.id);
    if (r.rows[0].user_id) await insertNotification({ userId: r.rows[0].user_id, title: 'Paiement mis à jour', message: `Le paiement de ta commande ${req.params.id.slice(0, 8)} est: ${status}.`, type: 'payment', severity: status === 'failed' ? 'high' : 'normal', entityType: 'order', entityId: req.params.id });
    res.json({ order: r.rows[0] });
  } catch { res.status(500).json({ message: 'Impossible de mettre à jour le paiement' }); }
});

// ORDER CONFIRMATION CODE
app.post('/api/admin/orders/:id/confirmation-code', auth, admin, async (req,res)=>{
  try {
    const orderId=req.params.id;
    const o=await q('SELECT o.*,u.id AS customer_id,u.name AS customer_name,u.email AS customer_email FROM orders o LEFT JOIN users u ON u.id=o.user_id WHERE o.id=$1',[orderId]);
    if(!o.rowCount) return res.status(404).json({message:'Commande introuvable'});
    const order=o.rows[0];
    if(!order.customer_id) return res.status(400).json({message:'Cette commande n’a pas de client connecté'});
    const code=String(crypto.randomInt(100000,1000000));
    const hash=crypto.createHash('sha256').update(code).digest('hex');
    await q("UPDATE confirmation_codes SET used_at=COALESCE(used_at,now()) WHERE order_id=$1 AND purpose='order_confirmation' AND used_at IS NULL",[orderId]);
    await q("INSERT INTO confirmation_codes(id,user_id,order_id,code_hash,purpose,expires_at,created_by) VALUES($1,$2,$3,$4,$5,now()+interval '15 minutes',$6)",[id(),order.customer_id,orderId,hash,'order_confirmation',req.user.id]);
    const conv=await getOrCreateConversation({name:order.customer_name||'Client',email:order.customer_email||null}, order.customer_id);
    const text=`🔐 Code de confirmation de ta commande ${orderId.slice(0,8)} : ${code}.
Valable pendant 15 minutes.`;
    const messageId=await saveMessage({conversationId:conv.id,sender:'admin',senderUserId:req.user.id,message:text,severity:'high',urgent:false});
    await insertNotification({userId:order.customer_id,title:'Code de confirmation',message:`Ton code de confirmation pour la commande ${orderId.slice(0,8)} est ${code}. Valable 15 minutes.`,type:'message',severity:'high',entityType:'order',entityId:orderId,force:true});
    res.status(201).json({ok:true,conversationId:conv.id,messageId,code,expiresInMinutes:15});
  } catch(e) { console.error('Code commande impossible:',e.message); res.status(500).json({message:'Impossible de générer le code'}); }
});

// OWNER role management
app.patch('/api/admin/users/:id', auth, async (req,res)=>{
  if(String(req.user?.role||'').toLowerCase()!=='owner') return res.status(403).json({message:'Seul le Owner peut modifier les rôles'});
  const role=String(req.body?.role||'').toLowerCase();
  if(!['admin','customer','user'].includes(role)) return res.status(400).json({message:'Rôle invalide'});
  try{const r=await q("UPDATE users SET role=$1,updated_at=now() WHERE id=$2 AND role<>'owner' RETURNING *",[role==='user'?'customer':role,req.params.id]);if(!r.rowCount)return res.status(404).json({message:'Utilisateur introuvable ou protégé'});res.json({user:publicUser(r.rows[0])});}catch{res.status(500).json({message:'Impossible de modifier le rôle'});}
});

// USERS / STATS
app.get('/api/users', auth, admin, async (req, res) => { const r = await q('SELECT * FROM users ORDER BY created_at DESC'); res.json({ users: r.rows.map(publicUser) }); });
app.get('/api/admin/stats', auth, admin, async (req, res) => {
  const [s, o, u, p, pending, unread] = await Promise.all([
    q('SELECT COALESCE(SUM(total),0) sales FROM orders'), q('SELECT COUNT(*)::int count FROM orders'), q('SELECT COUNT(*)::int count FROM users'),
    q('SELECT COUNT(*)::int count FROM products'), q("SELECT COUNT(*)::int count FROM orders WHERE status NOT IN ('Livrée','Terminée','Annulée')"), q('SELECT COALESCE(SUM(unread),0)::int count FROM conversations')
  ]);
  res.json({ stats: { sales: num(s.rows[0].sales), totalSales: num(s.rows[0].sales), orders: o.rows[0].count, ordersCount: o.rows[0].count, users: u.rows[0].count, usersCount: u.rows[0].count, products: p.rows[0].count, pendingOrders: pending.rows[0].count, unreadMessages: unread.rows[0].count } });
});

// NOTIFICATIONS
app.get('/api/notifications', auth, async (req, res) => { const r = await q('SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200', [req.user.id]); res.json({ notifications: r.rows.map(notificationOut), unread: r.rows.filter(x => !x.read && !x.seen_at).length }); });
app.get('/api/notifications/due-reminders', auth, async (req, res) => {
  const r = await q(`SELECT * FROM notifications WHERE user_id=$1 AND read=false AND seen_at IS NULL
    AND (last_reminded_at IS NULL OR last_reminded_at + (remind_every_minutes || ' minutes')::interval <= now())
    ORDER BY created_at DESC LIMIT 50`, [req.user.id]);
  if (r.rowCount) await q(`UPDATE notifications SET last_reminded_at=now() WHERE id=ANY($1::uuid[])`, [r.rows.map(x => x.id)]);
  res.json({ reminders: r.rows.map(notificationOut) });
});
app.post('/api/notifications', auth, async (req, res) => { const n = await insertNotification({ userId: req.user.id, title: req.body?.title || 'ZhuoMarket', message: req.body?.message || '', type: req.body?.type || 'info', severity: req.body?.severity || 'normal', remindEveryMinutes: req.body?.remindEveryMinutes || 10 }); res.status(201).json({ notification: notificationOut(n) }); });
app.patch('/api/notifications/:id/read', auth, async (req, res) => { const r = await q('UPDATE notifications SET read=true,seen_at=COALESCE(seen_at,now()) WHERE id=$1 AND user_id=$2 RETURNING *', [req.params.id, req.user.id]); if (!r.rowCount) return res.status(404).json({ message: 'Notification introuvable' }); res.json({ notification: notificationOut(r.rows[0]) }); });
app.post('/api/notifications/mark-all-read', auth, async (req, res) => { await q('UPDATE notifications SET read=true,seen_at=COALESCE(seen_at,now()) WHERE user_id=$1 AND read=false', [req.user.id]); res.json({ ok: true }); });
app.get('/api/notification-preferences', auth, async (req, res) => { await ensurePrefs(req.user.id); const r = await q('SELECT * FROM notification_preferences WHERE user_id=$1', [req.user.id]); res.json({ preferences: r.rows[0] }); });
app.patch('/api/notification-preferences', auth, async (req, res) => { await ensurePrefs(req.user.id); const b = req.body || {}; const r = await q(`UPDATE notification_preferences SET order_updates=COALESCE($1,order_updates),payment_updates=COALESCE($2,payment_updates),messages=COALESCE($3,messages),promotions=COALESCE($4,promotions),security=COALESCE($5,security),reminder_minutes=COALESCE($6,reminder_minutes),updated_at=now() WHERE user_id=$7 RETURNING *`, [b.order_updates ?? null, b.payment_updates ?? null, b.messages ?? null, b.promotions ?? null, b.security ?? null, b.reminder_minutes != null ? Math.max(1, Math.min(1440, Number(b.reminder_minutes))) : null, req.user.id]); res.json({ preferences: r.rows[0] }); });

// CHAT: customer + admin, urgent escalation creates admin notifications
async function getOrCreateConversation(b, userId) {
  if (userId) { const r = await q('SELECT * FROM conversations WHERE user_id=$1 ORDER BY last_message_at DESC LIMIT 1', [userId]); if (r.rowCount) return r.rows[0]; }
  const c = id(); const x = await q('INSERT INTO conversations(id,user_id,name,email) VALUES($1,$2,$3,$4) RETURNING *', [c, userId || null, clean(b.name, 120) || 'Client', clean(b.email, 200) || null]); return x.rows[0];
}
async function saveMessage({ conversationId, sender, senderUserId, message, severity = 'normal', urgent = false }) {
  const mid = id(); await q('INSERT INTO messages(id,conversation_id,sender,sender_user_id,message,severity,urgent) VALUES($1,$2,$3,$4,$5,$6,$7)', [mid, conversationId, sender, senderUserId || null, clean(message, 4000), severity, !!urgent]);
  if (sender === 'customer') await q('UPDATE conversations SET last_message=$1,last_message_at=now(),unread=unread+1 WHERE id=$2', [clean(message, 500), conversationId]);
  else await q('UPDATE conversations SET last_message=$1,last_message_at=now(),unread_for_user=unread_for_user+1 WHERE id=$2', [clean(message, 500), conversationId]);
  return mid;
}
app.get('/api/admin/messages', auth, admin, async (req, res) => { const r = await q('SELECT c.*,u.avatar FROM conversations c LEFT JOIN users u ON u.id=c.user_id ORDER BY last_message_at DESC'); res.json({ conversations: r.rows.map(x => ({ id:x.id,name:x.name,email:x.email,avatar:x.avatar || null,lastMessage:x.last_message,lastMessageAt:x.last_message_at,unread:x.unread })) }); });
app.get('/api/admin/messages/unread', auth, admin, async (req, res) => { const [c, n] = await Promise.all([q('SELECT id,name,email,last_message,last_message_at,unread FROM conversations WHERE unread>0 ORDER BY last_message_at DESC'), q("SELECT * FROM notifications WHERE user_id=$1 AND read=false ORDER BY created_at DESC LIMIT 50", [req.user.id])]); res.json({ unread: c.rows.reduce((s,x) => s + Number(x.unread), 0) + n.rowCount, notifications: [...c.rows.map(x => ({ id:x.id,name:x.name,lastMessage:x.last_message,unread:x.unread,type:'message' })), ...n.rows.map(notificationOut)] }); });
app.get('/api/admin/messages/:id', auth, admin, async (req, res) => { const r = await q('SELECT id,sender,message AS text,severity,urgent,created_at AS "createdAt" FROM messages WHERE conversation_id=$1 ORDER BY created_at ASC', [req.params.id]); await q('UPDATE conversations SET unread=0 WHERE id=$1', [req.params.id]); res.json({ messages: r.rows }); });
app.post('/api/admin/messages', optAuth, async (req, res) => {
  try {
    const b = req.body || {}; if (!clean(b.message, 4000)) return res.status(400).json({ message: 'Message vide' });
    const isAdminSender = ['admin','owner'].includes(String(req.user?.role||'').toLowerCase()); const c = await getOrCreateConversation(b, isAdminSender ? b.userId : (req.user?.id || b.userId || null));
    const urgent = bool(b.urgent); const severity = clean(b.severity || (urgent ? 'high' : 'normal'), 30);
    const mid = await saveMessage({ conversationId:c.id,sender:isAdminSender?'admin':'customer',senderUserId:req.user?.id || null,message:b.message,severity,urgent });
    if (!isAdminSender) {
      if (urgent || severity === 'high' || severity === 'critical') await notifyAllAdmins('Problème client urgent', `${c.name || 'Un client'} a signalé un problème sérieux.`, 'support', severity, 'conversation', c.id);
      else await notifyAllAdmins('Nouveau message client', `${c.name || 'Un client'} a envoyé un message.`, 'support', 'normal', 'conversation', c.id);
    }
    res.status(201).json({ ok:true,conversationId:c.id,messageId:mid });
  } catch { res.status(500).json({ message:'Message impossible' }); }
});
app.post('/api/admin/messages/:id', auth, admin, async (req, res) => {
  try { const c = await q('SELECT * FROM conversations WHERE id=$1', [req.params.id]); if (!c.rowCount) return res.status(404).json({ message:'Conversation introuvable' }); const mid = await saveMessage({ conversationId:req.params.id,sender:'admin',senderUserId:req.user.id,message:req.body?.message || '' }); if (c.rows[0].user_id) await insertNotification({ userId:c.rows[0].user_id,title:'Réponse de ZhuoMarket',message:'Un administrateur a répondu à ta conversation.',type:'message',severity:'high',entityType:'conversation',entityId:req.params.id,force:true }); res.status(201).json({ ok:true,messageId:mid }); }
  catch { res.status(500).json({ message:'Réponse impossible' }); }
});

// ADMIN TEAM CHAT: private WhatsApp-like conversation between Admin/Owner accounts.
async function ensureAdminPeer(peerId, currentId) {
  const r = await q("SELECT * FROM users WHERE id=$1 AND role IN ('admin','owner')", [peerId]);
  if (!r.rowCount || String(peerId) === String(currentId)) return null;
  return r.rows[0];
}
async function getAdminChat(a,b) {
  let r = await q('SELECT * FROM admin_chats WHERE (admin_a_id=$1 AND admin_b_id=$2) OR (admin_a_id=$2 AND admin_b_id=$1) LIMIT 1',[a,b]);
  if (r.rowCount) return r.rows[0];
  const c=id();
  try {
    r=await q('INSERT INTO admin_chats(id,admin_a_id,admin_b_id) VALUES($1,$2,$3) RETURNING *',[c,a,b]);
    return r.rows[0];
  } catch {
    const x=await q('SELECT * FROM admin_chats WHERE (admin_a_id=$1 AND admin_b_id=$2) OR (admin_a_id=$2 AND admin_b_id=$1) LIMIT 1',[a,b]);
    return x.rows[0]||null;
  }
}
function adminChatOut(r, currentId, peer) {
  const currentIsA=String(r.admin_a_id)===String(currentId);
  return {id:r.id,peerId:peer?.id||null,peerName:peer?.name||peer?.email||'Admin',peerEmail:peer?.email||'',peerRole:peer?.role||'admin',lastMessage:r.last_message||'',lastMessageAt:r.last_message_at,unread:Number(currentIsA?r.unread_for_a:r.unread_for_b||0)};
}
app.get('/api/admin/team', auth, admin, async (req,res)=>{
  const r=await q("SELECT id,name,email,role,avatar,created_at FROM users WHERE role IN ('admin','owner') AND id<>$1 ORDER BY CASE WHEN role='owner' THEN 0 ELSE 1 END, name ASC",[req.user.id]);
  res.json({admins:r.rows.map(x=>({id:x.id,name:x.name,email:x.email,role:x.role,avatar:x.avatar||null,createdAt:x.created_at}))});
});
app.get('/api/admin/team/chats', auth, admin, async (req,res)=>{
  const peers=await q("SELECT id,name,email,role,avatar FROM users WHERE role IN ('admin','owner') AND id<>$1 ORDER BY name ASC",[req.user.id]);
  const chats=await q('SELECT * FROM admin_chats WHERE admin_a_id=$1 OR admin_b_id=$1 ORDER BY last_message_at DESC',[req.user.id]);
  const out=[];
  for(const c of chats.rows){const peerId=String(c.admin_a_id)===String(req.user.id)?c.admin_b_id:c.admin_a_id;const p=peers.rows.find(x=>String(x.id)===String(peerId));out.push(adminChatOut(c,req.user.id,p));}
  res.json({chats:out});
});
app.get('/api/admin/team/chats/:peerId', auth, admin, async (req,res)=>{
  const peer=await ensureAdminPeer(req.params.peerId,req.user.id); if(!peer)return res.status(404).json({message:'Admin introuvable'});
  const chat=await getAdminChat(req.user.id,peer.id); if(!chat)return res.status(500).json({message:'Chat indisponible'});
  const r=await q('SELECT id,sender_id AS "senderId",message,created_at AS "createdAt" FROM admin_chat_messages WHERE chat_id=$1 ORDER BY created_at ASC',[chat.id]);
  if(String(chat.admin_a_id)===String(req.user.id)) await q('UPDATE admin_chats SET unread_for_a=0 WHERE id=$1',[chat.id]); else await q('UPDATE admin_chats SET unread_for_b=0 WHERE id=$1',[chat.id]);
  res.json({chatId:chat.id,peer:{id:peer.id,name:peer.name,email:peer.email,role:peer.role,avatar:peer.avatar||null},messages:r.rows});
});
app.post('/api/admin/team/chats/:peerId', auth, admin, async (req,res)=>{
  const peer=await ensureAdminPeer(req.params.peerId,req.user.id); if(!peer)return res.status(404).json({message:'Admin introuvable'});
  const text=clean(req.body?.message,4000); if(!text)return res.status(400).json({message:'Message vide'});
  const chat=await getAdminChat(req.user.id,peer.id); if(!chat)return res.status(500).json({message:'Chat indisponible'});
  const mid=id(); await q('INSERT INTO admin_chat_messages(id,chat_id,sender_id,message) VALUES($1,$2,$3,$4)',[mid,chat.id,req.user.id,text]);
  const currentIsA=String(chat.admin_a_id)===String(req.user.id);
  await q(currentIsA?'UPDATE admin_chats SET last_message=$1,last_message_at=now(),unread_for_b=unread_for_b+1 WHERE id=$2':'UPDATE admin_chats SET last_message=$1,last_message_at=now(),unread_for_a=unread_for_a+1 WHERE id=$2',[clean(text,500),chat.id]);
  await insertNotification({userId:peer.id,title:`Message de ${req.user.name||'Admin'}`,message:clean(text,800),type:'message',severity:'normal',entityType:'admin_chat',entityId:chat.id,force:true});
  res.status(201).json({ok:true,chatId:chat.id,messageId:mid});
});

// Trade feature switch controlled from Admin and read publicly by the client.
app.get('/api/support/config', async (req,res)=>{
  try {
    const r=await q("SELECT value FROM app_settings WHERE key='support_admin_phone'");
    const raw=r.rows[0]?.value;
    const phone=raw==null?null:(typeof raw==='string'?raw:String(raw).replace(/^\"|\"$/g,''));
    res.json({supportName:'Zhuo Support',adminPhone:phone||null,aiOnly:true});
  } catch { res.json({supportName:'Zhuo Support',adminPhone:null,aiOnly:true}); }
});
app.patch('/api/admin/settings/support', auth, admin, async (req,res)=>{
  const phone=clean(req.body?.adminPhone,40).replace(/[^0-9+()\- .]/g,'');
  await q("INSERT INTO app_settings(key,value) VALUES('support_admin_phone',$1::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",[JSON.stringify(phone||null)]);
  res.json({ok:true,adminPhone:phone||null});
});

app.get('/api/settings/trade', async (req,res)=>{try{const r=await q("SELECT value FROM app_settings WHERE key='trade_enabled'");const raw=r.rows[0]?.value;const enabled=typeof raw==='boolean'?raw:String(raw).replace(/^"|"$/g,'')!=='false';res.json({enabled});}catch{res.json({enabled:true})}});
app.patch('/api/admin/settings/trade', auth, admin, async (req,res)=>{const enabled=bool(req.body?.enabled,true);await q("INSERT INTO app_settings(key,value) VALUES('trade_enabled',$1::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",[JSON.stringify(enabled)]);res.json({ok:true,enabled});});
app.get('/api/messages', auth, async (req, res) => { const c = await getOrCreateConversation({name:req.user.name,email:req.user.email}, req.user.id); const r = await q('SELECT id,sender,message AS text,severity,urgent,created_at AS "createdAt" FROM messages WHERE conversation_id=$1 ORDER BY created_at ASC', [c.id]); await q('UPDATE conversations SET unread_for_user=0 WHERE id=$1', [c.id]); res.json({ conversationId:c.id,messages:r.rows }); });
app.post('/api/messages', auth, async (req, res) => { const c = await getOrCreateConversation({name:req.user.name,email:req.user.email}, req.user.id); const urgent=bool(req.body?.urgent); const severity=clean(req.body?.severity || (urgent?'high':'normal'),30); const mid=await saveMessage({conversationId:c.id,sender:'customer',senderUserId:req.user.id,message:req.body?.message||'',severity,urgent}); if(urgent||severity==='high'||severity==='critical') await notifyAllAdmins('Problème client urgent', `${req.user.name} a signalé un problème sérieux.`, 'support', severity, 'conversation', c.id); else await notifyAllAdmins('Nouveau message client', `${req.user.name} a envoyé un message.`, 'support', 'normal', 'conversation', c.id); res.status(201).json({ ok:true,conversationId:c.id,messageId:mid }); });

// TRADES
app.get('/api/trades', auth, async (req, res) => { const adminView=['admin','owner'].includes(String(req.user.role||'').toLowerCase())&&req.query.admin==='true'; const r=adminView?await q('SELECT * FROM trades ORDER BY created_at DESC'):await q('SELECT * FROM trades WHERE user_id=$1 ORDER BY created_at DESC',[req.user.id]); res.json({ trades:r.rows.map(x=>({...x,images:parseJson(x.images,[]),createdAt:x.created_at,updatedAt:x.updated_at})) }); });
app.post('/api/trades', auth, async (req,res)=>{ try{ const setting=await q("SELECT value FROM app_settings WHERE key='trade_enabled'"); if(setting.rows[0] && String(setting.rows[0].value).replace(/^\"|\"$/g,'')==='false') return res.status(403).json({message:'Trade désactivé'}); const b=req.body||{};const r=await q('INSERT INTO trades(id,user_id,device,storage,condition,wanted_product_id,message,images) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',[id(),req.user.id,clean(b.device,160),clean(b.storage,80),clean(b.condition,100),b.wantedProductId||null,clean(b.message,2000),JSON.stringify(Array.isArray(b.images)?b.images.slice(0,10):[])]);await notifyAllAdmins('Nouvelle demande Trade',`${req.user.name} a envoyé une demande Trade.`, 'trade','normal','trade',r.rows[0].id);res.status(201).json({trade:r.rows[0]}); }catch{res.status(500).json({message:'Trade impossible'})} });
app.patch('/api/trades/:id/status',auth,admin,async(req,res)=>{const st=clean(req.body?.status,40); if(!['new','reviewing','accepted','rejected','completed'].includes(st))return res.status(400).json({message:'Statut Trade invalide'});const r=await q('UPDATE trades SET status=$1,updated_at=now() WHERE id=$2 RETURNING *',[st,req.params.id]);if(!r.rowCount)return res.status(404).json({message:'Trade introuvable'});if(r.rows[0].user_id)await insertNotification({userId:r.rows[0].user_id,title:'Trade mis à jour',message:`Ton Trade est maintenant: ${st}.`,type:'trade',entityType:'trade',entityId:r.rows[0].id});res.json({trade:r.rows[0]});});

// ADMIN PAYMENTS
app.get('/api/admin/payment-methods', auth, admin, async (req,res)=>{const r=await q('SELECT * FROM payment_methods ORDER BY sort_order,created_at');res.json({paymentMethods:r.rows.map(x=>({...paymentMethodPublic(x),config:parseJson(x.config,{}),provider:x.provider||x.id,logo:x.logo||x.provider||x.id}))});});
app.post('/api/admin/payment-methods', auth, admin, async (req,res)=>{try{const b=req.body||{};const pid=clean(b.id,80)||id();const provider=clean(b.provider||pid,40);const logo=clean(b.logo||provider,40);const r=await q('INSERT INTO payment_methods(id,name,description,enabled,instructions,config,provider,logo,sort_order) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',[pid,clean(b.name,120)||'Paiement',clean(b.description,500),bool(b.enabled,true),clean(b.instructions,1000),JSON.stringify(b.config||{}),provider,logo,Math.max(0,Math.floor(num(b.sortOrder,100)))]);res.status(201).json({paymentMethod:paymentMethodPublic(r.rows[0])});}catch{res.status(500).json({message:'Erreur méthode paiement'})}});
app.patch('/api/admin/payment-methods/:id', auth, admin, async(req,res)=>{try{const b=req.body||{};const r=await q(`UPDATE payment_methods SET name=COALESCE($1,name),description=COALESCE($2,description),enabled=COALESCE($3,enabled),instructions=COALESCE($4,instructions),config=COALESCE($5,config),provider=COALESCE($6,provider),logo=COALESCE($7,logo),sort_order=COALESCE($8,sort_order),updated_at=now() WHERE id=$9 RETURNING *`,[b.name??null,b.description??null,b.enabled!=null?bool(b.enabled):null,b.instructions??null,b.config?JSON.stringify(b.config):null,b.provider??null,b.logo??null,b.sortOrder!=null?Math.floor(num(b.sortOrder)):null,req.params.id]);if(!r.rowCount)return res.status(404).json({message:'Méthode introuvable'});res.json({paymentMethod:paymentMethodPublic(r.rows[0])});}catch{res.status(500).json({message:'Impossible de modifier le paiement'})}});
app.get('/api/admin/payment-methods/:id', auth, admin, async(req,res)=>{const r=await q('SELECT * FROM payment_methods WHERE id=$1',[req.params.id]);if(!r.rowCount)return res.status(404).json({message:'Introuvable'});res.json({paymentMethod:paymentMethodPublic(r.rows[0])});});


// REAL PAYMENT GATEWAYS
async function requireOrderForUser(orderId,userId){const r=await q('SELECT * FROM orders WHERE id=$1 AND user_id=$2',[orderId,userId]);if(!r.rowCount)throw new Error('Commande introuvable');return r.rows[0];}
function stripeAmount(value){return Math.round(Number(value)*100);}
app.post('/api/payments/stripe/checkout-session',auth,async(req,res)=>{try{if(!STRIPE_SECRET_KEY)return res.status(503).json({message:'Stripe n’est pas configuré dans Render'});const order=await requireOrderForUser(clean(req.body?.orderId,80),req.user.id);if(String(order.payment_method)!=='stripe_card')return res.status(400).json({message:'Cette commande n’utilise pas Stripe'});if(String(order.total||0)<=0)return res.status(400).json({message:'Montant invalide'});if(String(order.currency||'USD').toUpperCase()!=='USD')return res.status(400).json({message:'Stripe est configuré ici pour les commandes USD.'});const currency='usd';let items=parseJson(order.items,[]);const service=parseJson(order.service_order,null);if(!items.length&&service?.planId){const pr=await q('SELECT service,name,description,price,currency FROM streaming_plans WHERE id=$1 AND enabled=true',[service.planId]);if(pr.rowCount)items=[{brand:pr.rows[0].service==='netflix'?'Netflix':'Disney+',name:pr.rows[0].name,unitPrice:num(pr.rows[0].price),quantity:1}];}if(!items.length)return res.status(400).json({message:'Aucun article payable trouvé pour cette commande'});const params=new URLSearchParams();params.set('mode','payment');params.set('success_url',clean(req.body?.successUrl,1000)||'http://localhost/success');params.set('cancel_url',clean(req.body?.cancelUrl,1000)||'http://localhost/cancel');params.set('client_reference_id',order.id);params.set('metadata[order_id]',order.id);items.slice(0,50).forEach((it,i)=>{const unit=Math.max(1,stripeAmount(it.unitPrice));params.set(`line_items[${i}][price_data][currency]`,currency);params.set(`line_items[${i}][price_data][product_data][name]`,clean(`${it.brand||''} ${it.name||'Produit'}`,200));params.set(`line_items[${i}][price_data][unit_amount]`,String(unit));params.set(`line_items[${i}][quantity]`,String(Math.max(1,Number(it.quantity||1))));});const r=await fetch('https://api.stripe.com/v1/checkout/sessions',{method:'POST',headers:{Authorization:'Bearer '+STRIPE_SECRET_KEY,'Content-Type':'application/x-www-form-urlencoded'},body:params});const data=await r.json();if(!r.ok)return res.status(502).json({message:data?.error?.message||'Stripe a refusé la session'});await q('UPDATE orders SET payment_reference=$1,updated_at=now() WHERE id=$2',[data.id,order.id]);res.json({id:data.id,url:data.url});}catch(e){res.status(400).json({message:e.message||'Stripe indisponible'});}});
app.get('/api/payments/stripe/session',auth,async(req,res)=>{try{if(!STRIPE_SECRET_KEY)return res.status(503).json({message:'Stripe non configuré'});const order=await requireOrderForUser(clean(req.query?.orderId,80),req.user.id);const r=await fetch('https://api.stripe.com/v1/checkout/sessions/'+encodeURIComponent(clean(req.query?.sessionId,255)),{headers:{Authorization:'Bearer '+STRIPE_SECRET_KEY}});const data=await r.json();if(!r.ok)return res.status(502).json({message:data?.error?.message||'Stripe session introuvable'});res.json({status:data.payment_status||data.status,orderId:order.id});}catch(e){res.status(400).json({message:e.message||'Stripe indisponible'});}});

async function paypalToken(){if(!PAYPAL_CLIENT_ID||!PAYPAL_CLIENT_SECRET)throw new Error('PayPal n’est pas configuré dans Render');const r=await fetch(PAYPAL_BASE+'/v1/oauth2/token',{method:'POST',headers:{Authorization:'Basic '+Buffer.from(PAYPAL_CLIENT_ID+':'+PAYPAL_CLIENT_SECRET).toString('base64'),'Content-Type':'application/x-www-form-urlencoded'},body:'grant_type=client_credentials'});const data=await r.json();if(!r.ok)throw new Error(data?.error_description||'PayPal auth failed');return data.access_token;}
app.post('/api/payments/paypal/create-order',auth,async(req,res)=>{try{const order=await requireOrderForUser(clean(req.body?.orderId,80),req.user.id);if(String(order.payment_method)!=='paypal')return res.status(400).json({message:'Cette commande n’utilise pas PayPal'});if(Number(order.total)<=0)return res.status(400).json({message:'Montant invalide'});if(/htg/i.test(String(order.currency||'')))return res.status(400).json({message:'PayPal exige ici un paiement en USD'});const token=await paypalToken();const r=await fetch(PAYPAL_BASE+'/v2/checkout/orders',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json','PayPal-Request-Id':order.id},body:JSON.stringify({intent:'CAPTURE',purchase_units:[{reference_id:order.id,custom_id:order.id,amount:{currency_code:'USD',value:Number(order.total).toFixed(2)}}],application_context:{return_url:clean(req.body?.returnUrl,1000),cancel_url:clean(req.body?.cancelUrl,1000)}})});const data=await r.json();if(!r.ok)return res.status(502).json({message:data?.message||'PayPal a refusé la commande'});const approval=(data.links||[]).find(x=>x.rel==='approve')?.href;await q('UPDATE orders SET payment_reference=$1,updated_at=now() WHERE id=$2',[data.id,order.id]);res.json({paypalOrderId:data.id,approvalUrl:approval});}catch(e){res.status(400).json({message:e.message||'PayPal indisponible'});}});
app.post('/api/payments/paypal/capture-order',auth,async(req,res)=>{try{const order=await requireOrderForUser(clean(req.body?.orderId,80),req.user.id);const paypalOrderId=clean(req.body?.paypalOrderId,100);if(!paypalOrderId||String(order.payment_reference||'')!==paypalOrderId)return res.status(400).json({message:'Référence PayPal invalide pour cette commande'});const token=await paypalToken();const r=await fetch(PAYPAL_BASE+'/v2/checkout/orders/'+encodeURIComponent(paypalOrderId)+'/capture',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json','PayPal-Request-Id':order.id}});const data=await r.json();if(!r.ok)return res.status(502).json({message:data?.message||'Capture PayPal refusé'});const paid=data.status==='COMPLETED';await q("UPDATE orders SET payment_status=$1,payment_reference=$2,paid_at=CASE WHEN $1='paid' THEN now() ELSE paid_at END,updated_at=now() WHERE id=$3",[paid?'paid':'pending',paypalOrderId,order.id]);if(paid)await insertNotification({userId:req.user.id,title:'Paiement PayPal confirmé',message:`Le paiement de ta commande ${order.id.slice(0,8)} est confirmé.`,type:'payment',entityType:'order',entityId:order.id,force:true});res.json({ok:true,status:data.status});}catch(e){res.status(400).json({message:e.message||'PayPal indisponible'});}});

app.post('/api/payments/manual/confirm',auth,async(req,res)=>{try{const order=await requireOrderForUser(clean(req.body?.orderId,80),req.user.id);const reference=clean(req.body?.reference,200);if(!reference)return res.status(400).json({message:'Référence de transaction requise'});await q("UPDATE orders SET payment_reference=$1,payment_status='pending',updated_at=now() WHERE id=$2",[reference,order.id]);await notifyAllAdmins('Paiement à vérifier',`${req.user.name} a envoyé la référence de paiement ${reference} pour la commande ${order.id.slice(0,8)}. `,'payment','high','order',order.id);res.json({ok:true,status:'pending_review'});}catch(e){res.status(400).json({message:e.message||'Paiement manuel impossible'});}});

// AI SUPPORT — secret stays server-side; optional until OPENAI_API_KEY is configured.
app.post('/api/chatbot', auth, async (req, res) => {
  const text = clean(req.body?.message, 4000); if (!text) return res.status(400).json({ message:'Message vide' });
  const history = Array.isArray(req.body?.history) ? req.body.history.slice(-12).map(m => ({ role:m?.from==='bot'?'assistant':'user', content:clean(m?.text || m?.message, 2000) })).filter(m=>m.content) : [];
  const apiKey = String(process.env.OPENAI_API_KEY || '').trim(); const model = clean(process.env.OPENAI_MODEL || 'gpt-5.6-luna', 100);
  let reply = ''; let needsAdmin = false; let severity = 'normal'; let aiConfigured = !!apiKey; let aiError = null; let summary='';
  const serious = /(arnaque|fraude|vol|escroquerie|probl[eè]me grave|urgent|urgence|compte pirat|paiement inconnu|paiement non autoris|bloqu[eé]|erreur de paiement|commande perdue)/i.test(text);
  if (serious) { needsAdmin = true; severity = 'high'; }
  if (apiKey) {
    try {
      const messages = [
        { role:'system', content:`Tu es Zhuo Support, l'assistant IA officiel de ZhuoMarket. Réponds en français simple, court et utile. Tu es le seul chat support côté client. Ne demande jamais au client d'écrire lui-même à l'administrateur. Si le problème nécessite une intervention humaine (paiement inconnu, fraude, compte compromis, commande bloquée/perdue, litige ou problème complexe), indique que tu transmets automatiquement la demande à l'équipe. Ne révèle jamais de secrets, tokens, mots de passe, clés API ou données privées.`, },
        ...history,
        { role:'user', content:text }
      ];
      const r = await fetch('https://api.openai.com/v1/responses',{method:'POST',headers:{'Authorization':`Bearer ${apiKey}`,'Content-Type':'application/json'},body:JSON.stringify({model,input:messages,max_output_tokens:500})});
      if(r.ok){const data=await r.json();const out=(data.output||[]).flatMap(x=>x.content||[]).filter(x=>typeof x.text==='string').map(x=>x.text).join('\n').trim();if(out)reply=out; else aiError='empty_response';} else { aiError='api_http_'+r.status; }
    }catch(e){ aiError='network_error'; }
  }
  if(!reply){
    if(/paiement|moncash|natcash|carte/i.test(text)) reply='Je peux t’aider avec ton paiement. Si le paiement est inconnu, refusé ou bloqué, je transmets automatiquement le problème à l’équipe ZhuoMarket.';
    else if(/commande|livraison|expédi|livr/i.test(text)) reply='Je peux t’aider avec ta commande. Si elle est bloquée, perdue ou présente un problème important, je transmets automatiquement le dossier à l’équipe.';
    else if(/compte|connexion|mot de passe/i.test(text)) reply='Je peux t’aider avec ton compte et ta connexion. Si ton compte semble compromis ou bloqué, je transmets automatiquement le problème à l’équipe.';
    else reply='Bonjour 👋 Je suis Zhuo Support, l’assistant IA de ZhuoMarket. Explique-moi ton problème et je vais t’aider.';
  }
  // Heuristic escalation remains active even if the external AI is unavailable.
  if (serious || /admin|humain|équipe|support humain|intervention/i.test(reply)) needsAdmin=true;
  if (needsAdmin && req.user?.id) {
    try {
      const c = await getOrCreateConversation({name:req.user.name,email:req.user.email}, req.user.id);
      const convoText=[...history.filter(x=>x.role==='user').map(x=>x.content),text].slice(-8).join(' | ');
      summary = `Résumé IA — Client: ${req.user.name||'Client'} — Problème: ${clean(convoText,1200)}`;
      await saveMessage({conversationId:c.id,sender:'customer',senderUserId:req.user.id,message:text,severity,urgent:severity==='high'});
      await saveMessage({conversationId:c.id,sender:'admin',senderUserId:null,message:summary,severity:'high',urgent:severity==='high'});
      await notifyAllAdmins('Zhuo Support — résumé IA', summary, 'support', severity, 'conversation', c.id);
      return res.json({reply,needsAdmin:true,conversationId:c.id,severity,summary,aiConfigured,aiError});
    } catch { /* return AI answer even if escalation storage fails */ }
  }
  res.json({reply,needsAdmin:false,conversationId:null,severity,summary:'',aiConfigured,aiError});
});

// ADMIN NOTIFICATIONS alias used by current frontend
app.get('/api/admin/notifications', auth, admin, async (req,res)=>{const r=await q("SELECT * FROM notifications WHERE user_id=$1 OR user_id IS NULL ORDER BY created_at DESC LIMIT 100",[req.user.id]);res.json({notifications:r.rows.map(notificationOut)});});
app.post('/api/admin/notifications/:id/seen', auth, admin, async(req,res)=>{const r=await q('UPDATE notifications SET read=true,seen_at=COALESCE(seen_at,now()) WHERE id=$1 AND (user_id=$2 OR user_id IS NULL) RETURNING *',[req.params.id,req.user.id]);if(!r.rowCount)return res.status(404).json({message:'Notification introuvable'});res.json({notification:notificationOut(r.rows[0])});});

app.use((err, req, res, next) => { console.error(err); if (res.headersSent) return next(err); res.status(500).json({ message: 'Erreur serveur' }); });
app.use((req,res)=>res.status(404).json({message:'Route introuvable'}));

initDb().then(()=>app.listen(PORT,()=>console.log(`ZhuoMarket backend running on port ${PORT}`))).catch(err=>{console.error('Database initialization failed:',err);process.exit(1)});
