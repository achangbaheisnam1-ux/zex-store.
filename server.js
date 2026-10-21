const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.sqlite');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INTEGER, order_ref TEXT UNIQUE NOT NULL, game TEXT NOT NULL, player_id TEXT NOT NULL, server TEXT, item TEXT NOT NULL, amount INTEGER NOT NULL, payment TEXT NOT NULL DEFAULT 'UPI', utr TEXT, status TEXT NOT NULL DEFAULT 'pending_verification', admin_note TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id));
`);
const q = (sql) => db.prepare(sql);
const isProd = process.env.NODE_ENV === 'production';
if (!process.env.SESSION_SECRET && isProd) throw new Error('Set SESSION_SECRET in production.');
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false }));
app.use(session({
  name: 'zex.sid', secret: process.env.SESSION_SECRET || 'local-development-only-change-me',
  resave: false, saveUninitialized: false, store: new SQLiteStore({ db: 'sessions.sqlite', dir: path.dirname(DB_PATH) }),
  cookie: { httpOnly: true, sameSite: 'lax', secure: isProd, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
const publicDir = path.join(__dirname, 'public');
const safeUser = u => ({ id: u.id, name: u.name, user: u.username, role: u.role, isAdmin: u.role === 'admin' });
function auth(req,res,next){ if(!req.session.userId) return res.status(401).json({status:'error',code:'unauthorized'}); next(); }
function admin(req,res,next){ if(!req.session.userId) return res.status(401).json({status:'error',code:'unauthorized'}); const u=q('SELECT role FROM users WHERE id=?').get(req.session.userId); if(!u || u.role!=='admin') return res.status(403).json({status:'error',code:'forbidden'}); next(); }
function normalizeUsername(v){return String(v||'').trim().toLowerCase();}
function validLogin(u,p){return u.length>=3 && u.length<=190 && p.length>=8 && p.length<=200;}
async function bootstrapAdmin(){
  const username=normalizeUsername(process.env.ADMIN_EMAIL);
  const password=process.env.ADMIN_PASSWORD || '';
  if(!username || !password) { console.warn('Admin bootstrap skipped: set ADMIN_EMAIL and ADMIN_PASSWORD.'); return; }
  if(password.length<12) throw new Error('ADMIN_PASSWORD must be at least 12 characters.');
  const existing=q('SELECT id,role FROM users WHERE username=?').get(username);
  if(existing){ if(existing.role!=='admin') q("UPDATE users SET role='admin' WHERE id=?").run(existing.id); return; }
  q("INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,'admin')").run(process.env.ADMIN_NAME||'Store Admin',username,await bcrypt.hash(password,12));
}
app.post('/api/auth/register', rateLimit({windowMs:3600000,limit:10}), async (req,res)=>{
  const name=String(req.body.name||'').trim().slice(0,80), username=normalizeUsername(req.body.user), password=String(req.body.password||'');
  if(!name||!username||!validLogin(username,password)) return res.status(400).json({status:'error',code:'invalid'});
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(username) && !/^\+?[0-9]{8,16}$/.test(username)) return res.status(400).json({status:'error',code:'invalid'});
  if(q('SELECT id FROM users WHERE username=?').get(username)) return res.status(409).json({status:'error',code:'exists'});
  const info=q("INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,'customer')").run(name,username,await bcrypt.hash(password,12));
  req.session.userId=info.lastInsertRowid; res.json({status:'success',user:safeUser(q('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid))});
});
app.post('/api/auth/login', rateLimit({windowMs:900000,limit:10}), async (req,res)=>{
  const username=normalizeUsername(req.body.user), password=String(req.body.password||'');
  const u=q('SELECT * FROM users WHERE username=?').get(username);
  if(!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({status:'error',code:'bad_creds'});
  req.session.userId=u.id; res.json({status:'success',user:safeUser(u)});
});
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>{res.clearCookie('zex.sid');res.json({status:'success'});}));
app.get('/api/auth/me',(req,res)=>{if(!req.session.userId)return res.status(401).json({status:'error'});const u=q('SELECT * FROM users WHERE id=?').get(req.session.userId);if(!u)return res.status(401).json({status:'error'});res.json({user:safeUser(u)});});
app.get('/api/account/orders',auth,(req,res)=>res.json({orders:q('SELECT order_ref AS ref,game,item,amount,status,created_at AS createdAt FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 100').all(req.session.userId)}));
app.post('/api/account/password',auth,async(req,res)=>{
 const u=q('SELECT * FROM users WHERE id=?').get(req.session.userId), current=String(req.body.current||''), password=String(req.body.password||'');
 if(!u||!(await bcrypt.compare(current,u.password_hash)))return res.status(400).json({status:'error',code:'bad_creds'});
 if(password.length<8||password.length>200)return res.status(400).json({status:'error',code:'weak'});
 q('UPDATE users SET password_hash=? WHERE id=?').run(await bcrypt.hash(password,12),u.id);res.json({status:'success'});
});
app.post('/api/orders', (req,res)=>{
 const b=req.body||{}, game=String(b.game||'').slice(0,100), playerId=String(b.playerId||'').trim().slice(0,80), server=String(b.server||'').trim().slice(0,30), item=String(b.item||'').slice(0,120), amount=Number(b.amount), utr=String(b.utr||'').trim().slice(0,30);
 if(!game||!playerId||!item||!Number.isFinite(amount)||amount<1||amount>1000000||!/^[A-Za-z0-9]{8,22}$/.test(utr))return res.status(400).json({status:'error',code:'invalid_order'});
 const ref='ZEX-'+Date.now().toString(36).toUpperCase()+'-'+crypto.randomBytes(3).toString('hex').toUpperCase();
 const uid=req.session.userId||null;
 q("INSERT INTO orders(user_id,order_ref,game,player_id,server,item,amount,payment,utr,status) VALUES(?,?,?,?,?,?,?,'UPI',?,'pending_verification')").run(uid,ref,game,playerId,server,item,Math.round(amount),utr);
 res.status(201).json({status:'success',orderRef:ref});
});
app.get('/api/admin/summary',admin,(req,res)=>{
 res.json({orders:q('SELECT COUNT(*) n FROM orders').get().n,pending:q("SELECT COUNT(*) n FROM orders WHERE status='pending_verification'").get().n,revenue:q("SELECT COALESCE(SUM(amount),0) n FROM orders WHERE status IN ('paid','processing','completed','delivered')").get().n,customers:q("SELECT COUNT(*) n FROM users WHERE role='customer'").get().n});
});
app.get('/api/admin/orders',admin,(req,res)=>{
 const status=String(req.query.status||'').trim();
 const rows=status?q('SELECT o.*,u.username AS customer FROM orders o LEFT JOIN users u ON u.id=o.user_id WHERE o.status=? ORDER BY o.id DESC LIMIT 500').all(status):q('SELECT o.*,u.username AS customer FROM orders o LEFT JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 500').all();
 res.json({orders:rows});
});
app.patch('/api/admin/orders/:id',admin,(req,res)=>{
 const status=String(req.body.status||''), note=String(req.body.admin_note||'').slice(0,500);
 if(!['pending_verification','paid','processing','completed','rejected','refunded'].includes(status))return res.status(400).json({status:'error',code:'invalid_status'});
 const result=q('UPDATE orders SET status=?,admin_note=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status,note,Number(req.params.id));
 if(!result.changes)return res.status(404).json({status:'error',code:'not_found'});
 res.json({status:'success'});
});
app.get('/api/admin/products',admin,(req,res)=>res.json({note:'Product catalogue is currently defined in public/index.html; price editing is not yet backed by a database.'}));
app.get('/admin',(req,res)=>{ if(!req.session.userId)return res.redirect('/?admin-login=1');const u=q('SELECT role FROM users WHERE id=?').get(req.session.userId);if(!u||u.role!=='admin')return res.status(403).send('Forbidden');res.sendFile(path.join(publicDir,'admin.html'));});
app.use(express.static(publicDir,{extensions:['html']}));
app.get('*',(req,res)=>res.sendFile(path.join(publicDir,'index.html')));
bootstrapAdmin().then(()=>app.listen(PORT,()=>console.log(`Zex Store running on port ${PORT}`))).catch(e=>{console.error(e);process.exit(1);});
