const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const DATA_DIR = process.env.DATA_DIR || process.env.RAILWAY_VOLUME_MOUNT_PATH || path.join(ROOT, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'data.sqlite');
const PORT = Number(process.env.PORT || 3000);
const IS_PRODUCTION = String(process.env.NODE_ENV || '').toLowerCase() === 'production';
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || '');
if (ADMIN_PASSWORD.length < 12) {
  throw new Error('ADMIN_PASSWORD must be set and contain at least 12 characters.');
}
fs.mkdirSync(PUBLIC, { recursive: true });
const db = new DatabaseSync(DB_FILE);
db.exec(`PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('superadmin','admin','candidate')), name TEXT NOT NULL, group_name TEXT DEFAULT '', squad TEXT DEFAULT '', phone TEXT DEFAULT '', email TEXT DEFAULT '', avatar TEXT DEFAULT '', status TEXT DEFAULT 'active', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS stages (id INTEGER PRIMARY KEY, title TEXT NOT NULL, subtitle TEXT NOT NULL, icon TEXT NOT NULL, accent TEXT NOT NULL, sort_order INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stamps (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, stage_id INTEGER NOT NULL, admin_id INTEGER NOT NULL, note TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, stage_id), FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY(stage_id) REFERENCES stages(id), FOREIGN KEY(admin_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS missions (id INTEGER PRIMARY KEY AUTOINCREMENT, stage_id INTEGER NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, date_from TEXT NOT NULL, date_to TEXT NOT NULL, sort_order INTEGER NOT NULL, FOREIGN KEY(stage_id) REFERENCES stages(id));
CREATE TABLE IF NOT EXISTS mission_progress (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, mission_id INTEGER NOT NULL, completed INTEGER NOT NULL DEFAULT 0, proof TEXT DEFAULT '', proof_image TEXT DEFAULT '', completed_at TEXT, UNIQUE(user_id, mission_id), FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY(mission_id) REFERENCES missions(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, stage_id INTEGER, event_date TEXT NOT NULL, time_start TEXT DEFAULT '', time_end TEXT DEFAULT '', location TEXT DEFAULT '', description TEXT DEFAULT '', program TEXT DEFAULT '', organizer TEXT DEFAULT '', contact TEXT DEFAULT '', materials TEXT DEFAULT '', type TEXT DEFAULT 'ШМБ', sort_order INTEGER DEFAULT 0, FOREIGN KEY(stage_id) REFERENCES stages(id));
CREATE TABLE IF NOT EXISTS event_registrations (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, event_id INTEGER NOT NULL, status TEXT DEFAULT 'registered', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id,event_id), FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS event_materials (id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL, name TEXT NOT NULL, mime TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER NOT NULL, action TEXT NOT NULL, target_user_id INTEGER, payload TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(admin_id) REFERENCES users(id));`);

function ensureColumn(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(x => x.name);
  if (!cols.includes(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}
ensureColumn('users', 'avatar', "TEXT DEFAULT ''");
ensureColumn('mission_progress', 'proof_image', "TEXT DEFAULT ''");
ensureColumn('events', 'program', "TEXT DEFAULT ''");
ensureColumn('events', 'organizer', "TEXT DEFAULT ''");
ensureColumn('events', 'contact', "TEXT DEFAULT ''");
ensureColumn('events', 'materials', "TEXT DEFAULT ''");

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const candidate = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(hash, 'hex'));
}
function validImage(value) {
  if (!value) return true;
  if (typeof value !== 'string') return false;
  if (!/^data:image\/(png|jpe?g|webp);base64,[A-Za-z0-9+/=]+$/.test(value) && !/^data:image\/svg\+xml;base64,[A-Za-z0-9+/=]+$/.test(value)) return false;
  return value.length <= 2_500_000;
}
function clean(v, max = 5000) { return String(v ?? '').trim().slice(0, max); }

const MATERIAL_MAX = 20_000_000;
const MATERIAL_MIMES = new Set([
  'application/pdf','application/vnd.ms-powerpoint','application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'text/plain','text/csv','image/png','image/jpeg','image/webp','image/svg+xml'
]);
function validMaterial(value, mime, size) {
  if (!value || typeof value !== 'string' || !value.startsWith(`data:${mime};base64,`)) return false;
  if (!MATERIAL_MIMES.has(mime)) return false;
  if (!Number.isFinite(Number(size)) || Number(size) < 1 || Number(size) > MATERIAL_MAX) return false;
  return value.length <= Math.ceil(MATERIAL_MAX * 1.45) + 100;
}
function safeDownloadName(name) {
  return String(name || 'material').replace(/[\\/\0]/g,'_').replace(/["<>:|?*]/g,'_').slice(0,180) || 'material';
}

function loadSeedData() {
  const seedFile = path.join(ROOT, 'seed-data.json');
  if (!fs.existsSync(seedFile)) return { stages: [], missions: [], events: [] };
  try {
    const value = JSON.parse(fs.readFileSync(seedFile, 'utf8'));
    return {
      stages: Array.isArray(value.stages) ? value.stages : [],
      missions: Array.isArray(value.missions) ? value.missions : [],
      events: Array.isArray(value.events) ? value.events : []
    };
  } catch (e) {
    console.error('Cannot read seed-data.json:', e.message);
    return { stages: [], missions: [], events: [] };
  }
}

function seed() {
  const seedData = loadSeedData();
  if (!db.prepare('SELECT id FROM stages LIMIT 1').get()) {
    const s = db.prepare('INSERT INTO stages(id,title,subtitle,icon,accent,sort_order) VALUES(?,?,?,?,?,?)');
    for (const x of seedData.stages) s.run(x.id, x.title, x.subtitle, x.icon, x.accent, x.sort_order);
  }
  if (!db.prepare('SELECT id FROM missions LIMIT 1').get()) {
    const m = db.prepare('INSERT INTO missions(id,stage_id,title,description,date_from,date_to,sort_order) VALUES(?,?,?,?,?,?,?)');
    for (const x of seedData.missions) m.run(x.id, x.stage_id, x.title, x.description, x.date_from, x.date_to, x.sort_order);
  }
  if (!db.prepare('SELECT id FROM events LIMIT 1').get()) {
    const e = db.prepare('INSERT INTO events(id,title,stage_id,event_date,time_start,time_end,location,description,program,organizer,contact,materials,type,sort_order) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
    for (const x of seedData.events) e.run(x.id, x.title, x.stage_id, x.event_date, x.time_start, x.time_end, x.location, x.description, x.program, x.organizer, x.contact, x.materials, x.type, x.sort_order);
  }

  if (!db.prepare('SELECT id FROM users WHERE username=?').get('admin')) {
    db.prepare('INSERT INTO users(username,password_hash,role,name) VALUES(?,?,?,?)')
      .run('admin', hashPassword(ADMIN_PASSWORD), 'superadmin', 'Главный администратор');
  }
}

seed();

const sessions = new Map();
const token = () => crypto.randomBytes(32).toString('hex');
function currentUser(req) {
  const m = (req.headers.cookie || '').match(/(?:^|; )smb_session=([^;]+)/);
  if (!m) return null;
  const id = sessions.get(m[1]);
  return id ? db.prepare('SELECT id,username,role,name,group_name,squad,phone,email,avatar,status FROM users WHERE id=?').get(id) : null;
}
function send(res,status,data,headers={}) {
  const body = Buffer.isBuffer(data) || typeof data === 'string' ? data : JSON.stringify(data);
  res.writeHead(status, {'Content-Type': Buffer.isBuffer(data) ? 'application/octet-stream' : typeof data === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8', ...headers});
  res.end(body);
}
const json = (res,status,data,h={}) => send(res,status,data,{'Cache-Control':'no-store',...h});
async function body(req) {
  return new Promise((resolve,reject)=>{
    let raw='';
    req.on('data',c=>{ raw += c; if(raw.length > 35_000_000) req.destroy(); });
    req.on('end',()=>{ try { resolve(raw ? JSON.parse(raw) : {}); } catch(e) { reject(e); } });
    req.on('error',reject);
  });
}
function requireAuth(req,res,roles=[]) {
  const u=currentUser(req);
  if(!u){ json(res,401,{error:'Требуется авторизация'}); return null; }
  if(roles.length && !roles.includes(u.role)){ json(res,403,{error:'Недостаточно прав'}); return null; }
  return u;
}
const audit = (adminId,action,target,payload='') => db.prepare('INSERT INTO audit_log(admin_id,action,target_user_id,payload) VALUES(?,?,?,?)').run(adminId,action,target,payload);

function userView(id) {
  const u=db.prepare('SELECT id,username,role,name,group_name,squad,phone,email,avatar,status,created_at FROM users WHERE id=?').get(id);
  if(!u) return null;
  const stamps=db.prepare(`SELECT s.id,s.stage_id,s.note,s.created_at,st.title,st.subtitle,st.icon,st.accent,a.name admin_name FROM stamps s JOIN stages st ON st.id=s.stage_id JOIN users a ON a.id=s.admin_id WHERE s.user_id=? ORDER BY st.sort_order`).all(id);
  const missions=db.prepare(`SELECT m.*,COALESCE(mp.completed,0) completed,mp.proof,mp.proof_image,mp.completed_at FROM missions m LEFT JOIN mission_progress mp ON mp.mission_id=m.id AND mp.user_id=? ORDER BY m.sort_order`).all(id);
  const events=db.prepare(`SELECT e.*,COALESCE(er.status,'') registration_status FROM events e LEFT JOIN event_registrations er ON er.event_id=e.id AND er.user_id=? ORDER BY e.event_date,e.time_start`).all(id);
  return {...u,stamps,missions,events,progress:stamps.length,totalStages:6};
}
function eventView(id, userId=null) {
  const e=db.prepare(`SELECT e.*,st.title stage_title FROM events e LEFT JOIN stages st ON st.id=e.stage_id WHERE e.id=?`).get(id);
  if(!e) return null;
  if(userId) e.registration_status=db.prepare('SELECT status FROM event_registrations WHERE event_id=? AND user_id=?').get(id,userId)?.status || '';
  e.registrations=db.prepare('SELECT COUNT(*) n FROM event_registrations WHERE event_id=?').get(id).n;
  e.material_files=db.prepare('SELECT id,name,mime,size,created_at FROM event_materials WHERE event_id=? ORDER BY id DESC').all(id);
  return e;
}

async function api(req,res,url) {
  const user=currentUser(req);
  if(req.method==='POST'&&url==='/api/login'){
    const b=await body(req); const u=db.prepare('SELECT * FROM users WHERE username=?').get(clean(b.username,100));
    if(!u||!verifyPassword(String(b.password||''),u.password_hash)) return json(res,401,{error:'Неверный логин или пароль'});
    if(u.status==='pending') return json(res,403,{error:'Регистрация получена. Дождитесь подтверждения штабом.'});
    if(u.status!=='active') return json(res,403,{error:'Доступ к аккаунту заблокирован. Обратитесь в штаб.'});
    const t=token(); sessions.set(t,u.id);
    const secure = IS_PRODUCTION || req.headers['x-forwarded-proto'] === 'https';
    return json(res,200,{user:{id:u.id,username:u.username,role:u.role,name:u.name,group_name:u.group_name,squad:u.squad,phone:u.phone,email:u.email,avatar:u.avatar}},{'Set-Cookie':`smb_session=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800${secure?' ; Secure':''}`.replace(' ; Secure','; Secure')});
  }
  if(req.method==='POST'&&url==='/api/register'){
    const b=await body(req);
    const name=clean(b.name,120), username=clean(b.username,100), password=String(b.password||'');
    if(!name||!username||password.length<8)return json(res,400,{error:'Заполните ФИО, логин и пароль не короче 8 символов'});
    if(!/^[A-Za-zА-Яа-яЁё0-9._-]{3,100}$/.test(username))return json(res,400,{error:'Логин: минимум 3 символа, только буквы, цифры, точка, дефис и подчёркивание'});
    if(db.prepare('SELECT id FROM users WHERE username=?').get(username))return json(res,400,{error:'Такой логин уже существует'});
    if(b.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(b.email)))return json(res,400,{error:'Проверьте E-mail'});
    try{
      const r=db.prepare('INSERT INTO users(username,password_hash,role,name,group_name,squad,phone,email,status) VALUES(?,?,?,?,?,?,?,?,?)').run(username,hashPassword(password),'candidate',name,clean(b.group_name,120),clean(b.squad,120),clean(b.phone,80),clean(b.email,160),'pending');
      return json(res,201,{ok:true,id:Number(r.lastInsertRowid),message:'Заявка отправлена'});
    }catch(e){return json(res,400,{error:'Не удалось создать аккаунт'});}
  }
  if(req.method==='POST'&&url==='/api/logout'){
    const m=(req.headers.cookie||'').match(/(?:^|; )smb_session=([^;]+)/); if(m)sessions.delete(m[1]);
    const secure = IS_PRODUCTION || req.headers['x-forwarded-proto'] === 'https';
    return json(res,200,{ok:true},{'Set-Cookie':`smb_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure?'; Secure':''}`});
  }
  if(url==='/api/me') return json(res,200,{user});

  if(url.startsWith('/api/public/candidate/')&&req.method==='GET'){
    const id=Number(url.split('/').pop()),v=userView(id); if(!v)return json(res,404,{error:'Профиль не найден'});
    return json(res,200,{id:v.id,name:v.name,squad:v.squad,group_name:v.group_name,avatar:v.avatar,progress:v.progress,totalStages:v.totalStages,stamps:v.stamps.map(s=>({stage_id:s.stage_id,title:s.title,icon:s.icon,created_at:s.created_at}))});
  }

  if(url==='/api/passport'&&req.method==='GET'){
    const u=requireAuth(req,res); if(!u)return;
    return json(res,200,{user:userView(u.id),stages:db.prepare('SELECT * FROM stages ORDER BY sort_order').all()});
  }
  if(url==='/api/profile'&&req.method==='PUT'){
    const u=requireAuth(req,res); if(!u)return;
    const b=await body(req); if(!clean(b.name,120))return json(res,400,{error:'Имя не может быть пустым'}); if(!validImage(b.avatar))return json(res,400,{error:'Фото имеет неверный формат или слишком большое'});
    db.prepare('UPDATE users SET name=?,group_name=?,squad=?,phone=?,email=?,avatar=? WHERE id=?').run(clean(b.name,120),clean(b.group_name,120),clean(b.squad,120),clean(b.phone,80),clean(b.email,160),b.avatar||'',u.id);
    return json(res,200,{user:db.prepare('SELECT id,username,role,name,group_name,squad,phone,email,avatar,status FROM users WHERE id=?').get(u.id)});
  }
  if(url==='/api/mission'&&req.method==='POST'){
    const u=requireAuth(req,res); if(!u)return; const b=await body(req),mid=Number(b.mission_id);
    if(!db.prepare('SELECT id FROM missions WHERE id=?').get(mid))return json(res,404,{error:'Миссия не найдена'});
    if(!validImage(b.proof_image))return json(res,400,{error:'Фото имеет неверный формат или слишком большое'});
    db.prepare(`INSERT INTO mission_progress(user_id,mission_id,completed,proof,proof_image,completed_at) VALUES(?,?,1,?,?,CURRENT_TIMESTAMP) ON CONFLICT(user_id,mission_id) DO UPDATE SET completed=1,proof=excluded.proof,proof_image=excluded.proof_image,completed_at=CURRENT_TIMESTAMP`).run(u.id,mid,clean(b.proof,1000),b.proof_image||'');
    return json(res,200,{ok:true});
  }
  if(url==='/api/event/register'&&req.method==='POST'){
    const u=requireAuth(req,res); if(!u)return; const b=await body(req),eid=Number(b.event_id);
    if(!db.prepare('SELECT id FROM events WHERE id=?').get(eid))return json(res,404,{error:'Событие не найдено'});
    db.prepare(`INSERT INTO event_registrations(user_id,event_id,status) VALUES(?,?,?) ON CONFLICT(user_id,event_id) DO UPDATE SET status=excluded.status`).run(u.id,eid,'registered');
    return json(res,200,{ok:true});
  }
  if(url.startsWith('/api/event-material/')&&req.method==='GET'){
    const u=requireAuth(req,res); if(!u)return;
    const id=Number(url.split('/').pop()),m=db.prepare('SELECT * FROM event_materials WHERE id=?').get(id);
    if(!m)return send(res,404,'Материал не найден');
    const prefix=`data:${m.mime};base64,`;
    if(!m.data.startsWith(prefix))return send(res,500,'Материал повреждён');
    const buf=Buffer.from(m.data.slice(prefix.length),'base64');
    return send(res,200,buf,{'Content-Type':m.mime,'Content-Disposition':`inline; filename*=UTF-8''${encodeURIComponent(safeDownloadName(m.name))}`,'Cache-Control':'private, max-age=3600'});
  }
  if(url.startsWith('/api/event/')&&req.method==='GET'){
    const u=requireAuth(req,res); if(!u)return; const id=Number(url.split('/').pop()),e=eventView(id,u.id); if(!e)return json(res,404,{error:'Событие не найдено'}); return json(res,200,{event:e});
  }

  if(url==='/api/admin/dashboard'&&req.method==='GET'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return;
    const stats={candidates:db.prepare("SELECT COUNT(*) n FROM users WHERE role='candidate'").get().n,admins:db.prepare("SELECT COUNT(*) n FROM users WHERE role IN ('admin','superadmin')").get().n,stamps:db.prepare('SELECT COUNT(*) n FROM stamps').get().n,missions:db.prepare('SELECT COUNT(*) n FROM mission_progress WHERE completed=1').get().n,events:db.prepare('SELECT COUNT(*) n FROM events').get().n};
    return json(res,200,{stats});
  }
  if(url==='/api/admin/candidates'&&req.method==='GET'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const q=new URL(req.url,'http://x').searchParams.get('q')||'';
    const rows=db.prepare(`SELECT u.id,u.username,u.name,u.group_name,u.squad,u.phone,u.email,u.avatar,u.status,COUNT(s.id) stamps FROM users u LEFT JOIN stamps s ON s.user_id=u.id WHERE u.role='candidate' AND (u.name LIKE ? OR u.username LIKE ? OR u.group_name LIKE ? OR u.squad LIKE ?) GROUP BY u.id ORDER BY u.name`).all(`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`);
    return json(res,200,{candidates:rows});
  }
  if(url.startsWith('/api/admin/candidate/')&&req.method==='GET'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const id=Number(url.split('/').pop()),v=userView(id); if(!v)return json(res,404,{error:'Пользователь не найден'}); return json(res,200,{candidate:v});
  }
  if(url.startsWith('/api/admin/user/')&&req.method==='PATCH' && url.endsWith('/status')){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return;
    const id=Number(url.split('/').slice(-2,-1)[0]), target=db.prepare('SELECT id,role,status FROM users WHERE id=?').get(id);
    if(!target)return json(res,404,{error:'Пользователь не найден'});
    const b=await body(req); if(!['active','blocked','pending'].includes(b.status))return json(res,400,{error:'Недопустимый статус'});
    db.prepare('UPDATE users SET status=? WHERE id=?').run(b.status,id);
    audit(u.id,'change_user_status',id,JSON.stringify({status:b.status}));
    return json(res,200,{ok:true,status:b.status});
  }
  if(url.startsWith('/api/admin/user/')&&req.method==='PUT'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const id=Number(url.split('/').pop()),target=db.prepare('SELECT * FROM users WHERE id=?').get(id); if(!target)return json(res,404,{error:'Пользователь не найден'});
    const b=await body(req); if(!clean(b.name,120))return json(res,400,{error:'Имя не может быть пустым'}); if(!validImage(b.avatar))return json(res,400,{error:'Фото имеет неверный формат или слишком большое'});
    const nextRole=['candidate','admin','superadmin'].includes(b.role)?b.role:target.role;
    if(target.role==='superadmin' && u.id!==target.id)return json(res,403,{error:'Главного администратора нельзя редактировать другим пользователям'});
    if(nextRole!==target.role && u.role!=='superadmin')return json(res,403,{error:'Только главный администратор может менять роли'});
    if(nextRole==='superadmin' && u.role!=='superadmin')return json(res,403,{error:'Недостаточно прав'});
    if(b.password && String(b.password).length<8)return json(res,400,{error:'Новый пароль должен быть не короче 8 символов'});
    const passwordPart=b.password ? ',password_hash=?' : '';
    const nextStatus=['active','blocked'].includes(b.status)?b.status:target.status;
    const params=[clean(b.name,120),clean(b.group_name,120),clean(b.squad,120),clean(b.phone,80),clean(b.email,160),b.avatar||'',nextRole,nextStatus,id];
    if(b.password) params.splice(6,0,hashPassword(String(b.password)));
    db.prepare(`UPDATE users SET name=?,group_name=?,squad=?,phone=?,email=?,avatar=?${passwordPart},role=?,status=? WHERE id=?`).run(...params);
    audit(u.id,'edit_user',id,JSON.stringify({role:nextRole,password_changed:Boolean(b.password)}));
    return json(res,200,{ok:true});
  }
  if(url==='/api/admin/stamp'&&req.method==='POST'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const b=await body(req),uid=Number(b.user_id),sid=Number(b.stage_id); const target=db.prepare('SELECT id,role FROM users WHERE id=?').get(uid);
    if(!target||target.role!=='candidate')return json(res,400,{error:'Некорректный кандидат'}); if(!db.prepare('SELECT id FROM stages WHERE id=?').get(sid))return json(res,400,{error:'Некорректный этап'});
    db.prepare(`INSERT INTO stamps(user_id,stage_id,admin_id,note) VALUES(?,?,?,?) ON CONFLICT(user_id,stage_id) DO UPDATE SET admin_id=excluded.admin_id,note=excluded.note,created_at=CURRENT_TIMESTAMP`).run(uid,sid,u.id,clean(b.note,1000));
    audit(u.id,'stamp',uid,JSON.stringify({stage_id:sid,note:b.note||''})); return json(res,200,{ok:true});
  }
  if(url==='/api/admin/stages'&&req.method==='GET'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return;
    return json(res,200,{stages:db.prepare('SELECT * FROM stages ORDER BY sort_order').all()});
  }
  if(url.startsWith('/api/admin/stages/')&&req.method==='PATCH'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return;
    const id=Number(url.split('/').pop()),old=db.prepare('SELECT * FROM stages WHERE id=?').get(id); if(!old)return json(res,404,{error:'Штамп не найден'});
    const b=await body(req); if(!clean(b.title,120)||!clean(b.subtitle,240))return json(res,400,{error:'Название и описание обязательны'});
    const iconValue=String(b.icon??'').trim();
    if(iconValue && iconValue.startsWith('data:image/') && !validImage(iconValue))return json(res,400,{error:'Иконка должна быть корректным PNG, JPG или WebP'});
    if(iconValue.length>2_500_000)return json(res,400,{error:'Файл иконки слишком большой'});
    const icon=iconValue||old.icon;
    db.prepare('UPDATE stages SET title=?,subtitle=?,icon=?,accent=?,sort_order=? WHERE id=?').run(clean(b.title,120),clean(b.subtitle,240),icon,clean(b.accent,30)||old.accent,Number(b.sort_order)||old.sort_order,id);
    audit(u.id,'edit_stamp_definition',null,JSON.stringify({stage_id:id})); return json(res,200,{ok:true});
  }
  if(url==='/api/admin/stamp/edit'&&req.method==='PATCH'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return;
    const b=await body(req),id=Number(b.id),old=db.prepare('SELECT * FROM stamps WHERE id=?').get(id); if(!old)return json(res,404,{error:'Штамп участника не найден'});
    const sid=Number(b.stage_id||old.stage_id); if(!db.prepare('SELECT id FROM stages WHERE id=?').get(sid))return json(res,400,{error:'Некорректный этап'});
    db.prepare('UPDATE stamps SET stage_id=?,note=? WHERE id=?').run(sid,clean(b.note,1000),id); audit(u.id,'edit_stamp',old.user_id,JSON.stringify({stamp_id:id,stage_id:sid})); return json(res,200,{ok:true});
  }
  if(url==='/api/admin/missions'&&req.method==='GET'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return;
    return json(res,200,{missions:db.prepare('SELECT m.*,s.title stage_title FROM missions m JOIN stages s ON s.id=m.stage_id ORDER BY m.sort_order,m.id').all()});
  }
  if(url==='/api/admin/missions'&&req.method==='POST'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const b=await body(req);
    if(!clean(b.title,200)||!clean(b.description,3000)||!b.stage_id||!b.date_from||!b.date_to)return json(res,400,{error:'Заполните название, описание, этап и даты'});
    const r=db.prepare('INSERT INTO missions(stage_id,title,description,date_from,date_to,sort_order) VALUES(?,?,?,?,?,?)').run(Number(b.stage_id),clean(b.title,200),clean(b.description,3000),clean(b.date_from,20),clean(b.date_to,20),Number(b.sort_order)||0);
    audit(u.id,'create_mission',null,JSON.stringify({mission_id:Number(r.lastInsertRowid)})); return json(res,201,{ok:true,id:Number(r.lastInsertRowid)});
  }
  if(url.startsWith('/api/admin/missions/')&&req.method==='PATCH'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const id=Number(url.split('/').pop()),old=db.prepare('SELECT * FROM missions WHERE id=?').get(id); if(!old)return json(res,404,{error:'Миссия не найдена'}); const b=await body(req);
    db.prepare('UPDATE missions SET stage_id=?,title=?,description=?,date_from=?,date_to=?,sort_order=? WHERE id=?').run(Number(b.stage_id||old.stage_id),clean(b.title,200)||old.title,clean(b.description,3000)||old.description,clean(b.date_from,20)||old.date_from,clean(b.date_to,20)||old.date_to,Number(b.sort_order)||old.sort_order,id);
    audit(u.id,'edit_mission',null,JSON.stringify({mission_id:id})); return json(res,200,{ok:true});
  }
  if(url==='/api/admin/users'&&req.method==='GET'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; return json(res,200,{admins:db.prepare(`SELECT id,username,name,role,group_name,squad,phone,email,avatar,status,created_at FROM users WHERE role IN ('admin','superadmin') ORDER BY role DESC,name`).all()});
  }
  if(url==='/api/admin/users'&&req.method==='POST'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const b=await body(req),role=['admin','candidate'].includes(b.role)?b.role:null;
    if(!role||!b.username||!b.password||!b.name)return json(res,400,{error:'Заполните обязательные поля'}); if(!validImage(b.avatar))return json(res,400,{error:'Фото имеет неверный формат или слишком большое'});
    try{const r=db.prepare('INSERT INTO users(username,password_hash,role,name,group_name,squad,phone,email,avatar) VALUES(?,?,?,?,?,?,?,?,?)').run(clean(b.username,100),hashPassword(String(b.password)),role,clean(b.name,120),clean(b.group_name,120),clean(b.squad,120),clean(b.phone,80),clean(b.email,160),b.avatar||''); audit(u.id,'create_user',Number(r.lastInsertRowid),JSON.stringify({role})); return json(res,201,{ok:true,id:Number(r.lastInsertRowid)})}catch(e){return json(res,400,{error:'Такой логин уже существует'})}
  }
  if(url.startsWith('/api/admin/promote/')&&req.method==='POST'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const id=Number(url.split('/').pop()),target=db.prepare('SELECT id,role FROM users WHERE id=?').get(id); if(!target)return json(res,404,{error:'Пользователь не найден'});
    if(target.role==='superadmin')return json(res,403,{error:'Главного администратора нельзя изменить через эту панель'}); if(u.role!=='superadmin'&&target.role==='admin')return json(res,403,{error:'Только главный администратор может менять права администратора'});
    const b=await body(req),role=b.role==='admin'?'admin':'candidate'; db.prepare('UPDATE users SET role=? WHERE id=?').run(role,id); audit(u.id,'change_role',id,JSON.stringify({role})); return json(res,200,{ok:true});
  }
  if(url==='/api/admin/events'&&req.method==='GET'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const rows=db.prepare(`SELECT e.*,st.title stage_title,(SELECT COUNT(*) FROM event_registrations r WHERE r.event_id=e.id) registrations FROM events e LEFT JOIN stages st ON st.id=e.stage_id ORDER BY e.event_date,e.time_start`).all(); return json(res,200,{events:rows});
  }
  if(url.startsWith('/api/admin/event/')&&req.method==='GET'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const id=Number(url.split('/').pop()),e=eventView(id); if(!e)return json(res,404,{error:'Событие не найдено'});
    e.registrants=db.prepare(`SELECT u.id,u.name,u.username,u.group_name,u.squad,u.phone,u.email,er.status,er.created_at FROM event_registrations er JOIN users u ON u.id=er.user_id WHERE er.event_id=? ORDER BY er.created_at,u.name`).all(id);
    return json(res,200,{event:e});
  }
  if(url==='/api/admin/events'&&req.method==='POST'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const b=await body(req); if(!b.title||!b.event_date)return json(res,400,{error:'Название и дата обязательны'});
    const r=db.prepare('INSERT INTO events(title,stage_id,event_date,time_start,time_end,location,description,program,organizer,contact,materials,type,sort_order) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').run(clean(b.title,200),Number(b.stage_id)||null,clean(b.event_date,20),clean(b.time_start,10),clean(b.time_end,10),clean(b.location,200),clean(b.description,3000),clean(b.program,5000),clean(b.organizer,200),clean(b.contact,500),clean(b.materials,2000),clean(b.type,80)||'ШМБ',Number(b.sort_order)||0);
    audit(u.id,'create_event',null,JSON.stringify({event_id:Number(r.lastInsertRowid)})); return json(res,201,{ok:true,id:Number(r.lastInsertRowid)});
  }
  if(url.startsWith('/api/admin/event/')&&req.method==='PUT'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const id=Number(url.split('/').pop()); if(!db.prepare('SELECT id FROM events WHERE id=?').get(id))return json(res,404,{error:'Событие не найдено'}); const b=await body(req); if(!b.title||!b.event_date)return json(res,400,{error:'Название и дата обязательны'});
    db.prepare('UPDATE events SET title=?,stage_id=?,event_date=?,time_start=?,time_end=?,location=?,description=?,program=?,organizer=?,contact=?,materials=?,type=?,sort_order=? WHERE id=?').run(clean(b.title,200),Number(b.stage_id)||null,clean(b.event_date,20),clean(b.time_start,10),clean(b.time_end,10),clean(b.location,200),clean(b.description,3000),clean(b.program,5000),clean(b.organizer,200),clean(b.contact,500),clean(b.materials,2000),clean(b.type,80)||'ШМБ',Number(b.sort_order)||0,id);
    audit(u.id,'edit_event',null,JSON.stringify({event_id:id})); return json(res,200,{ok:true});
  }
  if(url.startsWith('/api/admin/event-materials/')&&req.method==='DELETE'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const id=Number(url.split('/').pop()),m=db.prepare('SELECT * FROM event_materials WHERE id=?').get(id);
    if(!m)return json(res,404,{error:'Материал не найден'}); db.prepare('DELETE FROM event_materials WHERE id=?').run(id); audit(u.id,'delete_event_material',null,JSON.stringify({material_id:id,event_id:m.event_id})); return json(res,200,{ok:true});
  }
  if(url==='/api/admin/event-materials'&&req.method==='POST'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const b=await body(req),eventId=Number(b.event_id),size=Number(b.size),mime=clean(b.mime,160),name=clean(b.name,180),data=String(b.data||'');
    if(!db.prepare('SELECT id FROM events WHERE id=?').get(eventId))return json(res,404,{error:'Событие не найдено'});
    if(!name||!validMaterial(data,mime,size))return json(res,400,{error:'Файл не поддерживается или превышает 20 МБ'});
    const count=db.prepare('SELECT COUNT(*) n FROM event_materials WHERE event_id=?').get(eventId).n; if(count>=10)return json(res,400,{error:'К событию можно прикрепить не более 10 материалов'});
    const r=db.prepare('INSERT INTO event_materials(event_id,name,mime,size,data) VALUES(?,?,?,?,?)').run(eventId,name,mime,size,data); audit(u.id,'add_event_material',null,JSON.stringify({material_id:Number(r.lastInsertRowid),event_id:eventId,name})); return json(res,201,{ok:true,id:Number(r.lastInsertRowid)});
  }
  if(url==='/api/admin/mission-submissions'&&req.method==='GET'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; const q=new URL(req.url,'http://x').searchParams.get('q')||'';
    const rows=db.prepare(`SELECT mp.id,mp.user_id,mp.mission_id,mp.proof,mp.proof_image,mp.completed_at,u.name user_name,u.group_name,u.squad,m.title mission_title,s.title stage_title FROM mission_progress mp JOIN users u ON u.id=mp.user_id JOIN missions m ON m.id=mp.mission_id JOIN stages s ON s.id=m.stage_id WHERE mp.completed=1 AND mp.proof_image<>'' AND (u.name LIKE ? OR m.title LIKE ? OR u.squad LIKE ?) ORDER BY mp.completed_at DESC,mp.id DESC`).all(`%${q}%`,`%${q}%`,`%${q}%`);
    return json(res,200,{submissions:rows});
  }
  if(url==='/api/admin/audit'&&req.method==='GET'){
    const u=requireAuth(req,res,['superadmin','admin']); if(!u)return; return json(res,200,{logs:db.prepare(`SELECT l.*,a.name admin_name,t.name target_name FROM audit_log l JOIN users a ON a.id=l.admin_id LEFT JOIN users t ON t.id=l.target_user_id ORDER BY l.id DESC LIMIT 150`).all()});
  }
  return json(res,404,{error:'Not found'});
}

const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp','.ico':'image/x-icon'};
const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url,`http://${req.headers.host}`).pathname;
  try{
    if(url==='/health') return json(res,200,{ok:true,status:'healthy'});
    if(url.startsWith('/api/')) return await api(req,res,url);
    if(url.startsWith('/profile/')){
      const id=Number(url.split('/').pop()),v=userView(id); if(!v)return send(res,404,'Профиль не найден'); const pct=Math.round(v.progress/v.totalStages*100);
      const escHtml=s=>String(s??'').replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
      const iconHtml=s=>String(s||'✦').startsWith('data:image/')?`<img src="${escHtml(s)}" class="stage-icon-img" alt="">`:escHtml(s||'✦');
      return send(res,200,`<!doctype html><html lang="ru"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Профиль ${escHtml(v.name)}</title><style>body{margin:0;background:#0d1714;color:#fff;font-family:system-ui;padding:28px}.card{max-width:560px;margin:30px auto;background:#fffaf0;color:#173f34;border-radius:24px;padding:28px}.mark{font-weight:900;letter-spacing:.08em}.public-logo{width:220px;max-width:100%;height:auto;margin-bottom:20px}.tag{display:inline-block;background:#e4eee3;padding:6px 9px;border-radius:99px;font-size:11px;font-weight:800;margin-top:20px}.photo{width:84px;height:84px;border-radius:50%;object-fit:cover;background:#dbe6da;display:block;margin-top:20px}h1{font-size:42px;line-height:1;margin:12px 0}.muted{color:#718078}.bar{height:10px;background:#ded9ca;border-radius:10px;overflow:hidden}.bar i{display:block;height:100%;width:${pct}%;background:#f2c51b}.stamps{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:20px}.s{padding:14px 8px;border-radius:14px;background:#edf5ed;text-align:center;font-size:12px}.s.off{opacity:.45;background:#f0ede4}@media(max-width:500px){h1{font-size:34px}.stamps{grid-template-columns:repeat(2,1fr)}}</style><body><main class="card"><img class="public-logo" src="/logo-rosbiotech.svg" alt="РОСБИОТЕХ">${v.avatar?`<img class="photo" src="${v.avatar}" alt="Фото ${escHtml(v.name)}">`:''}<span class="tag">ЦИФРОВОЙ ПРОФИЛЬ КАНДИДАТА</span><h1>${escHtml(v.name)}</h1><p class="muted">${escHtml(v.group_name||'')} ${v.squad?'· '+escHtml(v.squad):''}</p><p><b>Путь бойца</b> · ${v.progress}/${v.totalStages}</p><div class="bar"><i></i></div><div class="stamps">${Array.from({length:6},(_,i)=>{const s=v.stamps.find(s=>s.stage_id===i+1);return `<div class="s ${s?'':'off'}">${s?iconHtml(s.icon):'✦'}<br><b>${s?s.title:'Этап '+(i+1)}</b><br>${s?'пройдено':'ожидает'}</div>`}).join('')}</div></main></body></html>`,{'Content-Type':'text/html; charset=utf-8'});
    }
    const file=url==='/'?'/index.html':url; const fp=path.normalize(path.join(PUBLIC,file)); if(!fp.startsWith(PUBLIC))return send(res,403,'Forbidden'); if(fs.existsSync(fp)&&fs.statSync(fp).isFile())return send(res,200,fs.readFileSync(fp),{'Content-Type':mime[path.extname(fp)]||'application/octet-stream'}); return send(res,404,'Not found');
  }catch(e){console.error(e);return json(res,500,{error:'Ошибка сервера'});}
});
server.listen(PORT, '0.0.0.0', ()=>console.log(`SMB Passport running on port ${PORT}`));

function shutdown(signal) {
  console.log(`${signal} received, shutting down...`);
  server.close(() => {
    try { db.close(); } catch {}
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
