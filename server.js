require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'dulzstrm@gmail.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '768903';
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_TO_A_LONG_RANDOM_SECRET';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

if (JWT_SECRET === 'CHANGE_THIS_TO_A_LONG_RANDOM_SECRET') {
  console.warn('WARNING: set a strong JWT_SECRET in .env before production.');
}

app.use(cors({
  origin: ALLOWED_ORIGIN === '*' ? true : ALLOWED_ORIGIN,
  methods: ['GET','POST'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json({limit:'64kb'}));

const db = new Database(process.env.DB_PATH || 'visitors.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS visitors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  visitor_id TEXT NOT NULL UNIQUE,
  device TEXT,
  browser TEXT,
  platform TEXT,
  language TEXT,
  screen TEXT,
  user_agent TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_visitors_last_seen ON visitors(last_seen);
`);

function clean(v, max=500){
  return String(v ?? '').slice(0,max);
}

function auth(req,res,next){
  const h=req.headers.authorization||'';
  const token=h.startsWith('Bearer ')?h.slice(7):'';
  try{
    req.admin=jwt.verify(token,JWT_SECRET);
    next();
  }catch{
    res.status(401).json({error:'Unauthorized'});
  }
}

app.get('/api/health',(req,res)=>res.json({ok:true}));

app.post('/api/admin/login', async (req,res)=>{
  const email=clean(req.body?.email,200).trim();
  const password=String(req.body?.password||'');
  if(email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD){
    return res.status(401).json({error:'Email atau password salah.'});
  }
  const token=jwt.sign({role:'admin',email},JWT_SECRET,{expiresIn:'8h'});
  res.json({token});
});

app.post('/api/visitor',(req,res)=>{
  const now=new Date().toISOString();
  const visitor_id=clean(req.body?.id,100);
  if(!visitor_id) return res.status(400).json({error:'visitor id required'});

  const device=clean(req.body?.device,100);
  const browser=clean(req.body?.browser,100);
  const platform=clean(req.body?.platform,150);
  const language=clean(req.body?.language,50);
  const screen=clean(req.body?.screen,50);
  const user_agent=clean(req.body?.userAgent,1000);

  const existing=db.prepare('SELECT visitor_id FROM visitors WHERE visitor_id=?').get(visitor_id);
  if(existing){
    db.prepare(`UPDATE visitors SET device=?,browser=?,platform=?,language=?,screen=?,user_agent=?,last_seen=? WHERE visitor_id=?`)
      .run(device,browser,platform,language,screen,user_agent,now,visitor_id);
  }else{
    db.prepare(`INSERT INTO visitors(visitor_id,device,browser,platform,language,screen,user_agent,first_seen,last_seen)
                VALUES(?,?,?,?,?,?,?,?,?)`)
      .run(visitor_id,device,browser,platform,language,screen,user_agent,now,now);
  }
  res.json({ok:true});
});

app.get('/api/admin/devices',auth,(req,res)=>{
  const devices=db.prepare(`
    SELECT visitor_id,device,browser,platform,language,screen,first_seen,last_seen
    FROM visitors ORDER BY last_seen DESC LIMIT 500
  `).all();
  res.json({devices});
});

app.listen(PORT,()=>console.log(`Backend running on port ${PORT}`));
