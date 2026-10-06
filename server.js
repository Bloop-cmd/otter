const express=require('express');
const http=require('http');
const path=require('path');
const crypto=require('crypto');
const bcrypt=require('bcryptjs');
const {Pool}=require('pg');
const session=require('express-session');
const PgSession=require('connect-pg-simple')(session);
const {WebSocketServer}=require('ws');

const app=express();
const server=http.createServer(app);
const wss=new WebSocketServer({noServer:true});
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.NODE_ENV==='production'?{rejectUnauthorized:false}:false,max:10});
const isProd=process.env.NODE_ENV==='production';
const SESSION_SECRET=process.env.SESSION_SECRET;
if(!SESSION_SECRET) console.warn('SESSION_SECRET is not set; generate one before production.');
const sessionParser=session({
  store:new PgSession({pool,tableName:'user_sessions',createTableIfMissing:true}),
  secret:SESSION_SECRET||'development-only-change-me',
  resave:false,
  saveUninitialized:false,
  rolling:true,
  cookie:{httpOnly:true,sameSite:'lax',secure:isProd,maxAge:1000*60*60*24*14}
});
app.set('trust proxy',1);
app.use(express.json({limit:'32kb'}));
app.use(express.urlencoded({extended:false}));
app.use(sessionParser);
app.use(express.static(path.join(__dirname)));

const safe=(s,n=2000)=>String(s??'').slice(0,n).trim();
const uuid=()=>crypto.randomUUID();
function requireAuth(req,res,next){if(!req.session.userId)return res.status(401).json({error:'AUTH_REQUIRED'});next()}
function baseUrl(req){return process.env.APP_URL||`${req.protocol}://${req.get('host')}`}
function randomState(){return crypto.randomBytes(24).toString('hex')}

async function init(){
  if(!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  await pool.query(`CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY,email TEXT UNIQUE,password_hash TEXT,name TEXT NOT NULL,avatar TEXT,provider TEXT NOT NULL DEFAULT 'email',provider_id TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS users_provider_identity_idx ON users(provider, provider_id) WHERE provider_id IS NOT NULL;`);
  await pool.query(`CREATE TABLE IF NOT EXISTS rooms (id UUID PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL DEFAULT 'direct',created_by UUID REFERENCES users(id) ON DELETE SET NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE TABLE IF NOT EXISTS room_members (room_id UUID REFERENCES rooms(id) ON DELETE CASCADE,user_id UUID REFERENCES users(id) ON DELETE CASCADE,joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),PRIMARY KEY(room_id,user_id));`);
  await pool.query(`CREATE TABLE IF NOT EXISTS messages (id UUID PRIMARY KEY,room_id UUID REFERENCES rooms(id) ON DELETE CASCADE,user_id UUID REFERENCES users(id) ON DELETE SET NULL,text TEXT NOT NULL,under BOOLEAN NOT NULL DEFAULT FALSE,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE INDEX IF NOT EXISTS messages_room_created_idx ON messages(room_id,created_at DESC);`);
  await pool.query(`CREATE TABLE IF NOT EXISTS statuses (id UUID PRIMARY KEY,user_id UUID REFERENCES users(id) ON DELETE CASCADE,symbol TEXT,text TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE INDEX IF NOT EXISTS statuses_created_idx ON statuses(created_at DESC);`);
  await pool.query(`CREATE TABLE IF NOT EXISTS groups_meta (id UUID PRIMARY KEY,room_id UUID UNIQUE REFERENCES rooms(id) ON DELETE CASCADE,icon TEXT NOT NULL DEFAULT '◇',created_by UUID REFERENCES users(id) ON DELETE SET NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
}

app.get('/health',async(req,res)=>{try{await pool.query('SELECT 1');res.json({ok:true,service:'otti',database:'ok'});}catch(e){res.status(503).json({ok:false,database:'down'});}});
app.get('/api/me',async(req,res)=>{if(!req.session.userId)return res.json({user:null});const r=await pool.query('SELECT id,email,name,avatar,provider FROM users WHERE id=$1',[req.session.userId]);if(!r.rowCount){req.session.destroy(()=>{});return res.json({user:null});}res.json({user:r.rows[0]});});
app.post('/api/auth/email',async(req,res)=>{try{const email=safe(req.body.email,320).toLowerCase();const password=String(req.body.password||'');const mode=req.body.mode==='signup'?'signup':'signin';if(!/^\S+@\S+\.\S+$/.test(email)||password.length<8)return res.status(400).json({error:'Use a valid email and a password of at least 8 characters.'});let r=await pool.query('SELECT * FROM users WHERE email=$1',[email]);let user=r.rows[0];if(mode==='signup'){if(user)return res.status(409).json({error:'An account already exists for this email.'});const hash=await bcrypt.hash(password,12);user={id:uuid(),email,password_hash:hash,name:email.split('@')[0].slice(0,40),avatar:null,provider:'email'};await pool.query('INSERT INTO users(id,email,password_hash,name,provider) VALUES($1,$2,$3,$4,$5)',[user.id,user.email,user.password_hash,user.name,user.provider]);}else{if(!user||!user.password_hash||!(await bcrypt.compare(password,user.password_hash)))return res.status(401).json({error:'Email or password is incorrect.'});}req.session.regenerate(err=>{if(err)return res.status(500).json({error:'SESSION_ERROR'});req.session.userId=user.id;req.session.save(()=>res.json({user:{id:user.id,email:user.email,name:user.name,provider:user.provider}}));});}catch(e){console.error(e);res.status(500).json({error:'AUTH_ERROR'});}});
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>{res.clearCookie('connect.sid');res.json({ok:true})}));

app.get('/auth/google', (req,res)=>{if(!process.env.GOOGLE_CLIENT_ID||!process.env.GOOGLE_CLIENT_SECRET)return res.status(503).send('Google OAuth is not configured.');req.session.oauthState=randomState();const redirect=encodeURIComponent(`${baseUrl(req)}/auth/google/callback`);const scope=encodeURIComponent('openid email profile');res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?client_id=${encodeURIComponent(process.env.GOOGLE_CLIENT_ID)}&redirect_uri=${redirect}&response_type=code&scope=${scope}&state=${req.session.oauthState}&access_type=online&prompt=select_account`)});
app.get('/auth/google/callback',async(req,res)=>{try{if(!req.query.code||req.query.state!==req.session.oauthState)return res.status(400).send('Invalid OAuth state.');delete req.session.oauthState;const redirect=`${baseUrl(req)}/auth/google/callback`;const token=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({code:req.query.code,client_id:process.env.GOOGLE_CLIENT_ID,client_secret:process.env.GOOGLE_CLIENT_SECRET,redirect_uri:redirect,grant_type:'authorization_code'})}).then(r=>r.json());if(!token.access_token)return res.status(401).send('Google authorization failed.');const info=await fetch('https://openidconnect.googleapis.com/v1/userinfo',{headers:{authorization:`Bearer ${token.access_token}`}}).then(r=>r.json());const user=await upsertOAuth('google',info.sub,info.email,info.name||info.email?.split('@')[0]||'Otti User',info.picture);await loginSession(req,user.id);res.redirect('/');}catch(e){console.error(e);res.status(500).send('Google sign-in failed.');}});

app.get('/auth/github',(req,res)=>{if(!process.env.GITHUB_CLIENT_ID||!process.env.GITHUB_CLIENT_SECRET)return res.status(503).send('GitHub OAuth is not configured.');req.session.oauthState=randomState();const redirect=encodeURIComponent(`${baseUrl(req)}/auth/github/callback`);res.redirect(`https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(process.env.GITHUB_CLIENT_ID)}&redirect_uri=${redirect}&scope=${encodeURIComponent('read:user user:email')}&state=${req.session.oauthState}`)});
app.get('/auth/github/callback',async(req,res)=>{try{if(!req.query.code||req.query.state!==req.session.oauthState)return res.status(400).send('Invalid OAuth state.');delete req.session.oauthState;const redirect=`${baseUrl(req)}/auth/github/callback`;const token=await fetch('https://github.com/login/oauth/access_token',{method:'POST',headers:{accept:'application/json','content-type':'application/json'},body:JSON.stringify({client_id:process.env.GITHUB_CLIENT_ID,client_secret:process.env.GITHUB_CLIENT_SECRET,code:req.query.code,redirect_uri:redirect})}).then(r=>r.json());if(!token.access_token)return res.status(401).send('GitHub authorization failed.');const headers={authorization:`Bearer ${token.access_token}`,accept:'application/vnd.github+json','user-agent':'otti-live'};const profile=await fetch('https://api.github.com/user',{headers}).then(r=>r.json());const emails=await fetch('https://api.github.com/user/emails',{headers}).then(r=>r.json());const primary=(Array.isArray(emails)?emails.find(x=>x.primary&&x.verified):null)||emails?.find?.(x=>x.verified);if(!primary?.email)return res.status(400).send('A verified GitHub email is required.');const user=await upsertOAuth('github',String(profile.id),primary.email,profile.name||profile.login||'Otti User',profile.avatar_url);await loginSession(req,user.id);res.redirect('/');}catch(e){console.error(e);res.status(500).send('GitHub sign-in failed.');}});

async function upsertOAuth(provider,providerId,email,name,avatar){let r=await pool.query('SELECT * FROM users WHERE provider=$1 AND provider_id=$2',[provider,providerId]);if(r.rowCount)return r.rows[0];r=await pool.query('SELECT * FROM users WHERE email=$1',[email.toLowerCase()]);if(r.rowCount){const u=r.rows[0];await pool.query('UPDATE users SET provider=$1,provider_id=$2,avatar=COALESCE($3,avatar),updated_at=NOW() WHERE id=$4',[provider,providerId,avatar,u.id]);return {...u,provider,provider_id:providerId,avatar:avatar||u.avatar};}const u={id:uuid(),email:email.toLowerCase(),name:safe(name,80)||'Otti User',avatar:avatar||null,provider,provider_id:providerId};await pool.query('INSERT INTO users(id,email,name,avatar,provider,provider_id) VALUES($1,$2,$3,$4,$5,$6)',[u.id,u.email,u.name,u.avatar,u.provider,u.provider_id]);return u;}
function loginSession(req,userId){return new Promise((resolve,reject)=>req.session.regenerate(err=>{if(err)return reject(err);req.session.userId=userId;req.session.save(err2=>err2?reject(err2):resolve());}));}

app.post('/api/bootstrap',requireAuth,async(req,res)=>{try{let r=await pool.query("SELECT r.id FROM rooms r WHERE r.kind='lobby' AND r.name='Otti' LIMIT 1");let roomId;if(!r.rowCount){roomId=uuid();await pool.query('INSERT INTO rooms(id,name,kind,created_by) VALUES($1,$2,$3,$4)',[roomId,'Otti','lobby',req.session.userId]);}else roomId=r.rows[0].id;await pool.query('INSERT INTO room_members(room_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[roomId,req.session.userId]);res.json({ok:true,roomId});}catch(e){console.error(e);res.status(500).json({error:'BOOTSTRAP_ERROR'});}});

app.get('/api/statuses',requireAuth,async(req,res)=>{const r=await pool.query(`SELECT s.id,s.symbol,s.text,s.created_at,u.id user_id,u.name,u.email FROM statuses s JOIN users u ON u.id=s.user_id WHERE s.created_at>NOW()-INTERVAL '24 hours' ORDER BY s.created_at DESC LIMIT 100`);res.json({statuses:r.rows});});
app.post('/api/statuses',requireAuth,async(req,res)=>{const text=safe(req.body.text,300);if(!text)return res.status(400).json({error:'Status is required'});const s={id:uuid(),symbol:safe(req.body.symbol,8)||'✦',text};await pool.query('INSERT INTO statuses(id,user_id,symbol,text) VALUES($1,$2,$3,$4)',[s.id,req.session.userId,s.symbol,s.text]);res.json({status:s});});
app.get('/api/rooms',requireAuth,async(req,res)=>{const r=await pool.query(`SELECT r.id,r.name,r.kind,r.created_at,gm.icon FROM rooms r JOIN room_members rm ON rm.room_id=r.id LEFT JOIN groups_meta gm ON gm.room_id=r.id WHERE rm.user_id=$1 ORDER BY r.created_at DESC`,[req.session.userId]);res.json({rooms:r.rows});});
app.post('/api/groups',requireAuth,async(req,res)=>{const client=await pool.connect();try{await client.query('BEGIN');const roomId=uuid(),groupId=uuid();const name=safe(req.body.name,80)||'New Otti Circle',icon=safe(req.body.icon,8)||'◇';await client.query('INSERT INTO rooms(id,name,kind,created_by) VALUES($1,$2,$3,$4)',[roomId,name,'group',req.session.userId]);await client.query('INSERT INTO room_members(room_id,user_id) VALUES($1,$2)',[roomId,req.session.userId]);await client.query('INSERT INTO groups_meta(id,room_id,icon,created_by) VALUES($1,$2,$3,$4)',[groupId,roomId,icon,req.session.userId]);await client.query('COMMIT');res.json({room:{id:roomId,name,kind:'group',icon}});}catch(e){await client.query('ROLLBACK');res.status(500).json({error:'GROUP_ERROR'});}finally{client.release();}});
app.get('/api/rooms/:roomId/messages',requireAuth,async(req,res)=>{const access=await pool.query('SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2',[req.params.roomId,req.session.userId]);if(!access.rowCount)return res.status(403).json({error:'FORBIDDEN'});const r=await pool.query(`SELECT m.id,m.text,m.under,m.created_at,u.id user_id,u.name FROM messages m LEFT JOIN users u ON u.id=m.user_id WHERE m.room_id=$1 ORDER BY m.created_at ASC LIMIT 200`,[req.params.roomId]);res.json({messages:r.rows});});

const wsTokens=new Map();
app.post('/api/ws-token',requireAuth,(req,res)=>{const token=crypto.randomBytes(32).toString('hex');wsTokens.set(token,{userId:req.session.userId,expires:Date.now()+60000});res.json({token});});
setInterval(()=>{const now=Date.now();for(const [k,v] of wsTokens)if(v.expires<now)wsTokens.delete(k);},30000).unref();

const roomSockets=new Map();
function joinSocket(roomId,ws){if(!roomSockets.has(roomId))roomSockets.set(roomId,new Set());roomSockets.get(roomId).add(ws);}
function leaveSocket(roomId,ws){roomSockets.get(roomId)?.delete(ws);}
function broadcast(roomId,payload,except){for(const ws of roomSockets.get(roomId)||[]){if(ws!==except&&ws.readyState===1)ws.send(JSON.stringify(payload));}}
async function socketAuthorized(token){const x=wsTokens.get(token);if(!x||x.expires<Date.now())return null;wsTokens.delete(token);const r=await pool.query('SELECT id,name FROM users WHERE id=$1',[x.userId]);return r.rows[0]||null;}
server.on('upgrade',(req,socket,head)=>{if(req.url.startsWith('/ws')){const u=new URL(req.url,`http://${req.headers.host}`);socket.wsToken=u.searchParams.get('token');wss.handleUpgrade(req,socket,head,ws=>wss.emit('connection',ws,req));}else socket.destroy();});
wss.on('connection',async(ws,req)=>{const user=await socketAuthorized(req.socket.wsToken);if(!user){ws.close(1008,'unauthorized');return;}ws.user=user;ws.roomId=null;ws.on('message',async raw=>{try{const m=JSON.parse(raw);if(m.type==='join'){const roomId=safe(m.room,80);const access=await pool.query('SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2',[roomId,user.id]);if(!access.rowCount){ws.send(JSON.stringify({type:'error',error:'FORBIDDEN'}));return;}if(ws.roomId)leaveSocket(ws.roomId,ws);ws.roomId=roomId;joinSocket(roomId,ws);const history=await pool.query(`SELECT m.id,m.text,m.under,m.created_at,u.id user_id,u.name FROM messages m LEFT JOIN users u ON u.id=m.user_id WHERE m.room_id=$1 ORDER BY m.created_at DESC LIMIT 200`,[roomId]);ws.send(JSON.stringify({type:'room-state',room:roomId,messages:history.rows.reverse()}));broadcast(roomId,{type:'presence',user:user.name,count:roomSockets.get(roomId).size});return;}
if(!ws.roomId)return;
if(m.type==='message'){const text=safe(m.text);if(!text)return;const id=uuid();await pool.query('INSERT INTO messages(id,room_id,user_id,text,under) VALUES($1,$2,$3,$4,$5)',[id,ws.roomId,user.id,text,!!m.under]);const item={id,text,under:!!m.under,created_at:new Date().toISOString(),user_id:user.id,name:user.name};broadcast(ws.roomId,{type:'message',room:ws.roomId,...item});return;}
if(m.type==='dive'||m.type==='return'||m.type==='typing'){broadcast(ws.roomId,{type:m.type,room:ws.roomId,user:user.name});return;}
if(m.type==='react'){broadcast(ws.roomId,{type:'react',room:ws.roomId,user:user.name,messageId:safe(m.messageId,100),reaction:safe(m.reaction,8)});return;}
}catch(e){console.error('ws',e)}});ws.on('close',()=>{if(ws.roomId){const room=ws.roomId;leaveSocket(room,ws);broadcast(room,{type:'presence',user:user.name,count:roomSockets.get(room)?.size||0});}});
});

app.get('*',(req,res)=>{if(req.path.startsWith('/api/')||req.path.startsWith('/auth/'))return res.status(404).end();res.sendFile(path.join(__dirname,'index.html'));});

init().then(()=>server.listen(process.env.PORT||10000,'0.0.0.0',()=>console.log('OTTI V2 listening'))).catch(e=>{console.error(e);process.exit(1)});
