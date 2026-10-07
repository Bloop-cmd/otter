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
const wss=new WebSocketServer({noServer:true,perMessageDeflate:false});

const pool=new Pool({
  connectionString:process.env.DATABASE_URL,
  ssl:process.env.NODE_ENV==='production'?{rejectUnauthorized:false}:false,
  max:10
});

const isProd=process.env.NODE_ENV==='production';
const SESSION_SECRET=process.env.SESSION_SECRET;
const sessionParser=session({
  store:new PgSession({pool,tableName:'user_sessions',createTableIfMissing:true}),
  secret:SESSION_SECRET||'development-only-change-me',
  resave:false,saveUninitialized:false,rolling:true,
  cookie:{httpOnly:true,sameSite:'lax',secure:isProd,maxAge:1000*60*60*24*14}
});

app.set('trust proxy',1);
app.use(express.json({limit:'32kb'}));
app.use(express.urlencoded({extended:false}));
app.use(sessionParser);
app.use(express.static(path.join(__dirname)));

const safe=(s,n=2000)=>String(s??'').slice(0,n).trim();
const uuid=()=>crypto.randomUUID();

function requireAuth(req,res,next){
  if(!req.session.userId)return res.status(401).json({error:'AUTH_REQUIRED'});
  next();
}
function baseUrl(req){return process.env.APP_URL||`${req.protocol}://${req.get('host')}`}
function randomState(){return crypto.randomBytes(24).toString('hex')}

async function init(){
  if(!process.env.DATABASE_URL)throw new Error('DATABASE_URL is required');
  for(const table of ['users','rooms','room_members','messages','contacts','groups_meta','statuses'])
    await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
  await pool.query(`CREATE TABLE IF NOT EXISTS user_room_clears (user_id uuid NOT NULL, room_id uuid NOT NULL, cleared_at timestamptz NOT NULL DEFAULT NOW(), PRIMARY KEY(user_id,room_id))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS user_room_reads (user_id uuid NOT NULL, room_id uuid NOT NULL, last_read_at timestamptz NOT NULL DEFAULT NOW(), PRIMARY KEY(user_id,room_id))`);
  await pool.query(`INSERT INTO user_room_reads(user_id,room_id,last_read_at) SELECT user_id,room_id,NOW() FROM room_members ON CONFLICT DO NOTHING`);
}

app.get('/health',async(req,res)=>{
  try{await pool.query('SELECT 1');res.json({ok:true,service:'otti',database:'ok'})}
  catch(e){res.status(503).json({ok:false,database:'down'})}
});

app.get('/api/me',async(req,res)=>{
  if(!req.session.userId)return res.json({user:null});
  const r=await pool.query('SELECT id,email,name,avatar,provider FROM users WHERE id=$1',[req.session.userId]);
  if(!r.rowCount){req.session.destroy(()=>{});return res.json({user:null})}
  res.json({user:r.rows[0]});
});

app.post('/api/auth/email',async(req,res)=>{
  try{
    const email=safe(req.body.email,320).toLowerCase();
    const password=String(req.body.password||'');
    const mode=req.body.mode==='signup'?'signup':'signin';
    if(!/^\S+@\S+\.\S+$/.test(email)||password.length<8)
      return res.status(400).json({error:'Use a valid email and a password of at least 8 characters.'});

    let r=await pool.query('SELECT * FROM users WHERE email=$1',[email]);
    let user=r.rows[0];

    if(mode==='signup'){
      if(user)return res.status(409).json({error:'An account already exists for this email.'});
      user={id:uuid(),email,password_hash:await bcrypt.hash(password,12),name:email.split('@')[0].slice(0,40),avatar:null,provider:'email'};
      await pool.query('INSERT INTO users(id,email,password_hash,name,provider) VALUES($1,$2,$3,$4,$5)',[user.id,user.email,user.password_hash,user.name,user.provider]);
    }else{
      if(!user||!user.password_hash||!(await bcrypt.compare(password,user.password_hash)))
        return res.status(401).json({error:'Email or password is incorrect.'});
    }

    req.session.regenerate(err=>{
      if(err)return res.status(500).json({error:'SESSION_ERROR'});
      req.session.userId=user.id;
      req.session.save(()=>res.json({user:{id:user.id,email:user.email,name:user.name,provider:user.provider}}));
    });
  }catch(e){console.error(e);res.status(500).json({error:'AUTH_ERROR'})}
});

app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>{res.clearCookie('connect.sid');res.json({ok:true})}));

app.get('/auth/google',(req,res)=>{
  if(!process.env.GOOGLE_CLIENT_ID||!process.env.GOOGLE_CLIENT_SECRET)return res.status(503).send('Google OAuth is not configured.');
  req.session.oauthState=randomState();
  const redirect=encodeURIComponent(`${baseUrl(req)}/auth/google/callback`);
  const scope=encodeURIComponent('openid email profile');
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?client_id=${encodeURIComponent(process.env.GOOGLE_CLIENT_ID)}&redirect_uri=${redirect}&response_type=code&scope=${scope}&state=${req.session.oauthState}&access_type=online&prompt=select_account`);
});

app.get('/auth/google/callback',async(req,res)=>{
  try{
    if(!req.query.code||req.query.state!==req.session.oauthState)return res.status(400).send('Invalid OAuth state.');
    delete req.session.oauthState;
    const redirect=`${baseUrl(req)}/auth/google/callback`;
    const token=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({code:req.query.code,client_id:process.env.GOOGLE_CLIENT_ID,client_secret:process.env.GOOGLE_CLIENT_SECRET,redirect_uri:redirect,grant_type:'authorization_code'})}).then(r=>r.json());
    if(!token.access_token)return res.status(401).send('Google authorization failed.');
    const info=await fetch('https://openidconnect.googleapis.com/v1/userinfo',{headers:{authorization:`Bearer ${token.access_token}`}}).then(r=>r.json());
    const user=await upsertOAuth('google',info.sub,info.email,info.name||info.email?.split('@')[0]||'Otti User',info.picture);
    await loginSession(req,user.id);res.redirect('/');
  }catch(e){console.error(e);res.status(500).send('Google sign-in failed.')}
});

app.get('/auth/github',(req,res)=>{
  if(!process.env.GITHUB_CLIENT_ID||!process.env.GITHUB_CLIENT_SECRET)return res.status(503).send('GitHub OAuth is not configured.');
  req.session.oauthState=randomState();
  const redirect=encodeURIComponent(`${baseUrl(req)}/auth/github/callback`);
  res.redirect(`https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(process.env.GITHUB_CLIENT_ID)}&redirect_uri=${redirect}&scope=${encodeURIComponent('read:user user:email')}&state=${req.session.oauthState}`);
});

app.get('/auth/github/callback',async(req,res)=>{
  try{
    if(!req.query.code||req.query.state!==req.session.oauthState)return res.status(400).send('Invalid OAuth state.');
    delete req.session.oauthState;
    const redirect=`${baseUrl(req)}/auth/github/callback`;
    const token=await fetch('https://github.com/login/oauth/access_token',{method:'POST',headers:{accept:'application/json','content-type':'application/json'},body:JSON.stringify({client_id:process.env.GITHUB_CLIENT_ID,client_secret:process.env.GITHUB_CLIENT_SECRET,code:req.query.code,redirect_uri:redirect})}).then(r=>r.json());
    if(!token.access_token)return res.status(401).send('GitHub authorization failed.');
    const headers={authorization:`Bearer ${token.access_token}`,accept:'application/vnd.github+json','user-agent':'otti-live'};
    const profile=await fetch('https://api.github.com/user',{headers}).then(r=>r.json());
    const emails=await fetch('https://api.github.com/user/emails',{headers}).then(r=>r.json());
    const primary=(Array.isArray(emails)?emails.find(x=>x.primary&&x.verified):null)||emails?.find?.(x=>x.verified);
    if(!primary?.email)return res.status(400).send('A verified GitHub email is required.');
    const user=await upsertOAuth('github',String(profile.id),primary.email,profile.name||profile.login||'Otti User',profile.avatar_url);
    await loginSession(req,user.id);res.redirect('/');
  }catch(e){console.error(e);res.status(500).send('GitHub sign-in failed.')}
});

async function upsertOAuth(provider,providerId,email,name,avatar){
  let r=await pool.query('SELECT * FROM users WHERE provider=$1 AND provider_id=$2',[provider,providerId]);
  if(r.rowCount)return r.rows[0];
  r=await pool.query('SELECT * FROM users WHERE email=$1',[email.toLowerCase()]);
  if(r.rowCount){
    const u=r.rows[0];
    await pool.query('UPDATE users SET provider=$1,provider_id=$2,avatar=COALESCE($3,avatar),updated_at=NOW() WHERE id=$4',[provider,providerId,avatar,u.id]);
    return {...u,provider,provider_id:providerId,avatar:avatar||u.avatar};
  }
  const u={id:uuid(),email:email.toLowerCase(),name:safe(name,80)||'Otti User',avatar:avatar||null,provider,provider_id:providerId};
  await pool.query('INSERT INTO users(id,email,name,avatar,provider,provider_id) VALUES($1,$2,$3,$4,$5,$6)',[u.id,u.email,u.name,u.avatar,u.provider,u.provider_id]);
  return u;
}
function loginSession(req,userId){
  return new Promise((resolve,reject)=>req.session.regenerate(err=>{
    if(err)return reject(err);req.session.userId=userId;req.session.save(err2=>err2?reject(err2):resolve());
  }));
}

app.get('/api/contacts',requireAuth,async(req,res)=>{
  try{
    const r=await pool.query(`SELECT c.contact_user_id AS user_id,u.name,u.email,u.avatar,c.status,c.created_at,
      (SELECT r.id FROM rooms r JOIN room_members mine ON mine.room_id=r.id AND mine.user_id=$1 JOIN room_members peer ON peer.room_id=r.id AND peer.user_id=c.contact_user_id WHERE r.kind='direct' LIMIT 1) AS room_id
      FROM contacts c JOIN users u ON u.id=c.contact_user_id WHERE c.user_id=$1 AND c.status <> 'blocked' ORDER BY c.created_at DESC`,[req.session.userId]);
    res.json({contacts:r.rows});
  }catch(e){console.error(e);res.status(500).json({error:'CONTACTS_ERROR'})}
});

app.get('/api/users/search',requireAuth,async(req,res)=>{
  try{
    const q=safe(req.query.q,120).replace(/^@/,'').toLowerCase();
    if(!q)return res.json({users:[]});
    const r=await pool.query(`SELECT id,name,email,avatar FROM users WHERE id<>$1 AND (LOWER(name) LIKE $2 OR LOWER(email) LIKE $2) ORDER BY name LIMIT 20`,[req.session.userId,`%${q}%`]);
    res.json({users:r.rows});
  }catch(e){console.error(e);res.status(500).json({error:'USER_SEARCH_ERROR'})}
});

app.post('/api/contacts',requireAuth,async(req,res)=>{
  const target=safe(req.body.userId,80);
  if(!target)return res.status(400).json({error:'USER_REQUIRED'});
  try{
    const u=await pool.query('SELECT id,name,email,avatar FROM users WHERE id=$1',[target]);
    if(!u.rowCount)return res.status(404).json({error:'USER_NOT_FOUND'});
    if(target===req.session.userId)return res.status(400).json({error:'CANNOT_ADD_SELF'});
    const blocked=await pool.query(`SELECT 1 FROM contacts WHERE (user_id=$1 AND contact_user_id=$2 AND status='blocked') OR (user_id=$2 AND contact_user_id=$1 AND status='blocked') LIMIT 1`,[req.session.userId,target]);
    if(blocked.rowCount)return res.status(403).json({error:'CONTACT_BLOCKED'});
    for(const [a,b] of [[req.session.userId,target],[target,req.session.userId]]){
      const exists=await pool.query('SELECT 1 FROM contacts WHERE user_id=$1 AND contact_user_id=$2 LIMIT 1',[a,b]);
      if(exists.rowCount)await pool.query("UPDATE contacts SET status='accepted' WHERE user_id=$1 AND contact_user_id=$2",[a,b]);
      else await pool.query("INSERT INTO contacts(user_id,contact_user_id,status) VALUES($1,$2,'accepted')",[a,b]);
    }
    let room=await pool.query(`SELECT r.id,r.name,r.kind FROM rooms r JOIN room_members a ON a.room_id=r.id AND a.user_id=$1 JOIN room_members b ON b.room_id=r.id AND b.user_id=$2 WHERE r.kind='direct' LIMIT 1`,[req.session.userId,target]);
    if(!room.rowCount){
      const roomId=uuid(),name=u.rows[0].name;
      await pool.query('INSERT INTO rooms(id,name,kind,created_by) VALUES($1,$2,$3,$4)',[roomId,name,'direct',req.session.userId]);
      await pool.query('INSERT INTO room_members(room_id,user_id) VALUES($1,$2),($1,$3)',[roomId,req.session.userId,target]);
      await pool.query('INSERT INTO user_room_reads(user_id,room_id,last_read_at) VALUES($1,$2,NOW()),($3,$2,NOW()) ON CONFLICT DO NOTHING',[req.session.userId,roomId,target]);
      room={rows:[{id:roomId,name,kind:'direct'}]};
    }
    res.json({ok:true,user:u.rows[0],room:room.rows[0]});
  }catch(e){console.error(e);res.status(500).json({error:'CONTACT_ADD_ERROR'})}
});

app.get('/api/rooms/:roomId/messages',requireAuth,async(req,res)=>{
  const access=await pool.query('SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2',[req.params.roomId,req.session.userId]);
  if(!access.rowCount)return res.status(403).json({error:'FORBIDDEN'});
  const r=await pool.query(`SELECT m.id,m.text,m.is_hidden AS is_hidden,m.created_at,u.id user_id,u.name FROM messages m LEFT JOIN users u ON u.id=m.user_id WHERE m.room_id=$1 AND m.created_at>COALESCE((SELECT cleared_at FROM user_room_clears WHERE user_id=$2 AND room_id=$1), 'epoch'::timestamptz) ORDER BY m.created_at ASC LIMIT 200`,[req.params.roomId,req.session.userId]);
  res.json({messages:r.rows});
});

app.post('/api/rooms/:roomId/messages',requireAuth,async(req,res)=>{
  try{
    const roomId=safe(req.params.roomId,80);
    const access=await pool.query('SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2',[roomId,req.session.userId]);
    if(!access.rowCount)return res.status(403).json({error:'FORBIDDEN'});
    const text=safe(req.body.text);
    if(!text)return res.status(400).json({error:'MESSAGE_REQUIRED'});
    const id=uuid(),hidden=false;
    const r=await pool.query(`SELECT $1::uuid AS id,$2::uuid AS room_id,$3::uuid AS user_id,$4::text AS text,$5::boolean AS is_hidden,NOW() AS created_at,u.name FROM users u WHERE u.id=$3`,[id,roomId,req.session.userId,text,hidden]);
    await pool.query('INSERT INTO messages(id,room_id,user_id,text,is_hidden) VALUES($1,$2,$3,$4,$5)',[id,roomId,req.session.userId,text,hidden]);
    const message={...r.rows[0],client_id:safe(req.body.client_id,100)||null};
    broadcast(roomId,{type:'message',room:roomId,...message});
    console.log('REST message persisted',id,'room',roomId);
    res.json({ok:true,message});
  }catch(e){console.error('REST message error',e);res.status(500).json({error:'MESSAGE_SEND_ERROR'})}
});

// Per-user history clearing: does not delete the other participant's copy.
app.post('/api/rooms/:roomId/clear',requireAuth,async(req,res)=>{
  try{const roomId=safe(req.params.roomId,80);const access=await pool.query('SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2',[roomId,req.session.userId]);if(!access.rowCount)return res.status(403).json({error:'FORBIDDEN'});await pool.query(`INSERT INTO user_room_clears(user_id,room_id,cleared_at) VALUES($1,$2,NOW()) ON CONFLICT(user_id,room_id) DO UPDATE SET cleared_at=EXCLUDED.cleared_at`,[req.session.userId,roomId]);res.json({ok:true})}
  catch(e){console.error(e);res.status(500).json({error:'CHAT_CLEAR_ERROR'})}
});
app.post('/api/chats/clear-all',requireAuth,async(req,res)=>{
  try{await pool.query(`INSERT INTO user_room_clears(user_id,room_id,cleared_at) SELECT $1,room_id,NOW() FROM room_members WHERE user_id=$1 ON CONFLICT(user_id,room_id) DO UPDATE SET cleared_at=EXCLUDED.cleared_at`,[req.session.userId]);res.json({ok:true})}
  catch(e){console.error(e);res.status(500).json({error:'CLEAR_ALL_ERROR'})}
});
app.get('/api/contacts/blocked',requireAuth,async(req,res)=>{
  try{const r=await pool.query(`SELECT c.contact_user_id AS user_id,u.name,u.email FROM contacts c JOIN users u ON u.id=c.contact_user_id WHERE c.user_id=$1 AND c.status='blocked' ORDER BY c.created_at DESC`,[req.session.userId]);res.json({contacts:r.rows})}
  catch(e){console.error(e);res.status(500).json({error:'BLOCKED_CONTACTS_ERROR'})}
});
app.post('/api/contacts/:contactId/unblock',requireAuth,async(req,res)=>{
  try{await pool.query(`DELETE FROM contacts WHERE user_id=$1 AND contact_user_id=$2 AND status='blocked'`,[req.session.userId,safe(req.params.contactId,80)]);res.json({ok:true})}
  catch(e){console.error(e);res.status(500).json({error:'UNBLOCK_ERROR'})}
});
app.delete('/api/contacts/:contactId',requireAuth,async(req,res)=>{
  const target=safe(req.params.contactId,80);
  try{await pool.query('DELETE FROM contacts WHERE user_id=$1 AND contact_user_id=$2',[req.session.userId,target]);await pool.query(`DELETE FROM room_members rm USING rooms r WHERE rm.room_id=r.id AND rm.user_id=$1 AND r.kind='direct' AND EXISTS(SELECT 1 FROM room_members other WHERE other.room_id=r.id AND other.user_id=$2)`,[req.session.userId,target]);res.json({ok:true})}
  catch(e){console.error(e);res.status(500).json({error:'CONTACT_DELETE_ERROR'})}
});
app.post('/api/contacts/:contactId/block',requireAuth,async(req,res)=>{
  const target=safe(req.params.contactId,80);
  try{if(target===req.session.userId)return res.status(400).json({error:'CANNOT_BLOCK_SELF'});const existing=await pool.query("UPDATE contacts SET status='blocked' WHERE user_id=$1 AND contact_user_id=$2",[req.session.userId,target]);if(!existing.rowCount)await pool.query(`INSERT INTO contacts(user_id,contact_user_id,status) VALUES($1,$2,'blocked')`,[req.session.userId,target]);await pool.query(`DELETE FROM room_members rm USING rooms r WHERE rm.room_id=r.id AND rm.user_id=$1 AND r.kind='direct' AND EXISTS(SELECT 1 FROM room_members other WHERE other.room_id=r.id AND other.user_id=$2)`,[req.session.userId,target]);res.json({ok:true})}
  catch(e){console.error(e);res.status(500).json({error:'CONTACT_BLOCK_ERROR'})}
});

app.get('/api/statuses',requireAuth,async(req,res)=>{
  const r=await pool.query(`SELECT s.id,s.symbol,s.text,s.created_at,u.id user_id,u.name,u.email FROM statuses s JOIN users u ON u.id=s.user_id WHERE s.created_at>NOW()-INTERVAL '24 hours' ORDER BY s.created_at DESC LIMIT 100`);
  res.json({statuses:r.rows});
});
app.post('/api/statuses',requireAuth,async(req,res)=>{
  const text=safe(req.body.text,300);if(!text)return res.status(400).json({error:'Status is required'});
  const s={id:uuid(),symbol:safe(req.body.symbol,8)||'✦',text};
  await pool.query('INSERT INTO statuses(id,user_id,symbol,text) VALUES($1,$2,$3,$4)',[s.id,req.session.userId,s.symbol,s.text]);
  res.json({status:s});
});

app.get('/api/rooms',requireAuth,async(req,res)=>{
  const r=await pool.query(`SELECT r.id,r.name,r.kind,r.created_at,gm.icon FROM rooms r JOIN room_members rm ON rm.room_id=r.id LEFT JOIN groups_meta gm ON gm.room_id=r.id WHERE rm.user_id=$1 ORDER BY r.created_at DESC`,[req.session.userId]);
  res.json({rooms:r.rows});
});
app.post('/api/groups',requireAuth,async(req,res)=>{
  const client=await pool.connect();
  try{
    await client.query('BEGIN');const roomId=uuid(),groupId=uuid(),name=safe(req.body.name,80)||'New Otti Circle',icon=safe(req.body.icon,8)||'◇';
    await client.query('INSERT INTO rooms(id,name,kind,created_by) VALUES($1,$2,$3,$4)',[roomId,name,'group',req.session.userId]);
    await client.query('INSERT INTO room_members(room_id,user_id) VALUES($1,$2)',[roomId,req.session.userId]);
    await client.query('INSERT INTO user_room_reads(user_id,room_id,last_read_at) VALUES($1,$2,NOW()) ON CONFLICT DO NOTHING',[req.session.userId,roomId]);
    await client.query('INSERT INTO groups_meta(id,room_id,icon,created_by) VALUES($1,$2,$3,$4)',[groupId,roomId,icon,req.session.userId]);
    await client.query('COMMIT');res.json({room:{id:roomId,name,kind:'group',icon}});
  }catch(e){await client.query('ROLLBACK');console.error(e);res.status(500).json({error:'GROUP_ERROR'})}finally{client.release()}
});
app.delete('/api/groups/:roomId',requireAuth,async(req,res)=>{
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const owner=await client.query("SELECT id FROM rooms WHERE id=$1 AND kind='group' AND created_by=$2 FOR UPDATE",[req.params.roomId,req.session.userId]);
    if(!owner.rowCount){await client.query('ROLLBACK');return res.status(403).json({error:'NOT_GROUP_OWNER'})}
    await client.query('DELETE FROM messages WHERE room_id=$1',[req.params.roomId]);
    await client.query('DELETE FROM user_room_clears WHERE room_id=$1',[req.params.roomId]);
    await client.query('DELETE FROM user_room_reads WHERE room_id=$1',[req.params.roomId]);
    await client.query('DELETE FROM room_members WHERE room_id=$1',[req.params.roomId]);
    await client.query('DELETE FROM groups_meta WHERE room_id=$1',[req.params.roomId]);
    await client.query('DELETE FROM rooms WHERE id=$1',[req.params.roomId]);
    await client.query('COMMIT');res.json({ok:true});
  }catch(e){await client.query('ROLLBACK');console.error('Raft delete error',e);res.status(500).json({error:'RAFT_DELETE_ERROR'})}finally{client.release()}
});

app.get('/api/notifications',requireAuth,async(req,res)=>{
  try{
    const sinceRaw=safe(req.query.since,80);const parsed=sinceRaw?new Date(sinceRaw):new Date(Date.now()-5000);
    const since=Number.isNaN(parsed.getTime())?new Date(Date.now()-5000):parsed;
    const r=await pool.query(`
      SELECT m.id,m.room_id AS room,m.user_id,m.text,m.created_at,u.name,
             rooms.name AS room_name,rooms.kind
      FROM messages m
      JOIN room_members mine ON mine.room_id=m.room_id AND mine.user_id=$1
      JOIN rooms ON rooms.id=m.room_id
      LEFT JOIN users u ON u.id=m.user_id
      WHERE m.user_id<>$1 AND m.created_at>$2
        AND m.created_at>COALESCE((SELECT cleared_at FROM user_room_clears c WHERE c.user_id=$1 AND c.room_id=m.room_id),'epoch'::timestamptz)
      ORDER BY m.created_at ASC LIMIT 100`,[req.session.userId,since]);
    res.json({messages:r.rows,cursor:new Date().toISOString()});
  }catch(e){console.error('Notification poll error',e);res.status(500).json({error:'NOTIFICATIONS_ERROR'})}
});

app.post('/api/rooms/:roomId/read',requireAuth,async(req,res)=>{
  try{
    const roomId=safe(req.params.roomId,80);const access=await pool.query('SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2',[roomId,req.session.userId]);
    if(!access.rowCount)return res.status(403).json({error:'FORBIDDEN'});
    await pool.query(`INSERT INTO user_room_reads(user_id,room_id,last_read_at) VALUES($1,$2,NOW()) ON CONFLICT(user_id,room_id) DO UPDATE SET last_read_at=EXCLUDED.last_read_at`,[req.session.userId,roomId]);res.json({ok:true});
  }catch(e){console.error('Mark read error',e);res.status(500).json({error:'MARK_READ_ERROR'})}
});

app.get('/api/unread',requireAuth,async(req,res)=>{
  try{
    const r=await pool.query(`SELECT m.room_id,COUNT(*)::int AS count
      FROM messages m JOIN room_members mine ON mine.room_id=m.room_id AND mine.user_id=$1
      WHERE m.user_id<>$1 AND m.created_at>GREATEST(COALESCE((SELECT c.cleared_at FROM user_room_clears c WHERE c.user_id=$1 AND c.room_id=m.room_id),'epoch'::timestamptz),COALESCE((SELECT rd.last_read_at FROM user_room_reads rd WHERE rd.user_id=$1 AND rd.room_id=m.room_id),'epoch'::timestamptz))
      GROUP BY m.room_id`,[req.session.userId]);
    const counts={};for(const row of r.rows)counts[row.room_id]=row.count;res.json({counts});
  }catch(e){console.error('Unread counts error',e);res.status(500).json({error:'UNREAD_ERROR'})}
});

app.get('/api/groups/:roomId/members',requireAuth,async(req,res)=>{
  const access=await pool.query('SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2',[req.params.roomId,req.session.userId]);
  if(!access.rowCount)return res.status(403).json({error:'FORBIDDEN'});
  const r=await pool.query(`SELECT rm.user_id,u.name,u.email,u.avatar FROM room_members rm JOIN users u ON u.id=rm.user_id WHERE rm.room_id=$1 ORDER BY rm.joined_at`,[req.params.roomId]);
  res.json({members:r.rows});
});
app.post('/api/groups/:roomId/members',requireAuth,async(req,res)=>{
  const target=safe(req.body.userId,80);
  try{
    const owner=await pool.query("SELECT 1 FROM rooms WHERE id=$1 AND kind='group' AND created_by=$2",[req.params.roomId,req.session.userId]);
    if(!owner.rowCount)return res.status(403).json({error:'NOT_GROUP_OWNER'});
    const u=await pool.query('SELECT id,name,email,avatar FROM users WHERE id=$1',[target]);
    if(!u.rowCount)return res.status(404).json({error:'USER_NOT_FOUND'});
    await pool.query('INSERT INTO room_members(room_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[req.params.roomId,target]);
    await pool.query('INSERT INTO user_room_reads(user_id,room_id,last_read_at) VALUES($1,$2,NOW()) ON CONFLICT DO NOTHING',[target,req.params.roomId]);
    res.json({ok:true,user:u.rows[0]});
  }catch(e){console.error(e);res.status(500).json({error:'GROUP_MEMBER_ADD_ERROR'})}
});

/* ---------- Robust WebSocket ---------- */
const wsTokens=new Map();
app.post('/api/ws-token',requireAuth,async(req,res)=>{
  try{
    const roomId=safe(req.query.roomId||req.body?.roomId,80);
    if(!roomId)return res.status(400).json({error:'ROOM_REQUIRED'});
    const access=await pool.query('SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2',[roomId,req.session.userId]);
    if(!access.rowCount)return res.status(403).json({error:'FORBIDDEN'});
    const token=crypto.randomBytes(32).toString('hex');
    wsTokens.set(token,{userId:req.session.userId,roomId,expires:Date.now()+60000});
    res.json({token,roomId});
  }catch(e){console.error('WS token error',e);res.status(500).json({error:'WS_TOKEN_ERROR'})}
});
setInterval(()=>{const now=Date.now();for(const [k,v] of wsTokens)if(v.expires<now)wsTokens.delete(k)},30000).unref();

const roomSockets=new Map();
const userRoomSockets=new Map();
function joinSocket(roomId,ws){
  if(!roomSockets.has(roomId))roomSockets.set(roomId,new Set());
  roomSockets.get(roomId).add(ws);
  const key=`${ws.user.id}:${roomId}`;
  const previous=userRoomSockets.get(key);
  if(previous&&previous!==ws){try{previous.close(4001,'replaced')}catch(_){} }
  userRoomSockets.set(key,ws);
}
function leaveSocket(roomId,ws){
  const s=roomSockets.get(roomId);
  if(s){s.delete(ws);if(!s.size)roomSockets.delete(roomId)}
  const key=`${ws.user?.id}:${roomId}`;
  if(userRoomSockets.get(key)===ws)userRoomSockets.delete(key);
}
function broadcast(roomId,payload){for(const ws of roomSockets.get(roomId)||[]){if(ws.readyState===1)ws.send(JSON.stringify(payload))}}

async function authorizeWs(token){
  const x=wsTokens.get(token);
  if(!x||x.expires<Date.now()){if(token)wsTokens.delete(token);return null}
  wsTokens.delete(token);
  const r=await pool.query('SELECT id,name FROM users WHERE id=$1',[x.userId]);
  if(!r.rowCount)return null;
  return {...r.rows[0],roomId:x.roomId};
}

server.on('upgrade',(req,socket,head)=>{
  try{
    const u=new URL(req.url||'',`http://${req.headers.host||'localhost'}`);
    if(u.pathname!=='/ws')return socket.destroy();
    const token=u.searchParams.get('token');
    if(!token){console.error('WS upgrade rejected: missing token');return socket.destroy();}
    console.log('WS upgrade received');
    wss.handleUpgrade(req,socket,head,ws=>wss.emit('connection',ws,req,token));
  }catch(e){console.error('WS upgrade error',e);socket.destroy()}
});

wss.on('connection',async(ws,req,token)=>{
  const user=await authorizeWs(token);
  if(!user){console.error('WS authorization failed');ws.close(1008,'unauthorized');return}
  ws.user=user;ws.roomId=null;ws.isAlive=true;
  console.log('WS connected for user',user.id);

  // Auto-join the room carried by the one-time token. This removes the
  // fragile dependency on the browser sending a second 'join' frame.
  const tokenRoomId=user.roomId;
  if(tokenRoomId){
    const access=await pool.query('SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2',[tokenRoomId,user.id]);
    if(access.rowCount){
      ws.roomId=tokenRoomId;
      joinSocket(tokenRoomId,ws);
      console.log('WS auto-joined room',tokenRoomId,'user',user.id);
      const history=await pool.query(`SELECT m.id,m.text,m.is_hidden AS is_hidden,m.created_at,u.id user_id,u.name FROM messages m LEFT JOIN users u ON u.id=m.user_id WHERE m.room_id=$1 AND m.created_at>COALESCE((SELECT cleared_at FROM user_room_clears WHERE user_id=$2 AND room_id=$1), 'epoch'::timestamptz) ORDER BY m.created_at DESC LIMIT 200`,[tokenRoomId,user.id]);
      ws.send(JSON.stringify({type:'room-state',room:tokenRoomId,messages:history.rows.reverse()}));
      broadcast(tokenRoomId,{type:'presence',room:tokenRoomId,user:user.name,count:roomSockets.get(tokenRoomId).size});
    }else{
      ws.send(JSON.stringify({type:'error',error:'FORBIDDEN'}));
      ws.close(1008,'forbidden');return;
    }
  }

  ws.on('pong',()=>{ws.isAlive=true});
  ws.on('message',async raw=>{
    try{
      const m=JSON.parse(raw.toString());

      if(m.type==='ping'){ws.send(JSON.stringify({type:'pong'}));return}

      if(m.type==='join'){
        const roomId=safe(m.room,80);
        if(roomId===ws.roomId)return;
        const access=await pool.query('SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2',[roomId,user.id]);
        if(!access.rowCount){ws.send(JSON.stringify({type:'error',error:'FORBIDDEN'}));return}
        if(ws.roomId)leaveSocket(ws.roomId,ws);
        ws.roomId=roomId;joinSocket(roomId,ws);
        console.log('WS joined room',roomId,'user',user.id);
        const history=await pool.query(`SELECT m.id,m.text,m.is_hidden AS is_hidden,m.created_at,u.id user_id,u.name FROM messages m LEFT JOIN users u ON u.id=m.user_id WHERE m.room_id=$1 AND m.created_at>COALESCE((SELECT cleared_at FROM user_room_clears WHERE user_id=$2 AND room_id=$1), 'epoch'::timestamptz) ORDER BY m.created_at DESC LIMIT 200`,[roomId,user.id]);
        ws.send(JSON.stringify({type:'room-state',room:roomId,messages:history.rows.reverse()}));
        broadcast(roomId,{type:'presence',room:roomId,user:user.name,count:roomSockets.get(roomId).size});
        return;
      }

      if(!ws.roomId)return;

      if(m.type==='message'){
        const text=safe(m.text);
        if(!text)return;
        const id=uuid(),hidden=false;
        await pool.query('INSERT INTO messages(id,room_id,user_id,text,is_hidden) VALUES($1,$2,$3,$4,$5)',[id,ws.roomId,user.id,text,hidden]);
        console.log('WS message persisted',id,'room',ws.roomId);
        broadcast(ws.roomId,{type:'message',room:ws.roomId,id,text,is_hidden:hidden,client_id:safe(m.client_id,100)||null,created_at:new Date().toISOString(),user_id:user.id,name:user.name});
        return;
      }

      if(m.type==='typing'){
        broadcast(ws.roomId,{type:m.type,room:ws.roomId,user:user.name});
        return;
      }

      if(m.type==='react'){
        broadcast(ws.roomId,{type:'react',room:ws.roomId,user:user.name,messageId:safe(m.messageId,100),reaction:safe(m.reaction,8)});
      }
    }catch(e){console.error('ws message error',e)}
  });

  ws.on('close',()=>{
    if(ws.roomId){
      const room=ws.roomId;leaveSocket(room,ws);
      broadcast(room,{type:'presence',room,user:user.name,count:roomSockets.get(room)?.size||0});
    }
  });
});

const heartbeat=setInterval(()=>{
  for(const ws of wss.clients){
    if(ws.isAlive===false){try{ws.terminate()}catch(_){}continue}
    ws.isAlive=false;try{ws.ping()}catch(_){}
  }
},25000);
heartbeat.unref();

app.get('*',(req,res)=>{
  if(req.path.startsWith('/api/')||req.path.startsWith('/auth/'))return res.status(404).end();
  res.sendFile(path.join(__dirname,'index.html'));
});

init().then(()=>{
  server.listen(process.env.PORT||10000,'0.0.0.0',()=>console.log('OTTI V3 listening'));
}).catch(e=>{console.error(e);process.exit(1)});
