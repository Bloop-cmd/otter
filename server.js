const express = require('express');
const http = require('http');
const path = require('path');
const { WebSocketServer } = require('ws');
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const rooms = new Map();
app.use(express.static(path.join(__dirname)));
app.get('/health', (_req,res)=>res.json({ok:true,service:'otti',rooms:rooms.size}));
function room(name){ if(!rooms.has(name)) rooms.set(name,new Set()); return rooms.get(name); }
function broadcast(roomName,msg){ for(const ws of room(roomName)){ if(ws.readyState===1) ws.send(JSON.stringify(msg)); } }
wss.on('connection', ws=>{
 let currentRoom='Otti', user='Guest'; room(currentRoom).add(ws);
 ws.on('message', raw=>{ try{const m=JSON.parse(raw); if(m.type==='join'){ if(currentRoom) room(currentRoom).delete(ws); currentRoom=m.room||'Otti'; user=m.user||'Guest'; room(currentRoom).add(ws); broadcast(currentRoom,{type:'presence',user,count:room(currentRoom).size}); return; }
 if(m.type==='message'){broadcast(currentRoom,{type:'message',room:currentRoom,user,text:String(m.text||'').slice(0,2000),time:new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}),under:!!m.under});}
 if(m.type==='dive'){broadcast(currentRoom,{type:'dive',room:currentRoom,user});}
 }catch{} });
 ws.on('close',()=>{room(currentRoom).delete(ws);broadcast(currentRoom,{type:'presence',user,count:room(currentRoom).size});});
});
const PORT=process.env.PORT||3000;
server.listen(PORT,()=>console.log(`OTTI live server listening on ${PORT}`));
