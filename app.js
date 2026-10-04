const slang = [
 ["◇","say less","secret / understood","Privacy"],
 ["●🌊","lowkey","private / quiet","Mood"],
 ["◉〰","ayo...","someone's looking","Privacy"],
 ["✦","lesgooo","excited / let's go","Energy"],
 ["☾","eepy","sleepy / rest mode","Mood"],
 ["≈","chaotic","no context needed","Mood"],
 ["♡","soft hours","affection / warm vibes","Love"],
 ["〰","offline-ish","need space","Privacy"],
 ["⌁","we're back","surface / return","Privacy"],
 ["○","imma dip","leave / disappear","Mood"],
 ["✧","urgent","pay attention","Alert"],
 ["●","mine","personal / private","Privacy"]
];
const pages=[...document.querySelectorAll('.page')];
const navs=[...document.querySelectorAll('[data-nav]')];
const toastEl=document.getElementById('toast');
function toast(msg){toastEl.textContent=msg;toastEl.classList.add('show');setTimeout(()=>toastEl.classList.remove('show'),2200)}
function showPage(id){
 pages.forEach(p=>p.classList.toggle('active',p.id===id));
 document.querySelectorAll('.nav-btn,.bottom-nav button').forEach(b=>b.classList.toggle('active',b.dataset.nav===id));
 window.scrollTo({top:0,behavior:'smooth'});
}
navs.forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.nav)));
function openModal(id){document.getElementById(id).classList.add('open')}
function closeModals(){document.querySelectorAll('.modal').forEach(m=>m.classList.remove('open'))}
document.querySelectorAll('.close').forEach(b=>b.addEventListener('click',closeModals));
document.querySelectorAll('.modal').forEach(m=>m.addEventListener('click',e=>{if(e.target===m)closeModals()}));

function dive(){
 document.getElementById('diveOverlay').classList.add('active');
 document.body.style.overflow='hidden';
}
function surface(){
 document.getElementById('diveOverlay').classList.remove('active');
 document.body.style.overflow='';
 toast('Back on the surface.');
}
['heroDive','cardDive','chatDive'].forEach(id=>document.getElementById(id)?.addEventListener('click',dive));
document.getElementById('surfaceBtn').addEventListener('click',surface);

const grid=document.getElementById('slangGrid');
function renderSlang(filter=''){
 grid.innerHTML='';
 slang.filter(x=>x.join(' ').toLowerCase().includes(filter.toLowerCase())).forEach(x=>{
   const c=document.createElement('button');c.className='slang-card';
   c.innerHTML=`<span class="slang-glyph">${x[0]}</span><span><b>${x[1]}</b><small>${x[2]} · ${x[3]}</small></span>`;
   c.addEventListener('click',()=>toast(`${x[0]} means “${x[1]}”`));
   grid.appendChild(c);
 });
}
renderSlang();
document.getElementById('slangSearch').addEventListener('input',e=>renderSlang(e.target.value));
document.getElementById('saveSymbol').addEventListener('click',e=>{e.target.textContent='Saved ✓';toast('Added ◇ to your Codex.');});
document.getElementById('combineBtn').addEventListener('click',()=>toast('Symbol mixer coming next — the language is growing.'));
document.querySelectorAll('.symbol-card').forEach(c=>c.addEventListener('click',()=>toast(`Symbol ${c.dataset.symbol} selected.`)));

document.getElementById('cameraBtn').addEventListener('click',()=>openModal('cameraModal'));
document.getElementById('openCamera').addEventListener('click',()=>openModal('cameraModal'));
let stream=null;
document.getElementById('startCamera').addEventListener('click',async()=>{
 try{
   stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:'user'},audio:false});
   document.getElementById('camera').srcObject=stream;
   document.getElementById('cameraState').textContent='Camera ready · watching locally';
   toast('Peek protection is active.');
 }catch(err){document.getElementById('cameraState').textContent='Camera permission needed';toast('Camera access was not granted.');}
});
document.getElementById('simulatePeek').addEventListener('click',()=>{closeModals();setTimeout(dive,120);toast('Peek detected — diving now.');});

document.getElementById('createGroup').addEventListener('click',()=>openModal('groupModal'));
document.getElementById('finishGroup').addEventListener('click',()=>{closeModals();toast('Your new group is ready.');});
document.getElementById('setStatus').addEventListener('click',()=>openModal('statusModal'));
document.querySelectorAll('.status-picks button').forEach(b=>b.addEventListener('click',()=>document.getElementById('statusText').value=b.dataset.status));
document.getElementById('finishStatus').addEventListener('click',()=>{closeModals();toast('Status posted.');});
document.getElementById('newChat').addEventListener('click',()=>toast('New chat composer opened.'));

document.getElementById('profileBtn').addEventListener('click',()=>toast('Profile + privacy controls are ready for the next build.'));
window.addEventListener('keydown',e=>{if(e.key==='Escape'){surface();closeModals()} if(e.key.toLowerCase()==='d' && !e.metaKey && !e.ctrlKey)dive()});
