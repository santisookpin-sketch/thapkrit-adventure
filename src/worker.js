const JSON_HEADERS = {'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'};
const json=(obj,status=200,headers={})=>new Response(JSON.stringify(obj),{status,headers:{...JSON_HEADERS,...headers}});
const err=(message,status=400)=>json({ok:false,error:message},status);
const now=()=>new Date().toISOString();
const validatePhone=p=>/^0[0-9]{9}$/.test(p);
const validateNickname=p=>p.length>=2&&p.length<=24;
const allowedDifficulty=[0,1,2];

const randomId=()=>crypto.randomUUID();
const randomToken=()=>Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b=>b.toString(16).padStart(2,'0')).join('');
const sha256=async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))).map(b=>b.toString(16).padStart(2,'0')).join('');
async function hmac(key,message){const secret=await crypto.subtle.importKey('raw',new TextEncoder().encode(key),{name:'HMAC',hash:'SHA-256'},false,['sign']);return Array.from(new Uint8Array(await crypto.subtle.sign('HMAC',secret,new TextEncoder().encode(message)))).map(b=>b.toString(16).padStart(2,'0')).join('');}
function eq(a,b){if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;let z=0;for(let i=0;i<a.length;i++)z|=a.charCodeAt(i)^b.charCodeAt(i);return z===0;}
const getCookie=(req,n)=>((req.headers.get('cookie')||'').split(';').map(v=>v.trim()).find(v=>v.startsWith(n+'='))||'').slice(n.length+1);
async function isAdmin(req,env){if(!env.ADMIN_PASSWORD)return false;const c=getCookie(req,'tk_admin');const [exp,sig]=c.split('.');if(!exp||!sig||!/^\d+$/.test(exp)||Number(exp)<Date.now())return false;return eq(sig,await hmac(env.ADMIN_PASSWORD,exp));}
async function requirePlayer(req,env){const header=req.headers.get('Authorization')||'';if(!header.startsWith('Bearer '))return null;const token=header.slice(7);if(!/^[0-9a-f]{64}$/.test(token))return null;const row=await env.DB.prepare('SELECT id,nickname,status FROM players WHERE session_hash=?').bind(await sha256(token)).first();return row?.status==='active'?row:null;}
async function readJSON(req){if(Number(req.headers.get('content-length')||0)>8192)throw Error('JSON ใหญ่เกินไป');const t=await req.text();if(t.length>8192)throw Error('JSON ใหญ่เกินไป');return JSON.parse(t||'{}');}
function panel(){return `<!doctype html><html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Thapkrit Admin</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#071421;color:#eaf3fa;font:15px system-ui,Tahoma;padding:22px}h1{margin:0 0 7px;color:#f4cb75}.muted{color:#96acbd}.wrap{max-width:1180px;margin:auto}.bar{display:flex;gap:9px;flex-wrap:wrap;align-items:center;margin:12px 0 18px}input,button,select{padding:10px 13px;border:1px solid #385971;border-radius:9px;background:#122d40;color:white}button{cursor:pointer;background:#236e8e}button.danger{background:#812e3d}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:19px}.card{border:1px solid #254659;border-radius:13px;background:#10283a;padding:16px}.card strong{display:block;font-size:27px;color:#ffe19a}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;min-width:650px;background:#102638}th,td{padding:11px;border-bottom:1px solid #304456;text-align:left}th{color:#f2d58f}tr:hover{background:#173548}section{margin:22px 0}small{color:#95a7b7}#msg{min-height:20px;color:#a5ffc2}#login{max-width:400px;padding:26px;border:1px solid #2b5066;border-radius:14px;margin:70px auto;background:#102a3e}#login input{width:100%;margin:13px 0}</style></head><body><div class="wrap"><h1>🎮 ทับกฤช Adventure — Admin</h1><p class="muted">จัดการผู้เล่นและคะแนนจาก Cloudflare D1 • ข้อมูลคะแนนจากตัวเกมยังไม่ผ่านการยืนยันป้องกันโกง</p><div id="msg"></div><div id="login" hidden><h2>เข้าสู่ระบบผู้ดูแล</h2><form id="loginform"><input type="password" id="password" placeholder="รหัสผ่าน Admin" required autocomplete="current-password"><button type="submit">เข้าสู่ระบบ</button></form></div><div id="dashboard" hidden><div class="bar"><button onclick="loadAll()">↻ รีเฟรช</button><button onclick="logout()">ออกจากระบบ</button><a href="/" style="color:#f5d894">เปิดเกม</a></div><div class="cards" id="cards"></div><section><h2>🏆 คะแนนสูงสุด (ทุกด่าน)</h2><div class="scroll"><table><thead><tr><th>ชื่อ</th><th>ด่าน</th><th>คะแนน</th><th>วันที่</th></tr></thead><tbody id="top"></tbody></table></div></section><section><h2>👥 ผู้เล่น</h2><div class="bar"><input id="search" placeholder="ค้นหาชื่อผู้เล่น" oninput="drawPlayers()"><select id="state" onchange="drawPlayers()"><option value="">สถานะทั้งหมด</option><option value="active">ปกติ</option><option value="blocked">ระงับ</option></select></div><div class="scroll"><table><thead><tr><th>ชื่อ</th><th>โทรศัพท์ (Admin เท่านั้น)</th><th>คะแนนดีที่สุดรวม</th><th>ผ่านด่าน</th><th>สถานะ</th><th>เล่นล่าสุด</th><th>จัดการ</th></tr></thead><tbody id="players"></tbody></table></div></section><section><h2>🧾 ผลการเล่นล่าสุด</h2><div class="scroll"><table><thead><tr><th>ชื่อ</th><th>ด่าน</th><th>คะแนน</th><th>เหรียญ</th><th>เวลา</th></tr></thead><tbody id="runs"></tbody></table></div></section></div></div><script>
const $=id=>document.getElementById(id);let data={players:[],runs:[],top:[],stats:{}};const escapeHtml=s=>String(s??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));const req=async(url,opts={})=>{const r=await fetch(url,{...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});const d=await r.json();if(!r.ok)throw Error(d.error||r.status);return d};
async function boot(){try{await loadAll();$('dashboard').hidden=false;$('login').hidden=true}catch(e){$('login').hidden=false;$('dashboard').hidden=true}}
$('loginform').onsubmit=async e=>{e.preventDefault();try{await req('/api/admin/login',{method:'POST',body:JSON.stringify({password:$('password').value})});$('password').value='';$('msg').textContent='เข้าสู่ระบบสำเร็จ';await boot()}catch(ex){$('msg').textContent=ex.message}};
async function logout(){await req('/api/admin/logout',{method:'POST'});$('dashboard').hidden=true;$('login').hidden=false}
async function loadAll(){const d=await req('/api/admin/summary');data=d;$('cards').innerHTML='<div class="card">ผู้เล่นทั้งหมด<strong>'+d.stats.players+'</strong></div><div class="card">ผู้เล่นปกติ<strong>'+d.stats.active+'</strong></div><div class="card">ครั้งที่ผ่านด่าน<strong>'+d.stats.runs+'</strong></div><div class="card">คะแนนสูงสุด<strong>'+d.stats.maxScore+'</strong></div>'; const rows=(arr,fn)=>arr.map(fn).join('');$('top').innerHTML=rows(d.top,r=>'<tr><td>'+escapeHtml(r.nickname)+'</td><td>'+r.stage+'</td><td>'+r.score.toLocaleString()+'</td><td>'+escapeHtml(r.created_at)+'</td></tr>');$('runs').innerHTML=rows(d.runs,r=>'<tr><td>'+escapeHtml(r.nickname)+'</td><td>'+r.stage+'</td><td>'+r.score.toLocaleString()+'</td><td>'+r.coins+'</td><td>'+escapeHtml(r.created_at)+'</td></tr>');drawPlayers()}
function drawDifficulty(){const labels=['หน้าตลาด','ตลาดเก่า','ศาลเจ้า','วัดทับกฤช','สถานีรถไฟ'];$('difficultySettings').innerHTML=(data.difficulty||[1,1,1,1,1]).map((v,i)=>'<label style="display:grid;gap:5px">ด่าน '+(i+1)+' '+labels[i]+'<select class="difficulty" data-stage="'+i+'"><option value="0" '+(v===0?'selected':'')+'>ง่าย</option><option value="1" '+(v===1?'selected':'')+'>ปกติ</option><option value="2" '+(v===2?'selected':'')+'>ยาก</option></select></label>').join('');}
$('saveDifficulty').onclick=async()=>{try{const difficulty=Array.from(document.querySelectorAll('select.difficulty')).map(x=>Number(x.value));await req('/api/admin/settings',{method:'PUT',body:JSON.stringify({difficulty})});$('msg').textContent='บันทึกระดับความยากสำเร็จ';await loadAll()}catch(e){$('msg').textContent=e.message}};
function drawPlayers(){const s=$('search').value.toLowerCase(),st=$('state').value;$('players').innerHTML=data.players.filter(r=>r.nickname.toLowerCase().includes(s)&&(!st||r.status===st)).map(r=>'<tr><td>'+escapeHtml(r.nickname)+'</td><td>'+escapeHtml(r.phone||'-')+'</td><td>'+r.total_best.toLocaleString()+'</td><td>'+r.stages_cleared+'/5</td><td>'+escapeHtml(r.status)+'</td><td>'+escapeHtml(r.last_seen)+'</td><td><button data-op="toggle" data-id="'+r.id+'" data-state="'+r.status+'">'+(r.status==='active'?'ระงับ':'ปลดระงับ')+'</button> <button class="danger" data-op="delete" data-id="'+r.id+'">ลบ</button></td></tr>').join('')}
$('players').addEventListener('click',e=>{const b=e.target.closest('button[data-op]');if(!b)return;if(b.dataset.op==='toggle')togglePlayer(b.dataset.id,b.dataset.state);else if(b.dataset.op==='delete')deletePlayer(b.dataset.id)});
async function togglePlayer(id,status){if(!confirm('ยืนยันเปลี่ยนสถานะผู้เล่น?'))return;await req('/api/admin/players/'+id,{method:'PATCH',body:JSON.stringify({status:status==='active'?'blocked':'active'})});await loadAll()}
async function deletePlayer(id){if(!confirm('ลบผู้เล่นและคะแนนทั้งหมดอย่างถาวร?'))return;await req('/api/admin/players/'+id,{method:'DELETE'});await loadAll()}
boot();
</script></body></html>`}
export default {async fetch(request,env){const url=new URL(request.url),path=url.pathname,method=request.method;try{
  if(path==='/api/health')return json({ok:true,service:'thapkrit-adventure',time:now()});
  if(path==='/api/player'&&method==='POST'){
    const b=await readJSON(request);let nickname=String(b.nickname||'').trim().replace(/[<>]/g,'');const phone=String(b.phone||'').replace(/[\s-]/g,'');if(!validateNickname(nickname))return err('ชื่อผู้เล่นต้องยาว 2–24 ตัวอักษร');if(!validatePhone(phone)||b.consent!==true)return err('กรุณาใส่เบอร์โทร 10 หลักและยินยอมข้อมูล');
    
const id=randomId(),token=randomToken();await env.DB.prepare("INSERT INTO players(id,nickname,session_hash,phone,prize_consent_at) VALUES(?,?,?,?,datetime('now'))").bind(id,nickname,await sha256(token),phone).run();return json({ok:true,id,nickname,token});

  }
  if(path==='/api/player/me'&&method==='GET'){const p=await requirePlayer(request,env);if(!p)return err('กรุณาเข้าสู่เกมอีกครั้ง',401);return json({ok:true,player:p});}
  if(path==='/api/settings'&&method==='GET'){
    const rows=await env.DB.prepare('SELECT stage,difficulty FROM stage_settings ORDER BY stage').all();
    const values=[1,1,1,1,1];for(const r of rows.results||[])if(r.stage>=1&&r.stage<=5)values[r.stage-1]=r.difficulty;
    return json({ok:true,difficulty:values});
  }
  if(path==='/api/player/profile'&&method==='PUT'){
    const p=await requirePlayer(request,env);if(!p)return err('กรุณาลงทะเบียนใหม่',401);
    const b=await readJSON(request),nickname=String(b.nickname||'').trim().replace(/[<>]/g,''),phone=String(b.phone||'').replace(/[\s-]/g,'');
    if(!validateNickname(nickname)||!validatePhone(phone)||b.consent!==true)return err('กรุณากรอกชื่อ เบอร์โทร และยินยอม',400);
    await env.DB.prepare("UPDATE players SET nickname=?,phone=?,prize_consent_at=datetime('now'),last_seen=datetime('now') WHERE id=?").bind(nickname,phone,p.id).run();
    return json({ok:true});
  }
  if(path==='/api/runs'&&method==='POST'){
    const p=await requirePlayer(request,env);if(!p)return err('ไม่พบเซสชันผู้เล่น',401);
    const b=await readJSON(request),stage=Number(b.stage),score=Number(b.score),coins=Number(b.coins||0),elapsed=Number(b.elapsed||0);
    if(![stage,score,coins,elapsed].every(Number.isSafeInteger)||stage<1||stage>5||score<0||score>100000||coins<0||coins>10000||elapsed<0||elapsed>1e7)return err('ข้อมูลคะแนนไม่ถูกต้อง');
    const limit=await env.DB.prepare("SELECT COUNT(*) n FROM runs WHERE player_id=? AND created_at>datetime('now','-1 minute')").bind(p.id).first();if(limit.n>=12)return err('ส่งคะแนนถี่เกินไป กรุณาลองอีกครั้ง',429);
    await env.DB.batch([env.DB.prepare('INSERT INTO runs(player_id,stage,score,coins,elapsed) VALUES(?,?,?,?,?)').bind(p.id,stage,score,coins,elapsed),env.DB.prepare("UPDATE players SET last_seen=datetime('now') WHERE id=?").bind(p.id)]);
    return json({ok:true,unverified:true});
  }
  if(path==='/api/leaderboard'&&method==='GET'){
    const stage=Number(url.searchParams.get('stage')||0);if(!Number.isInteger(stage)||stage<0||stage>5)return err('ด่านไม่ถูกต้อง');
    const sql=stage?'SELECT p.nickname,r.stage,MAX(r.score) score FROM runs r JOIN players p ON p.id=r.player_id WHERE p.status=? AND r.stage=? GROUP BY p.id ORDER BY score DESC LIMIT 30':'SELECT p.nickname,SUM(best.score) score FROM players p JOIN (SELECT player_id,stage,MAX(score) score FROM runs GROUP BY player_id,stage) best ON best.player_id=p.id WHERE p.status=? GROUP BY p.id ORDER BY score DESC LIMIT 30';
    const rs=stage?await env.DB.prepare(sql).bind('active',stage).all():await env.DB.prepare(sql).bind('active').all();return json({ok:true,stage,top:rs.results});
  }
  if(path==='/admin'||path==='/admin/'){return new Response(panel(),{headers:{'content-type':'text/html;charset=utf-8','cache-control':'no-store','x-frame-options':'DENY','content-security-policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'"}})}
  if(path==='/api/admin/login'&&method==='POST'){
    if(!env.ADMIN_PASSWORD||env.ADMIN_PASSWORD.length<16)return err('ยังไม่ได้ตั้ง ADMIN_PASSWORD ที่ Cloudflare',503);
    const ipHash=await sha256((request.headers.get('CF-Connecting-IP')||'local')+':'+env.ADMIN_PASSWORD);const failed=await env.DB.prepare("SELECT COUNT(*) n FROM admin_login_attempts WHERE ip_hash=? AND created_at>datetime('now','-1 hour')").bind(ipHash).first();if(failed.n>=10)return err('ล็อกอินผิดหลายครั้ง กรุณารอ 1 ชั่วโมง',429);const b=await readJSON(request);const hash=await sha256(String(b.password||'')),valid=eq(hash,await sha256(env.ADMIN_PASSWORD));if(!valid){await env.DB.prepare('INSERT INTO admin_login_attempts(ip_hash) VALUES(?)').bind(ipHash).run();return err('รหัสผ่านไม่ถูกต้อง',401);}await env.DB.prepare('DELETE FROM admin_login_attempts WHERE ip_hash=?').bind(ipHash).run();
    const exp=String(Date.now()+8*3600*1000),sig=await hmac(env.ADMIN_PASSWORD,exp);return json({ok:true},200,{'set-cookie':`tk_admin=${exp}.${sig}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`});
  }
  if(path==='/api/admin/logout'&&method==='POST')return json({ok:true},200,{'set-cookie':'tk_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'});
  if(path.startsWith('/api/admin/')){
    if(!await isAdmin(request,env))return err('กรุณาเข้าสู่ระบบ Admin',401);
    if(path==='/api/admin/settings'&&method==='PUT'){
      const b=await readJSON(request);if(!Array.isArray(b.difficulty)||b.difficulty.length!==5||!b.difficulty.every(x=>allowedDifficulty.includes(x)))return err('กรุณาเลือกระดับความยากทั้ง 5 ด่าน');
      await env.DB.batch(b.difficulty.map((difficulty,i)=>env.DB.prepare('INSERT INTO stage_settings(stage,difficulty) VALUES(?,?) ON CONFLICT(stage) DO UPDATE SET difficulty=excluded.difficulty').bind(i+1,difficulty)));
      await env.DB.prepare('INSERT INTO audit_log(action,detail) VALUES(?,?)').bind('difficulty_update',JSON.stringify(b.difficulty)).run();
      return json({ok:true});
    }
    if(path==='/api/admin/summary'&&method==='GET'){
      const [stats,players,runs,top]=await Promise.all([
        env.DB.prepare("SELECT (SELECT COUNT(*) FROM players) players,(SELECT COUNT(*) FROM players WHERE status='active') active,(SELECT COUNT(*) FROM runs) runs,COALESCE((SELECT MAX(score) FROM runs),0) maxScore").first(),
        env.DB.prepare("SELECT p.id,p.nickname,p.phone,p.prize_consent_at,p.status,p.created_at,p.last_seen,COUNT(DISTINCT best.stage) stages_cleared,COALESCE(SUM(best.score),0) total_best FROM players p LEFT JOIN (SELECT player_id,stage,MAX(score) score FROM runs GROUP BY player_id,stage) best ON best.player_id=p.id GROUP BY p.id ORDER BY p.created_at DESC LIMIT 500").all(),
        env.DB.prepare('SELECT p.nickname,r.stage,r.score,r.coins,r.created_at FROM runs r JOIN players p ON p.id=r.player_id ORDER BY r.id DESC LIMIT 50').all(),
        env.DB.prepare('SELECT p.nickname,r.stage,r.score,r.created_at FROM runs r JOIN players p ON p.id=r.player_id ORDER BY r.score DESC LIMIT 20').all()
      ]);const sr=await env.DB.prepare('SELECT stage,difficulty FROM stage_settings ORDER BY stage').all();const difficulty=[1,1,1,1,1];for(const r of sr.results||[])difficulty[r.stage-1]=r.difficulty;return json({ok:true,stats,players:players.results,runs:runs.results,top:top.results,difficulty});
    }
    const m=path.match(/^\/api\/admin\/players\/([0-9a-f-]{36})$/);if(m){const id=m[1];if(method==='PATCH'){const b=await readJSON(request);if(!['active','blocked'].includes(b.status))return err('สถานะไม่ถูกต้อง');await env.DB.prepare('UPDATE players SET status=? WHERE id=?').bind(b.status,id).run();await env.DB.prepare('INSERT INTO audit_log(action,detail) VALUES(?,?)').bind('player_status',id+':'+b.status).run();return json({ok:true});}if(method==='DELETE'){await env.DB.batch([env.DB.prepare('DELETE FROM runs WHERE player_id=?').bind(id),env.DB.prepare('DELETE FROM players WHERE id=?').bind(id)]);await env.DB.prepare('INSERT INTO audit_log(action,detail) VALUES(?,?)').bind('player_delete',id).run();return json({ok:true});}}
    return err('ไม่พบ API',404);
  }
  if(path.startsWith('/api/'))return err('ไม่พบ API',404);
  return env.ASSETS ? env.ASSETS.fetch(request) : new Response("Backend พร้อมแล้ว — รออัปโหลดไฟล์เกมในขั้นถัดไป", {status:200,headers:{"content-type":"text/plain;charset=utf-8"}});
}catch(e){console.error('Worker error',e);return err('เกิดข้อผิดพลาดของระบบ',500)}}};
