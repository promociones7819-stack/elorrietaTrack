import {digest} from './password.js';
const DAY=86400000;
// Separate purpose key derived from the existing server-only secret; never expose it.
async function registerKey(env){const jwk=JSON.parse(env.LICENSE_PRIVATE_JWK);const raw=await crypto.subtle.digest('SHA-256',new TextEncoder().encode('elorrietatrack:license-register:v1:'+jwk.d));return crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']);}
async function seal(value,env,id){const iv=crypto.getRandomValues(new Uint8Array(12)),bytes=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:new TextEncoder().encode(id)},await registerKey(env),new TextEncoder().encode(value));return btoa(String.fromCharCode(...iv,...new Uint8Array(bytes)));}
async function unseal(value,env,id){if(!value)return null;try{const bytes=Uint8Array.from(atob(value),c=>c.charCodeAt(0));return new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.slice(0,12),additionalData:new TextEncoder().encode(id)},await registerKey(env),bytes.slice(12)));}catch{return null;}}
const validEmail=value=>typeof value==='string'&&value.length<=254&&(!value||/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value));
// Prefix, case, whitespace and common hyphen separators are presentation only.
export function normalizeLicenseKey(value){
 if(typeof value!=='string')return null;
 const compact=value.toUpperCase().replace(/[\s\u200B-\u200D\uFEFF\-\u2010-\u2015\u2212]/g,'');
 const tier=compact.startsWith('PRE')?'PRE':'EEM';
 const token=compact.replace(/^(EEM|PRE)/,'');
 return /^[A-F0-9]{32}$/.test(token)?tier+'-'+token:null;
}
export async function licenseAPI(request,env,path,json){
 const raw=await request.text();if(raw.length>4096)return json({error:'Solicitud demasiado grande.'},413);const b=JSON.parse(raw);
 if(path==='/api/license/activate'){
  if(typeof b.key!=='string'||b.key.length>100||!b.device||b.device.length!==64||typeof b.publicKey!=='string'||b.publicKey.length>1000)return json({error:'Datos de activación incorrectos.'},400);
  const normalized=normalizeLicenseKey(b.key);
  if(!normalized)return json({error:'La clave debe contener 32 letras y números. Copia la clave completa; los prefijos EEM- y PRE- son opcionales.'},400);
  let keyHash=await digest(normalized);
  if(!/^\s*(EEM|PRE)/i.test(b.key)&&normalized.startsWith('EEM-')){const present=await env.AUTH.prepare('SELECT id FROM licenses WHERE key_hash=?').bind(keyHash).first();if(!present)keyHash=await digest('PRE-'+normalized.slice(4));}
  // A consumed key can never activate again, including on the same device.
  const r=await env.AUTH.prepare('UPDATE licenses SET device=?,public_key=?,activated_at=? WHERE key_hash=? AND device IS NULL AND active=1 AND expires_at>? RETURNING *').bind(b.device,b.publicKey,Date.now(),keyHash,Date.now()).first();
  if(!r){
   const existing=await env.AUTH.prepare('SELECT active,expires_at,device FROM licenses WHERE key_hash=?').bind(keyHash).first();
   const error=!existing?'No se encuentra esta clave. Revisa que la hayas copiado completa.':!existing.active?'Esta licencia está bloqueada. Contacta con el administrador.':existing.expires_at<=Date.now()?'Esta licencia ha caducado. El administrador debe renovar su fecha.':'Esta clave ya se utilizó. En el equipo activado pulsa Comprobar renovación; para otro equipo necesitas una clave nueva.';
   return json({error},409);
  }
  return issue(r,env,json);
 }
 if(path==='/api/license/refresh'){
  const r=await env.AUTH.prepare('SELECT * FROM licenses WHERE id=?').bind(String(b.id||'').slice(0,100)).first();
  if(!r||!r.active||r.expires_at<=Date.now())return json({error:'Licencia caducada o bloqueada. Contacta con el administrador.'},403);
  if(!Number.isSafeInteger(b.time)||Math.abs(Date.now()-b.time)>300000||typeof b.nonce!=='string'||b.nonce.length>100)return json({error:'Solicitud caducada. Comprueba la fecha del equipo.'},400);
  try{
   const key=await crypto.subtle.importKey('jwk',JSON.parse(r.public_key),{name:'Ed25519'},false,['verify']);
   const msg=new TextEncoder().encode(JSON.stringify([r.id,b.time,b.nonce]));
   if(!await crypto.subtle.verify('Ed25519',key,Uint8Array.from(atob(b.signature),c=>c.charCodeAt(0)),msg))throw Error();
  }catch{return json({error:'Este equipo no corresponde a la licencia.'},403);}
  await env.AUTH.prepare('DELETE FROM license_nonces WHERE created_at<?').bind(Date.now()-600000).run();
  const n=await env.AUTH.prepare('INSERT OR IGNORE INTO license_nonces(nonce,created_at) VALUES(?,?)').bind(b.nonce,Date.now()).run();
  if(!n.meta.changes)return json({error:'Solicitud ya utilizada.'},409);
  return issue(r,env,json);
 }
 return json({error:'No encontrado.'},404);
}
async function issue(r,env,json){
 const now=Date.now(),payload=JSON.stringify({id:r.id,label:r.label,device:r.device,publicKey:r.public_key,plan:r.plan==='premium'?'premium':'basic',apiBase:env.PUBLIC_ORIGIN||new URL('https://elorrietatrack.promociones7819.workers.dev').origin,expiresAt:r.expires_at,issuedAt:now,offlineUntil:Math.min(r.expires_at,now+30*DAY)});
 const key=await crypto.subtle.importKey('jwk',JSON.parse(env.LICENSE_PRIVATE_JWK),{name:'Ed25519'},false,['sign']);
 const signature=await crypto.subtle.sign('Ed25519',key,new TextEncoder().encode(payload));
 return json({payload,signature:btoa(String.fromCharCode(...new Uint8Array(signature)))});
}
export async function adminLicenses(request,env,path,json){
 if(path==='/api/admin/licenses'&&request.method==='GET'){
  const {results}=await env.AUTH.prepare('SELECT id,label,owner_email,key_ciphertext,plan,expires_at,active,activated_at,created_at FROM licenses ORDER BY created_at DESC').all();return json({licenses:await Promise.all(results.map(async({key_ciphertext,...row})=>({...row,key:await unseal(key_ciphertext,env,row.id)})))});
 }
 const deleteId=path.match(/^\/api\/admin\/licenses\/([a-f0-9-]+)$/)?.[1];
 if(deleteId&&request.method==='DELETE'){
  const result=await env.AUTH.prepare('DELETE FROM licenses WHERE id=?').bind(deleteId).run();
  return result.meta.changes?json({ok:true}):json({error:'La licencia ya no existe.'},404);
 }
 const b=await request.json();
 if(path==='/api/admin/licenses'&&request.method==='POST'){
  if(typeof b.label!=='string'||!b.label.trim()||b.label.length>150||!Number.isSafeInteger(b.expiresAt)||b.expiresAt<=Date.now())return json({error:'Indica un nombre y una fecha futura.'},400);
  const email=String(b.email||'').trim().toLowerCase();if(!validEmail(email))return json({error:'Correo del destinatario incorrecto.'},400);
  const plan=b.plan==='premium'?'premium':'basic';
  const key=(plan==='premium'?'PRE-':'EEM-')+crypto.randomUUID().replaceAll('-','').toUpperCase(),id=crypto.randomUUID();
  await env.AUTH.prepare('INSERT INTO licenses(id,key_hash,label,expires_at,created_at,plan,key_ciphertext,owner_email) VALUES(?,?,?,?,?,?,?,?)').bind(id,await digest(key),b.label.trim(),b.expiresAt,Date.now(),plan,await seal(key,env,id),email).run();
  return json({key,id},201);
 }
 const id=path.match(/^\/api\/admin\/licenses\/([a-f0-9-]+)$/)?.[1];
 if(id&&request.method==='PATCH'){
  if(typeof b.key==='string'){
   const row=await env.AUTH.prepare('SELECT key_hash FROM licenses WHERE id=?').bind(id).first();let key=normalizeLicenseKey(b.key);if(!row||!key)return json({error:'Clave incorrecta.'},400);
   if(await digest(key)!==row.key_hash&&key.startsWith('EEM-')&&!/^\s*EEM/i.test(b.key))key='PRE-'+key.slice(4);
   if(await digest(key)!==row.key_hash)return json({error:'La clave no corresponde a esta licencia.'},400);
   await env.AUTH.prepare('UPDATE licenses SET key_ciphertext=? WHERE id=?').bind(await seal(key,env,id),id).run();
  }else if(typeof b.email==='string'){
   const email=b.email.trim().toLowerCase();if(!validEmail(email))return json({error:'Correo incorrecto.'},400);
   await env.AUTH.prepare('UPDATE licenses SET owner_email=? WHERE id=?').bind(email,id).run();
  }else if(['basic','premium'].includes(b.plan))await env.AUTH.prepare('UPDATE licenses SET plan=? WHERE id=?').bind(b.plan,id).run();
  else if(typeof b.active==='boolean')await env.AUTH.prepare('UPDATE licenses SET active=? WHERE id=?').bind(b.active?1:0,id).run();
  else if(Number.isSafeInteger(b.expiresAt)&&b.expiresAt>Date.now())await env.AUTH.prepare('UPDATE licenses SET expires_at=? WHERE id=?').bind(b.expiresAt,id).run();
  else return json({error:'Fecha incorrecta.'},400);
  return json({ok:true});
 }
 return json({error:'No encontrado.'},404);
}
