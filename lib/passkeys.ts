import {generateRegistrationOptions,verifyRegistrationResponse,generateAuthenticationOptions,verifyAuthenticationResponse} from '@simplewebauthn/server';
export const ORIGIN='https://aleph-passkey-intro.rlatmdgus4141.chatgpt.site';
export const COOKIE='__Host-t08_session',FLOW='__Host-t08_flow';
export const SESSION_MS=12*60*60*1000,CHALLENGE_MS=5*60*1000;
type DB=any;type Row=any;type Config={origin:string,rpID:string};
export class HttpError extends Error{status:number;constructor(status:number,message:string){super(message);this.status=status;}}
export const q=(db:DB,sql:string,...params:any[])=>db.prepare(sql).bind(...params);
export const b64=(a:Uint8Array)=>btoa(String.fromCharCode(...a)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
export const bytes=(s:string)=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const random=()=>b64(crypto.getRandomValues(new Uint8Array(32)));
export async function digest(s:string){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))).map(x=>x.toString(16).padStart(2,'0')).join('');}
function cookie(req:Request,name:string){return (req.headers.get('Cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='))?.slice(name.length+1)||'';}
const setCookie=(name:string,value:string,seconds:number)=>`${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${seconds}`;
function json(value:any,status=200,cookies:string[]=[]){const headers=new Headers({'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});for(const c of cookies)headers.append('Set-Cookie',c);return new Response(JSON.stringify(value),{status,headers});}
export async function session(db:DB,req:Request,required=true){const raw=cookie(req,COOKIE);if(!raw){if(required)throw new HttpError(401,'패스키 로그인이 필요합니다.');return null;}
const s=await q(db,'SELECT s.*,u.username FROM passkey_sessions s JOIN passkey_users u ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?',await digest(raw),new Date().toISOString()).first();if(!s&&required)throw new HttpError(401,'세션이 만료되었거나 로그아웃되었습니다.');return s;}
function recent(s:Row){if(Date.now()-Date.parse(s.created_at)>5*60*1000)throw new HttpError(403,'패스키 관리 전 다시 패스키로 로그인해 주세요.');}
async function newSession(db:DB,uid:string,cid:string){const raw=random(),now=new Date().toISOString();await q(db,'INSERT INTO passkey_sessions(token_hash,user_id,credential_id,created_at,expires_at) VALUES (?,?,?,?,?)',await digest(raw),uid,cid,now,new Date(Date.now()+SESSION_MS).toISOString()).run();return setCookie(COOKIE,raw,SESSION_MS/1000);}
async function throttle(db:DB,key:string){const now=new Date().toISOString(),reset=new Date(Date.now()+15*60*1000).toISOString();const r=await q(db,'INSERT INTO passkey_limits(key,count,reset_at) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN reset_at<=? THEN 1 ELSE count+1 END,reset_at=CASE WHEN reset_at<=? THEN excluded.reset_at ELSE reset_at END RETURNING count',key,reset,now,now).first();if(r.count>30)throw new HttpError(429,'요청이 많습니다. 잠시 뒤 다시 시도해 주세요.');}
async function consume(db:DB,req:Request,id:string,purpose:string){if(typeof id!=='string')throw new HttpError(400,'질문 ID가 필요합니다.');const flow=cookie(req,FLOW);if(!flow)throw new HttpError(401,'등록·로그인 흐름을 다시 시작해 주세요.');const row=await q(db,'DELETE FROM passkey_challenges WHERE id=? AND flow_hash=? AND purpose=? RETURNING *',id,await digest(flow),purpose).first();if(!row)throw new HttpError(409,'이미 사용했거나 취소된 질문입니다. 새로 시작해 주세요.');if(Date.parse(row.expires_at)<=Date.now())throw new HttpError(410,'질문이 만료되었습니다. 새로 시작해 주세요.');return row;}
function validName(v:any){if(typeof v!=='string'||!v.trim()||v.length>60)throw new HttpError(400,'패스키 이름은 1~60자로 입력하세요.');return v.trim();}
const storageTypes=['Windows Hello','Google 비밀번호 관리자','Apple 암호·키체인','보안 키','기타·확인 중'];
export async function handle(req:Request,db:DB,config:Config={origin:ORIGIN,rpID:new URL(ORIGIN).hostname}):Promise<Response>{try{
const url=new URL(req.url),path=url.pathname;
if(req.method==='GET'){
 if(path==='/api/private'){const s=await session(db,req);const target=url.searchParams.get('user_id');if(target&&target!==s.user_id)throw new HttpError(403,'다른 계정의 비공개 자료를 볼 수 없습니다.');const rows=(await q(db,'SELECT id,title,body FROM private_notes WHERE user_id=? ORDER BY id',s.user_id).all()).results;return json({synthetic:true,owner:s.user_id,items:rows});}
 if(path==='/api/passkeys'){const s=await session(db,req,false);if(!s)return json({authenticated:false});const rows=(await q(db,'SELECT id,name,storage,device_type,backed_up,created_at,public_key FROM passkey_credentials WHERE user_id=? ORDER BY created_at,id',s.user_id).all()).results;return json({authenticated:true,user:{id:s.user_id,username:s.username},passkeys:rows,sessionExpires:s.expires_at});}
 throw new HttpError(404,'주소를 찾을 수 없습니다.');
}
if(req.method!=='POST')throw new HttpError(405,'허용하지 않는 요청입니다.');
if(req.headers.get('Origin')!==config.origin)throw new HttpError(403,'이 페이지에서 시작한 요청만 허용합니다.');
if(!req.headers.get('Content-Type')?.startsWith('application/json'))throw new HttpError(415,'JSON 요청이 필요합니다.');
const text=await req.text();if(text.length>65000)throw new HttpError(413,'요청이 너무 큽니다.');let x:any;try{x=JSON.parse(text)}catch{throw new HttpError(400,'잘못된 JSON입니다.');}
if(!x||typeof x!=='object')throw new HttpError(400,'잘못된 요청입니다.');const action=x.action;
if(path==='/api/private'){const s=await session(db,req);const rows=(await q(db,'SELECT id,title,body FROM private_notes WHERE user_id=? ORDER BY id',s.user_id).all()).results;return json({synthetic:true,owner:s.user_id,items:rows});}
if(path!=='/api/passkeys')throw new HttpError(404,'주소를 찾을 수 없습니다.');
if(action==='cancel'){const flow=cookie(req,FLOW);if(flow)await q(db,'DELETE FROM passkey_challenges WHERE id=? AND flow_hash=?',x.flowId,await digest(flow)).run();return json({cancelled:true,credentialSaved:false},200,[setCookie(FLOW,'',0)]);}
if(action==='register-options'){
 const s=await session(db,req,false);if(s)recent(s);const username=s?.username||(typeof x.username==='string'?x.username.trim().toLowerCase():'');if(!/^[a-z0-9_-]{4,40}$/.test(username))throw new HttpError(400,'계정 별칭은 영문 소문자·숫자·_·- 4~40자로 입력하세요.');
 if(!s&&await q(db,'SELECT id FROM passkey_users WHERE username=?',username).first())throw new HttpError(409,'이미 있는 계정입니다. 패스키로 로그인하세요.');
 await throttle(db,'register:'+await digest((req.headers.get('cf-connecting-ip')||'local')+':'+username));
 const name=validName(x.name);if(!storageTypes.includes(x.storage))throw new HttpError(400,'패스키를 저장할 곳을 선택하세요.');
 const uid=s?.user_id||crypto.randomUUID();const old=s?(await q(db,'SELECT id,transports FROM passkey_credentials WHERE user_id=?',uid).all()).results:[];
 const options=await generateRegistrationOptions({rpName:'나만의 소개 메모',rpID:config.rpID,userName:username,userID:new TextEncoder().encode(uid),attestationType:'none',supportedAlgorithmIDs:[-7,-257],excludeCredentials:old.map((c:Row)=>({id:c.id,transports:JSON.parse(c.transports)})),authenticatorSelection:{residentKey:'required',userVerification:'required'}});
 const id=crypto.randomUUID(),flow=random(),at=new Date().toISOString();await q(db,'DELETE FROM passkey_challenges WHERE expires_at<=?',at).run();
 await q(db,'INSERT INTO passkey_challenges(id,challenge,flow_hash,purpose,user_id,username,name,storage,session_hash,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',id,options.challenge,await digest(flow),'register',uid,username,name,x.storage,s?.token_hash||null,at,new Date(Date.now()+CHALLENGE_MS).toISOString()).run();return json({flowId:id,options},200,[setCookie(FLOW,flow,CHALLENGE_MS/1000)]);
}
if(action==='register-verify'){
 const c=await consume(db,req,x.flowId,'register');if(c.session_hash){const s=await session(db,req);if(s.token_hash!==c.session_hash||s.user_id!==c.user_id)throw new HttpError(403,'등록을 시작한 계정으로 다시 로그인하세요.');recent(s);}
 let v:any;try{v=await verifyRegistrationResponse({response:x.response,expectedChallenge:c.challenge,expectedOrigin:config.origin,expectedRPID:config.rpID,requireUserVerification:true,supportedAlgorithmIDs:[-7,-257]})}catch{throw new HttpError(401,'패스키 등록 확인에 실패했습니다. 새로 시작해 주세요.');}
 if(!v.verified||!v.registrationInfo)throw new HttpError(401,'패스키 등록 확인에 실패했습니다.');const i=v.registrationInfo,k=i.credential,at=new Date().toISOString();
 const jobs=[];if(!c.session_hash){jobs.push(q(db,'INSERT INTO passkey_users(id,username,created_at) VALUES (?,?,?)',c.user_id,c.username,at));for(const [n,title,body] of [[1,'프로젝트 메모','가상 프로젝트 '+c.username+': 장비 점검 절차를 정리한다.'],[2,'지원 준비 목록','가상 조직 A·B의 공개 채용 정보를 비교한다.'],[3,'개인 회고','가상 회고 '+c.username+': 근거를 먼저 확인하고 결론을 적는다.']] as any[])jobs.push(q(db,'INSERT INTO private_notes(id,user_id,title,body) VALUES (?,?,?,?)',crypto.randomUUID(),c.user_id,title,body));}
 jobs.push(q(db,'INSERT INTO passkey_credentials(id,user_id,public_key,counter,transports,name,storage,device_type,backed_up,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)',k.id,c.user_id,b64(k.publicKey),k.counter,JSON.stringify(k.transports||[]),c.name,c.storage,i.credentialDeviceType,i.credentialBackedUp?1:0,at));
 try{await db.batch(jobs)}catch{throw new HttpError(409,'이미 등록된 계정 또는 패스키입니다. 저장하지 않았습니다.');}
 return json({verified:true,accountCreated:!c.session_hash,credential:{id:k.id,name:c.name,storage:c.storage,public_key:b64(k.publicKey),created_at:at},privateKeyReceived:false},200,[...(c.session_hash?[]:[await newSession(db,c.user_id,k.id)]),setCookie(FLOW,'',0)]);
}
if(action==='login-options'){
 const username=typeof x.username==='string'?x.username.trim().toLowerCase():'';await throttle(db,'login:'+await digest((req.headers.get('cf-connecting-ip')||'local')+':'+username));
 const user=await q(db,'SELECT id,username FROM passkey_users WHERE username=?',username).first();if(!user)throw new HttpError(401,'이 별칭으로 등록한 패스키가 없습니다.');const keys=(await q(db,'SELECT id,transports FROM passkey_credentials WHERE user_id=?',user.id).all()).results;if(!keys.length)throw new HttpError(401,'등록된 패스키가 없습니다. 비밀번호나 복구 우회는 제공하지 않습니다.');
 const options=await generateAuthenticationOptions({rpID:config.rpID,userVerification:'required',allowCredentials:keys.map((c:Row)=>({id:c.id,transports:JSON.parse(c.transports)}))});const id=crypto.randomUUID(),flow=random(),at=new Date().toISOString();
 await q(db,'DELETE FROM passkey_challenges WHERE expires_at<=?',at).run();await q(db,'INSERT INTO passkey_challenges(id,challenge,flow_hash,purpose,user_id,username,name,storage,session_hash,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',id,options.challenge,await digest(flow),'login',user.id,user.username,'','',null,at,new Date(Date.now()+CHALLENGE_MS).toISOString()).run();return json({flowId:id,options},200,[setCookie(FLOW,flow,CHALLENGE_MS/1000)]);
}
if(action==='login-verify'){
 const c=await consume(db,req,x.flowId,'login');const k=await q(db,'SELECT * FROM passkey_credentials WHERE id=? AND user_id=?',x.response?.id,c.user_id).first();if(!k)throw new HttpError(401,'사용할 수 없는 패스키입니다.');
 if(x.response?.response?.userHandle&&x.response.response.userHandle!==b64(new TextEncoder().encode(c.user_id)))throw new HttpError(401,'계정과 패스키가 일치하지 않습니다.');
 let v:any;try{v=await verifyAuthenticationResponse({response:x.response,expectedChallenge:c.challenge,expectedOrigin:config.origin,expectedRPID:config.rpID,credential:{id:k.id,publicKey:bytes(k.public_key),counter:k.counter,transports:JSON.parse(k.transports)},requireUserVerification:true})}catch{throw new HttpError(401,'서명 확인에 실패했습니다. 새로 로그인해 주세요.');}if(!v.verified)throw new HttpError(401,'서명 확인에 실패했습니다.');
 const r=await q(db,'UPDATE passkey_credentials SET counter=? WHERE id=? AND counter=?',v.authenticationInfo.newCounter,k.id,k.counter).run();if(r.meta.changes!==1)throw new HttpError(409,'인증 상태가 달라졌습니다. 다시 로그인하세요.');
 return json({verified:true},200,[await newSession(db,c.user_id,k.id),setCookie(FLOW,'',0)]);
}
if(action==='logout'){const raw=cookie(req,COOKIE);if(raw)await q(db,'DELETE FROM passkey_sessions WHERE token_hash=?',await digest(raw)).run();return json({loggedOut:true},200,[setCookie(COOKIE,'',0),setCookie(FLOW,'',0)]);}
if(action==='delete-passkey'){
 const s=await session(db,req);recent(s);const k=await q(db,'SELECT id FROM passkey_credentials WHERE id=? AND user_id=?',x.id,s.user_id).first();if(!k)throw new HttpError(403,'내 패스키만 삭제할 수 있습니다.');const count=(await q(db,'SELECT COUNT(*) AS n FROM passkey_credentials WHERE user_id=?',s.user_id).first()).n;if(count===1&&x.confirmLast!==true)throw new HttpError(409,'마지막 패스키를 지우면 계정에 다시 들어갈 수 없습니다. 명시적으로 확인해 주세요.');
 await db.batch([q(db,'DELETE FROM passkey_challenges WHERE user_id=?',s.user_id),q(db,'DELETE FROM passkey_credentials WHERE id=? AND user_id=?',x.id,s.user_id)]);const alive=await session(db,req,false);return json({deleted:true,remaining:count-1,loggedOut:!alive,warning:count===1?'남은 패스키가 없어 재로그인할 수 없습니다.':null},200,alive?[]:[setCookie(COOKIE,'',0)]);
}
if(action==='delete-account'){const s=await session(db,req);recent(s);if(x.confirm!==true)throw new HttpError(400,'계정 삭제 확인이 필요합니다.');await db.batch([q(db,'DELETE FROM passkey_challenges WHERE user_id=?',s.user_id),q(db,'DELETE FROM passkey_users WHERE id=?',s.user_id)]);return json({deleted:true},200,[setCookie(COOKIE,'',0)]);}
throw new HttpError(400,'알 수 없는 요청입니다.');
}catch(e){return json({error:e instanceof HttpError?e.message:'처리하지 못했습니다. 잠시 뒤 다시 시도해 주세요.'},e instanceof HttpError?e.status:500);}}
