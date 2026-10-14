'use strict';
// Test-owned files only. Serialized manifests never grant deletion authority.
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const {validateHome,inspectPath,validateSnapshot}=require('../src/core/path-policy.cjs');
const sets=new WeakMap(),roles=['trash','permanent','cancel','changed','recent','unselected'];
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function cacheRoot(home,platform){if(!['darwin','win32'].includes(platform))throw Error('PLATFORM_UNAVAILABLE');return path.join(home,...(platform==='darwin'?['Library','Caches','pip']:['AppData','Local','pip','Cache']));}
async function directory(file){const s=await fs.lstat(file);if(!s.isDirectory()||s.isSymbolicLink())throw Error('FIXTURE_DIRECTORY_IDENTITY');if(process.platform==='win32'){const p=await require('../src/platform/windows-native.cjs').getDefaultWindowsBridge().inspect(file);if(!p.ordinary||p.reparse||!p.ownedByCurrentUser)throw Error('FIXTURE_DIRECTORY_OWNER');}else if(s.uid!==process.getuid())throw Error('FIXTURE_DIRECTORY_OWNER');return {dev:String(s.dev),ino:String(s.ino)};}
function fixtureRelativePath(hash,platform=process.platform){if(typeof hash!=='string'||hash.length!==56||!/^[a-f0-9]{56}$/.test(hash)||!['darwin','win32'].includes(platform))throw Error('OWNED_FIXTURE_NAME_REQUIRED');return (platform==='win32'?path.win32:path.posix).join('http-v2',...hash.slice(0,5),hash.slice(5)+'.body');}
async function ownedAcl(file){if(process.platform!=='win32')return null;const {runProcess}=require('../src/platform/process.cjs');const result=await runProcess(path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe'),['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',path.join(__dirname,'cleaner-owned-acl-facts.ps1'),'-TargetPath',file],{timeoutMs:15000,maxOutput:16384});return JSON.parse(result.stdout.replace(/^\uFEFF/,''));}
async function createFixtures({home,platform=process.platform,onCreated=async()=>{}}){
 if(platform!==process.platform)throw Error('PLATFORM_UNAVAILABLE');await validateHome(home);const root=cacheRoot(home,platform),createdDirectories=[],entries=[],proofs=new Map();
 async function ensure(target){let current=home;for(const piece of path.relative(home,target).split(path.sep)){current=path.join(current,piece);let made=false;try{await fs.mkdir(current,{mode:0o700});made=true;}catch(e){if(e.code!=='EEXIST')throw e;}const identity=await directory(current);if(made)createdDirectories.push({file:current,identity});}}
 // Refuse links/foreign ancestors before creating any bytes beneath them.
 await ensure(root);
 for(const role of roles){const hash=crypto.randomBytes(28).toString('hex'),relativePath=fixtureRelativePath(hash,platform),file=path.join(root,...relativePath.split(path.sep));await ensure(path.dirname(file));
  const bytes=crypto.randomBytes(4096);await fs.writeFile(file,bytes,{flag:'wx',mode:0o600});await onCreated({role,relativePath,file,sha256:sha(bytes),bytes:bytes.length});const age=new Date(Date.now()-(role==='recent'?0:8*86400000));await fs.utimes(file,age,age);const proof=await inspectPath({home,root,target:file,kind:'file'}),entry=Object.freeze({role,relativePath,file,sha256:sha(bytes),bytes:bytes.length});entries.push(entry);proofs.set(entry,{proof,sha256:entry.sha256,sourceAcl:role==='permanent'?await ownedAcl(file):null});
 }
 const set=Object.freeze({home,root,platform,entries:Object.freeze(entries)});sets.set(set,{proofs,createdDirectories});return set;
}
async function verifyFixture(set,entry){const state=sets.get(set),saved=state?.proofs.get(entry);if(!saved)throw Error('FIXTURE_AUTHORITY');await fs.lstat(entry.file);const current=await validateSnapshot(saved.proof);if(!current.valid||sha(await fs.readFile(entry.file))!==saved.sha256)throw Error('FIXTURE_CHANGED');return {sha256:saved.sha256,bytes:(await fs.stat(entry.file)).size};}
async function changeFixture(set){const entry=set.entries.find(e=>e.role==='changed');await verifyFixture(set,entry);await fs.appendFile(entry.file,'owned GUI acceptance change');const proof=await inspectPath({home:set.home,root:set.root,target:entry.file,kind:'file'}),sha256=sha(await fs.readFile(entry.file));sets.get(set).proofs.set(entry,{proof,sha256});return {sha256,bytes:(await fs.stat(entry.file)).size};}
async function cleanupFixtures(set){const state=sets.get(set);if(!state)throw Error('FIXTURE_AUTHORITY');const remaining=[];for(const entry of set.entries){try{await verifyFixture(set,entry);remaining.push(entry);}catch(e){if(e.code!=='ENOENT')throw e;}}
 for(const entry of remaining){await verifyFixture(set,entry);await fs.unlink(entry.file);}
 // Only directories created by this call, still the same object and now empty.
 for(const item of [...state.createdDirectories].reverse()){try{if(JSON.stringify(await directory(item.file))!==JSON.stringify(item.identity))throw Error('FIXTURE_DIRECTORY_CHANGED');await fs.rmdir(item.file);}catch(e){if(!['ENOENT','ENOTEMPTY','EEXIST'].includes(e.code))throw e;}}
}
async function collectOwnedStageFacts(set,entry){
 const saved=sets.get(set)?.proofs.get(entry);if(!saved)throw Error('FIXTURE_AUTHORITY');const parent=path.dirname(entry.file);await directory(parent);const names=await fs.readdir(parent);if(names.length>64)throw Error('OWNED_STAGE_BOUND');const stages=[];
 for(const name of names){if(!/^\.laoyu-cleaner-stage-[a-f0-9-]{36}$/.test(name))continue;const folder=path.join(parent,name);await directory(folder);const manifest=path.join(folder,'manifest.json');let handle;
  try{await inspectPath({home:set.home,root:folder,target:manifest,kind:'file'});handle=await fs.open(manifest,require('node:fs').constants.O_RDONLY|(require('node:fs').constants.O_NOFOLLOW||0));const st=await handle.stat();if(!st.isFile()||st.nlink!==1||st.size>65536)throw Error('OWNED_STAGE_MANIFEST_BOUND');const buffer=Buffer.alloc(65537);const {bytesRead}=await handle.read(buffer,0,buffer.length,0);if(bytesRead>65536)throw Error('OWNED_STAGE_MANIFEST_BOUND');const record=JSON.parse(buffer.subarray(0,bytesRead).toString('utf8'));if(record.source?.path!==entry.file||record.source?.fingerprint!==saved.proof.fingerprint||record.directory!==folder||record.stagedPath!==path.join(folder,'payload'))continue;
   const fact={phase:record.phase,code:record.code,sourceIdentity:record.source.identity,sourceFingerprint:record.source.fingerprint,sourceAcl:saved.sourceAcl};try{const current=await inspectPath({home:set.home,root:folder,target:path.join(folder,'payload'),kind:'file'});fact.currentIdentity=current.identity;fact.currentFingerprint=current.fingerprint;fact.differences=Object.keys(record.source.identity).filter(key=>JSON.stringify(record.source.identity[key])!==JSON.stringify(current.identity[key]));fact.currentAcl=await ownedAcl(path.join(folder,'payload'));}catch(error){fact.inspectionError={code:error.code,message:String(error.message).slice(0,512)};}stages.push(fact);
  }catch(error){stages.push({inspectionError:{code:error.code,message:String(error.message).slice(0,512)}});}finally{await handle?.close();}
 }
 return {scope:'read-only bounded manifests and original inspector for exact in-memory owned fixture sibling stages',stages};
}
module.exports={fixtureRelativePath,cacheRoot,createFixtures,verifyFixture,changeFixture,cleanupFixtures,collectOwnedStageFacts};
