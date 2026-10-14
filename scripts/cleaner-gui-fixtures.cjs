'use strict';
// Test-owned files only. Serialized manifests never grant deletion authority.
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const {validateHome,inspectPath,validateSnapshot}=require('../src/core/path-policy.cjs');
const sets=new WeakMap(),roles=['trash','permanent','cancel','changed','recent','unselected'];
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function cacheRoot(home,platform){if(!['darwin','win32'].includes(platform))throw Error('PLATFORM_UNAVAILABLE');return path.join(home,...(platform==='darwin'?['Library','Caches','pip']:['AppData','Local','pip','Cache']));}
async function directory(file){const s=await fs.lstat(file);if(!s.isDirectory()||s.isSymbolicLink())throw Error('FIXTURE_DIRECTORY_IDENTITY');if(process.platform==='win32'){const p=await require('../src/platform/windows-native.cjs').getDefaultWindowsBridge().inspect(file);if(!p.ordinary||p.reparse||!p.ownedByCurrentUser)throw Error('FIXTURE_DIRECTORY_OWNER');}else if(s.uid!==process.getuid())throw Error('FIXTURE_DIRECTORY_OWNER');return {dev:String(s.dev),ino:String(s.ino)};}
async function createFixtures({home,platform=process.platform,onCreated=async()=>{}}){
 if(platform!==process.platform)throw Error('PLATFORM_UNAVAILABLE');await validateHome(home);const root=cacheRoot(home,platform),createdDirectories=[],entries=[],proofs=new Map();
 async function ensure(target){let current=home;for(const piece of path.relative(home,target).split(path.sep)){current=path.join(current,piece);let made=false;try{await fs.mkdir(current,{mode:0o700});made=true;}catch(e){if(e.code!=='EEXIST')throw e;}const identity=await directory(current);if(made)createdDirectories.push({file:current,identity});}}
 // Refuse links/foreign ancestors before creating any bytes beneath them.
 await ensure(root);
 for(const role of roles){const hash=crypto.randomBytes(28).toString('hex'),relativePath=path.posix.join('http-v2',...hash.slice(0,5),hash.slice(5)+'.body'),file=path.join(root,...relativePath.split('/'));await ensure(path.dirname(file));
  const bytes=crypto.randomBytes(4096);await fs.writeFile(file,bytes,{flag:'wx',mode:0o600});await onCreated({role,relativePath,file,sha256:sha(bytes),bytes:bytes.length});const age=new Date(Date.now()-(role==='recent'?0:8*86400000));await fs.utimes(file,age,age);const proof=await inspectPath({home,root,target:file,kind:'file'}),entry=Object.freeze({role,relativePath,file,sha256:sha(bytes),bytes:bytes.length});entries.push(entry);proofs.set(entry,{proof,sha256:entry.sha256});
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
module.exports={cacheRoot,createFixtures,verifyFixture,changeFixture,cleanupFixtures};
