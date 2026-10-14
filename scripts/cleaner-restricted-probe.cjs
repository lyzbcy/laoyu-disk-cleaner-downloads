'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict');
function verifyIdentity(parent,child){
 assert.equal(child.user,parent.user);assert.equal(child.owner,child.user);assert.equal(child.integrity,'S-1-16-8192');assert.equal(child.elevated,false);assert.equal(child.adminMember,false);assert.equal(child.session,parent.session);assert.equal(child.profile,parent.profile);assert.equal(child.HOME,parent.HOME);assert.equal(child.USERPROFILE,parent.USERPROFILE);assert.equal(child.windowStation.toLowerCase(),'winsta0');assert.equal(child.desktop.toLowerCase(),'default');
 const logon=rows=>rows.filter(g=>(g.attributes>>>0 & 0xC0000000)>>>0===0xC0000000).map(g=>g.sid).sort();assert(logon(parent.groups).length>0);assert.deepEqual(logon(child.groups),logon(parent.groups));
 const ordinary=new Set([parent.user,'S-1-1-0','S-1-2-0','S-1-2-1','S-1-5-4','S-1-5-11','S-1-5-32-545','S-1-5-113']);
 for(const original of parent.groups){if(ordinary.has(original.sid)||(original.attributes&0x20)||((original.attributes&0xC0000000)>>>0)===0xC0000000)continue;const group=child.groups.find(g=>g.sid===original.sid);assert(group,'restricted group must remain represented as deny-only');assert.equal(group.attributes&4,0);assert.equal(group.attributes&0x10,0x10);}
 for(const privilege of child.privileges)if(privilege.attributes&2)assert.equal(privilege.name,'SeChangeNotifyPrivilege');return true;
}
function diagnosticFailure(error,phase){return {phase,code:error.code||'PROBE_FAILED',message:String(error.message||error).slice(0,4096),stack:String(error.stack||'').slice(0,8192),exitCode:Number.isInteger(error.exitCode)?error.exitCode:null,exitSignal:typeof error.exitSignal==='string'?error.exitSignal.slice(0,64):null,stdout:String(error.stdout||'').slice(0,16384),stderr:String(error.stderr||'').slice(0,16384)};}
async function main(){
 if(process.platform!=='win32'||process.env.GITHUB_ACTIONS!=='true'||process.env.CI!=='true')throw Error('ISOLATED_WINDOWS_CI_ONLY');
 const output=process.argv[2],expected=path.resolve(__dirname,'../verification/restricted-probe');if(output!==expected)throw Error('INVALID_OUTPUT');
 const report={ok:false,scope:'same-SID restricted-token read-only production path probe, not GUI acceptance',pid:process.pid,paths:[],startedAt:new Date().toISOString()};let bridge,phase='read-parent-token';
 try{
  const parent=JSON.parse(await fs.readFile(path.join(output,'parent-token.json'),'utf8'));
  const {runProcess}=require('../src/platform/process.cjs'),exe=path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe');
  phase='inspect-child-token';const observed=await runProcess(exe,['-NoProfile','-NonInteractive','-File',path.join(__dirname,'cleaner-restricted-probe.ps1'),'-Inspect'],{timeoutMs:30000,maxOutput:1024*1024});phase='parse-child-token';const identity=JSON.parse(observed.stdout.replace(/^\uFEFF/,''));report.identity=identity;phase='verify-child-token';verifyIdentity(parent,identity);
  phase='production-profile';const native=require('../src/platform/windows-native.cjs');bridge=native.getDefaultWindowsBridge();const home=await native.getCurrentHome();report.home=home;assert.equal(home,identity.profile);assert.equal(home,os.homedir());
  phase='production-home-policy';const policy=require('../src/core/path-policy.cjs');await policy.validateHome(home);report.productionHomeAccepted=true;
  for(const relative of ['', 'AppData','AppData/Local','AppData/Local/pip','AppData/Local/pip/Cache']){
   phase='production-ancestor';const file=path.join(home,...relative.split('/').filter(Boolean));report.currentPath=file;let proof;try{proof=await bridge.inspect(file);report.paths.push({file,proof});}catch(error){report.paths.push({file,error:error.code||error.message});throw error;}
   assert.equal(proof.ordinary,true);assert.equal(proof.reparse,false);assert.equal(proof.type,'directory');if(relative)assert.equal(proof.ownedByCurrentUser,true,'existing cache ancestor must be owned by actual user');
  }
  report.ok=true;report.tokenProbePassed=true;report.guiAcceptance=false;
 }catch(error){report.error=diagnosticFailure(error,phase);throw error;}
 finally{bridge?.dispose();report.finishedAt=new Date().toISOString();await fs.writeFile(path.join(output,'child.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});}
}
module.exports={verifyIdentity,diagnosticFailure,main};if(require.main===module)main().catch(error=>{console.error(error.message);process.exitCode=1;});
