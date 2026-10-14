'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),{promisify}=require('node:util'),run=promisify(require('node:child_process').execFile);
test('owned desktop ACL operations preserve baseline bytes, remove only the unique owned ACE, and reject foreign SIDs',async()=>{
 const source=await fs.readFile(path.join(__dirname,'../scripts/cleaner-owned-desktop.cs'),'utf8');
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'owned-desktop-policy-'));
 try{
 const code=`$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n${source}\n'@\n[CleanerOwnedDesktopPolicyTests]::Run()\n`;
 const fixture=`
public static class CleanerOwnedDesktopPolicyTests {
 static void Must(bool ok){if(!ok)throw new System.Exception("OWNED_ACL_POLICY_FAILED");}
 static byte[] Descriptor(){return new byte[]{1,0,4,128,0,0,0,0,0,0,0,0,0,0,0,0,20,0,0,0,2,0,28,0,1,0,0,0,0,0,20,0,255,1,15,0,1,1,0,0,0,0,0,5,18,0,0,0};}
 public static void Run(){
 var d=Descriptor();var original=(byte[])d.Clone();var sid=new byte[]{1,5,0,0,0,0,0,5,21,0,0,0,1,0,0,0,2,0,0,0,3,0,0,0,233,3,0,0};
 var ace=CleanerOwnedDesktop.Ace(sid,0x20327);var changed=CleanerOwnedDesktop.Append(d,ace);Must(CleanerOwnedDesktop.Equal(d,original));Must(changed.Length==d.Length+ace.Length);Must(CleanerOwnedDesktop.SameExceptAppended(d,changed,ace));Must(CleanerOwnedDesktop.Equal(CleanerOwnedDesktop.Remove(changed,ace),d));
 var other=CleanerOwnedDesktop.Ace(new byte[]{1,1,0,0,0,0,0,5,11,0,0,0},1);var concurrent=CleanerOwnedDesktop.Append(changed,other);var expected=CleanerOwnedDesktop.Append(d,other);Must(CleanerOwnedDesktop.Equal(CleanerOwnedDesktop.Remove(concurrent,ace),expected));Must(!CleanerOwnedDesktop.SameExceptAppended(d,concurrent,ace));
 bool refused=false;try{CleanerOwnedDesktop.Remove(d,ace);}catch(System.InvalidOperationException){refused=true;}Must(refused);
 refused=false;try{CleanerOwnedDesktop.Remove(CleanerOwnedDesktop.Append(changed,ace),ace);}catch(System.InvalidOperationException){refused=true;}Must(refused);
 Must(CleanerOwnedDesktop.ValidSid("S-1-5-21-1-2-3-1001"));Must(!CleanerOwnedDesktop.ValidSid("S-1-5-32-545"));Must(!CleanerOwnedDesktop.ValidSid("S-1-1-0"));Must(!CleanerOwnedDesktop.ValidSid("S-1-5-21-1-2-3-500"));
 Must(CleanerOwnedDesktop.DesktopName("1234567890abcdef1234567890abcdef")=="LaoyuCleaner_1234567890abcdef1234567890abcdef");refused=false;try{CleanerOwnedDesktop.DesktopName("Default");}catch(System.InvalidOperationException){refused=true;}Must(refused);
 }
}`;
 const file=path.join(dir,'policy.ps1');await fs.writeFile(file,'\uFEFF'+code.replace(source,source+'\n'+fixture));const result=await run(process.env.CLEANER_PWSH||'powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',file]);assert.equal(result.stderr,'');
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});
test('owned controller starts in the exact CI desktop and checks input desktop independently',async()=>{
 const runner=await fs.readFile(path.join(__dirname,'../scripts/cleaner-owned-desktop-runner.ps1'),'utf8'),child=await fs.readFile(path.join(__dirname,'../scripts/cleaner-owned-desktop-probe.cjs'),'utf8');
 assert.match(runner,/Desktop=ownedDesktop.RequestedDesktop/);assert.match(runner,/ownedDesktop=new CleanerOwnedDesktop/);assert(runner.indexOf('ownedDesktop=new CleanerOwnedDesktop')<runner.indexOf('ownedDesktop.Prepare()'));assert(runner.indexOf('Check(TerminateJobObject(job,1))')<runner.indexOf('ownedDesktop.Restore(ownedStopped)'));
 assert.match(child,/CLEANER_CI_DESKTOP_NONCE/);assert.match(child,/identity.desktop,expectedDesktop/);assert.match(child,/inputDesktop/);assert.doesNotMatch(child,/identity.desktop,'Default'/);
});
test('owned launcher and UI observers compile/parse without invoking Windows APIs',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'owned-desktop-compile-'));
 try{
 const runner=path.join(__dirname,'../scripts/cleaner-owned-desktop-runner.ps1');const result=await run(process.env.CLEANER_PWSH||'powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',runner]);assert.equal(result.stdout.trim(),'winsta0\\default');
 for(const name of ['cleaner-owned-native-dialog-win.ps1','cleaner-owned-desktop-screen.ps1']){const file=path.join(__dirname,'../scripts',name),s=await fs.readFile(file,'utf8'),block=s.match(/Add-Type -TypeDefinition @'\r?\n([\s\S]+?)\r?\n'@/);assert(block);const quote=v=>"'"+v.replaceAll("'","''")+"'";const code=`$ErrorActionPreference='Stop'\n$errors=$null;$tokens=$null;[Management.Automation.Language.Parser]::ParseFile(${quote(file)},[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){throw 'SCRIPT_PARSE'}\nAdd-Type -TypeDefinition @'\n${block[1]}\n'@\n`;const script=path.join(dir,name);await fs.writeFile(script,'\uFEFF'+code,{flag:'wx'});await run(process.env.CLEANER_PWSH||'powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',script]);}
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});
test('uncertain desktop restoration retains the profile and never asks DELETE object access',async()=>{
 const runner=await fs.readFile(path.join(__dirname,'../scripts/cleaner-owned-desktop-runner.ps1'),'utf8'),native=await fs.readFile(path.join(__dirname,'../scripts/cleaner-owned-desktop.cs'),'utf8');assert.match(runner,/profileEverLoaded&&!profileLoaded&&ownedStopped&&desktopRestored/);assert.match(native,/0x60183/);assert.doesNotMatch(native,/0x70183/);
});
test('prelaunch diagnostics inspect actual target token file and owned desktop access without widening permissions',async()=>{
 const runner=await fs.readFile(path.join(__dirname,'../scripts/cleaner-owned-desktop-runner.ps1'),'utf8'),native=await fs.readFile(path.join(__dirname,'../scripts/cleaner-owned-desktop.cs'),'utf8');assert.match(runner,/Diagnostic\["prelaunchTargetFiles"\]=TargetFileAccess/);assert.match(runner,/Diagnostic\["prelaunchOwnedDesktopAccess"\]=ownedDesktop.Access/);assert.match(runner,/delegate\{Check\(RevertToSelf\(\)\);\}/);assert.match(native,/StationMask=0x20327, DesktopMask=0x201CF/);
});
test('a failed token reversion stays on an isolated thread and cannot escape into main cleanup',async()=>{
 const s=await fs.readFile(path.join(__dirname,'../scripts/cleaner-owned-desktop-runner.ps1'),'utf8');assert.match(s,/bool ownedStopped=ReadOnlyProbeThreadEnded/);assert(s.indexOf("ReadOnlyProbeThreadEnded=true;if(failure")>s.indexOf("if(!worker.Join(30000))"));const runner=s.match(/\$runnerSource=@'\r?\n([\s\S]+?)\r?\n'@/)[1],owned=(await fs.readFile(path.join(__dirname,'../scripts/cleaner-owned-desktop.cs'),'utf8')).replace(/^using [^;]+;\r?\n/gm,'');
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'owned-thread-policy-'));try{const code=`$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n${runner}\n${owned}\npublic static class IsolatedProbeTest { public static void Run(){int main=System.Threading.Thread.CurrentThread.ManagedThreadId,observed=main;bool reverted=false,failed=false;try{CleanerOwnedDesktopRunner.InIsolatedThread(delegate{observed=System.Threading.Thread.CurrentThread.ManagedThreadId;throw new System.Exception("probe failure");},delegate{reverted=true;throw new System.Exception("revert failure");});}catch(System.InvalidOperationException){failed=true;}if(!failed||!reverted||observed==main||!CleanerOwnedDesktopRunner.ReadOnlyProbeThreadEnded)throw new System.Exception("ISOLATED_REVERSION_POLICY");} }\n'@\n[IsolatedProbeTest]::Run()\n`;const file=path.join(dir,'thread.ps1');await fs.writeFile(file,'\uFEFF'+code);await run(process.env.CLEANER_PWSH||'powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',file]);}finally{await fs.rm(dir,{recursive:true,force:true});}
});
