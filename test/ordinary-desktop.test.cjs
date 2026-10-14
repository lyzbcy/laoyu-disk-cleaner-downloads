'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
function declarations(source){const found=source.match(/Add-Type -TypeDefinition @'\r?\n([\s\S]+?)\r?\n'@/);if(!found)throw Error('NATIVE_DECLARATION_BLOCK_REQUIRED');return found[1];}
test('ordinary desktop diagnostic preserves the native profile and never grants desktop or profile access',()=>{
 const s=fs.readFileSync(path.join(__dirname,'../scripts/cleaner-ordinary-user-runner.ps1'),'utf8');
 assert.match(s,/Desktop=RequestedDesktop\(\)/);assert.match(s,/LoadUserProfile/);assert.match(s,/CreateEnvironmentBlock\(out nativeEnv,token,false\)/);assert.match(s,/CreateProcessWithLogonW/);assert.match(s,/0x404/);assert.doesNotMatch(s,/0x08000404|LsaAddAccountRights|SetUserObjectSecurity|SetThreadDesktop|SetProcessWindowStation|LinkRight|admin-owned-file/);
 assert(s.indexOf('AssignProcessToJobObject(job,process.Process)')<s.indexOf('ResumeThread(process.Thread)'));assert(s.indexOf('Diagnostic[\"actualChildAccess\"]')<s.indexOf('if(ResumeThread'));assert.match(s,/WaitForOwnedJobExit/);assert.match(s,/RetryProfileDelete/);assert.match(s,/if\(MayDeleteAccount\(created,ownedStopped,profileLoadAttempted,profileLoaded,profileDeleted\)\)/);assert.doesNotMatch(s,/entries.Add\("(?:HOME|USERPROFILE|TEMP|TMP)=/);
});
test('child validates ordinary identity and production profile before starting an original visible client',()=>{
 const s=fs.readFileSync(path.join(__dirname,'../scripts/cleaner-ordinary-desktop-probe.cjs'),'utf8');
 for(const term of ['adminMember','elevated','S-1-16-8192','WinSta0','Default','CLEANER_CI_EXPECTED_SID','CLEANER_CI_OS_PROFILE','validateHome','nativeDialog','normalQuit'])assert(s.includes(term));
 assert(s.indexOf('await policy.validateHome(home)')<s.indexOf('await startSession('));assert.doesNotMatch(s,/createFixtures|secureDirectory|executePlan|confirm.*button|Set-Acl|SetNamedSecurityInfo/);
});
test('native standard-user launcher compiles at EOF without Windows APIs',async()=>{
 const {execFile}=require('node:child_process'),{promisify}=require('node:util'),run=promisify(execFile);const pwsh=process.env.CLEANER_PWSH||'powershell.exe';const result=await run(pwsh,['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',path.join(__dirname,'../scripts/cleaner-ordinary-user-runner.ps1')]);assert.equal(result.stdout.trim(),'winsta0\\default');
});
test('visible observer waits for actual window and has a bounded failure',async()=>{
 const {waitVisible}=require('../scripts/cleaner-ordinary-desktop-probe.cjs');let t=0,n=0;const options={now:()=>t,pause:async()=>{t+=100;},timeout:500};const observed=await waitVisible(async()=>++n<3?{visible:false}:{visible:true,pid:123},options);assert.equal(observed.pid,123);assert.equal(n,3);t=0;await assert.rejects(waitVisible(async()=>({visible:false}),options),e=>e.message==='VISIBLE_CLIENT_TIMEOUT'&&e.latest.visible===false);
});
test('actual-screen helper parses and its native declarations compile without calling desktop APIs',async()=>{
 const file=path.join(__dirname,'../scripts/cleaner-desktop-screen.ps1'),s=fs.readFileSync(file,'utf8'),native=declarations(s);assert.doesNotMatch(s,/SendInput|SwitchDesktop|SetUserObjectSecurity/);assert.match(s,/CopyFromScreen/);assert.match(s,/FileMode\]::CreateNew/);
 const {promisify}=require('node:util'),run=promisify(require('node:child_process').execFile);const quote=v=>"'"+v.replaceAll("'","''")+"'",code=`$errors=$null;$tokens=$null;[Management.Automation.Language.Parser]::ParseFile(${quote(file)},[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){throw 'SCREEN_SCRIPT_PARSE'};Add-Type -TypeDefinition ${quote(native)}`;await run(process.env.CLEANER_PWSH||'powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(code,'utf16le').toString('base64')]);
});
test('account deletion requires stopped owned processes and confirmed profile cleanup',async()=>{
 const fsp=fs.promises,os=require('node:os'),{promisify}=require('node:util'),run=promisify(require('node:child_process').execFile),dir=await fsp.mkdtemp(path.join(os.tmpdir(),'ordinary-cleanup-policy-'));
 try{const source=declarations(fs.readFileSync(path.join(__dirname,'../scripts/cleaner-ordinary-user-runner.ps1'),'utf8'));const code=`$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n${source}\n'@\nfunction Must([bool]$actual,[bool]$expected){if($actual -ne $expected){throw 'ACCOUNT_CLEANUP_GATE'}}\nMust ([CleanerOrdinaryDesktopRunner]::MayDeleteAccount($true,$true,$false,$false,$false)) $true\nMust ([CleanerOrdinaryDesktopRunner]::MayDeleteAccount($true,$false,$false,$false,$false)) $false\nMust ([CleanerOrdinaryDesktopRunner]::MayDeleteAccount($true,$true,$true,$true,$false)) $false\nMust ([CleanerOrdinaryDesktopRunner]::MayDeleteAccount($true,$true,$false,$true,$false)) $false\nMust ([CleanerOrdinaryDesktopRunner]::MayDeleteAccount($true,$true,$true,$false,$false)) $false\nMust ([CleanerOrdinaryDesktopRunner]::MayDeleteAccount($true,$true,$true,$false,$true)) $true\nMust ([CleanerOrdinaryDesktopRunner]::MayDeleteAccount($false,$true,$false,$false,$false)) $false\n`;
 const script=path.join(dir,'policy.ps1');await fsp.writeFile(script,'\uFEFF'+code,{flag:'wx'});await run(process.env.CLEANER_PWSH||'powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',script]);
 }finally{await fsp.rm(dir,{recursive:true,force:true});}
});

test('native declaration extraction accepts both actual checkout line endings',()=>{for(const eol of ['\n','\r\n']){const code='public static class Inert { }';assert.equal(declarations("Add-Type -TypeDefinition @'"+eol+code+eol+"'@"),code);}});
