'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {verifyIdentity,main}=require('../scripts/cleaner-restricted-probe.cjs');
const fixture=()=>({user:'S-1-5-21-1-2-3-1001',owner:'S-1-5-21-1-2-3-1001',integrity:'S-1-16-8192',elevated:false,adminMember:false,session:1,profile:'C:\\Users\\runner',HOME:null,USERPROFILE:'C:\\Users\\runner',windowStation:'WinSta0',desktop:'Default',groups:[{sid:'S-1-5-5-0-123',attributes:0xC0000007},{sid:'S-1-5-32-544',attributes:0x10}],privileges:[{name:'SeChangeNotifyPrivilege',attributes:2}]});
test('same-SID restricted identity requires real default desktop, profile, logon SID and safe token',()=>{
 const parent=fixture();assert.equal(verifyIdentity(parent,fixture()),true);
 for(const patch of [{user:'foreign'},{owner:'S-1-5-32-544'},{integrity:'S-1-16-12288'},{adminMember:true},{elevated:true},{session:2},{profile:'C:\\other'},{HOME:'C:\\changed'},{USERPROFILE:'C:\\changed'},{windowStation:'service'},{desktop:'alternate'},{groups:[{sid:'S-1-5-5-0-999',attributes:0xC0000007}]},{groups:[{sid:'S-1-5-5-0-123',attributes:0xC0000007},{sid:'S-1-5-32-544',attributes:4}]},{privileges:[{name:'SeDebugPrivilege',attributes:2}]}])assert.throws(()=>verifyIdentity(parent,{...fixture(),...patch}));
});
test('restricted probe cannot run on local desktop and never mutates existing ACL/profile/desktop',async()=>{
 const saved=process.env.GITHUB_ACTIONS;delete process.env.GITHUB_ACTIONS;try{await assert.rejects(main(),/ISOLATED_WINDOWS_CI_ONLY/);}finally{if(saved!==undefined)process.env.GITHUB_ACTIONS=saved;}
 const source=fs.readFileSync(path.join(__dirname,'../scripts/cleaner-restricted-probe.cs'),'utf8');assert.doesNotMatch(source,/Set-Acl|SetNamedSecurityInfo|SetSecurityInfo|AdjustTokenPrivileges|NetUserAdd|LoadUserProfile|DeleteProfile/);assert.match(source,/SetTokenInformation\(restricted,4/);assert.match(source,/SetTokenInformation\(restricted,25/);assert(source.indexOf('AssignProcessToJobObject(job,process.Process)')<source.indexOf('ResumeThread(process.Thread)'));assert.match(source,/Desktop="winsta0\\\\default"/);assert.match(source,/CreateEnvironmentBlock\(out environment,restricted,true\)/);
});
test('actual bundled PowerShell compiler validates restricted-token C# without calling native API',async()=>{
 const {runProcess}=require('../src/platform/process.cjs'),file=path.join(__dirname,'../scripts/cleaner-restricted-probe.cs'),pwsh=process.env.CLEANER_PWSH||(process.platform==='win32'?path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe'):'pwsh'),code=`Add-Type -Path '${file.replaceAll("'","''")}';if([CleanerRestrictedProbe]::OrdinaryGroup('S-1-5-32-544',7,'u')){throw 'ADMIN_ALLOWED'};if(![CleanerRestrictedProbe]::OrdinaryGroup('S-1-5-5-0-123',3221225479,'u')){throw 'LOGON_REMOVED'};if(![CleanerRestrictedProbe]::OrdinaryGroup('S-1-5-32-545',7,'u')){throw 'USERS_REMOVED'}`;
 const executable=path.isAbsolute(pwsh)?pwsh:require('node:child_process').execFileSync('/usr/bin/which',[pwsh],{encoding:'utf8'}).trim();await runProcess(executable,['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(code,'utf16le').toString('base64')]);
});
test('probe failure retains bounded actual process exit and output without changing eligibility',()=>{const {diagnosticFailure}=require('../scripts/cleaner-restricted-probe.cjs'),error=Object.assign(Error('failed'),{code:'PROCESS_EXIT',exitCode:17,exitSignal:'SIGTERM',stdout:'x'.repeat(20000),stderr:'native compiler denied'}),result=diagnosticFailure(error,'inspect-child-token');assert.equal(result.phase,'inspect-child-token');assert.equal(result.exitCode,17);assert.equal(result.exitSignal,'SIGTERM');assert.equal(result.code,'PROCESS_EXIT');assert.equal(result.stdout.length,16384);assert.equal(result.stderr,'native compiler denied');assert.equal(diagnosticFailure(Error('unknown'),'profile').exitCode,null);});
test('parent captures bounded read-only ACL evidence before verification and child launch',()=>{
 const source=fs.readFileSync(path.join(__dirname,'../scripts/cleaner-restricted-probe.cs'),'utf8');
 for(const name of ['DefaultDaclEvidence','GetUserObjectSecurity','AccessCheck','GetKernelObjectSecurity','sourceSecurity','restrictedSecurity','childSecurity','unavailableFromParent'])assert(source.includes(name),name);
 assert(source.indexOf('report["restrictedSecurity"]')<source.indexOf('Verify(before,after,ids)'));
 assert(source.indexOf('report["childSecurity"]')<source.indexOf('ResumeThread(process.Thread)'));
 assert.match(source,/DuplicateTokenEx\(token,8,IntPtr.Zero,2,2/);
 assert.doesNotMatch(source,/SetTokenInformation\(source,6|SetUserObjectSecurity|SetKernelObjectSecurity|SetThreadDesktop|SetProcessWindowStation/);
 assert.match(source,/65536/);assert.match(source,/256/);assert.match(source,/NativeErrorCode/);
});
test('new-token DefaultDacl experiment preserves baseline and re-reads proof before child creation',()=>{
 const source=fs.readFileSync(path.join(__dirname,'../scripts/cleaner-restricted-probe.cs'),'utf8');
 assert.match(source,/AppendUserGenericAll/);assert.match(source,/SetTokenInformation\(restricted,6/);
 assert(source.indexOf('report["restrictedSecurity"]')<source.indexOf('ApplyUserDefaultDacl(restricted,user)'));
 assert(source.indexOf('ApplyUserDefaultDacl(restricted,user)')<source.indexOf('CreateEnvironmentBlock(out environment'));
 assert.match(source,/VerifyDefaultDaclAddition/);assert.match(source,/restrictedSecurityAfterDefaultDacl/);
 assert.match(source,/sourceDefaultDaclBefore/);assert.match(source,/sourceDefaultDaclAfter/);
 assert.match(source,/VerifyExactBytes\(sourceDefaultDaclBefore,sourceDefaultDaclAfter\)/);
 assert.doesNotMatch(source,/SetTokenInformation\(source,6|SetUserObjectSecurity|SetKernelObjectSecurity|SetNamedSecurityInfo|SetSecurityInfo/);
});
test('compiled pure ACL experiment preserves existing ACE bytes and rejects corruption without Windows APIs',async()=>{
 const {runProcess}=require('../src/platform/process.cjs'),file=path.join(__dirname,'../scripts/cleaner-restricted-probe.cs'),pwsh=process.env.CLEANER_PWSH||(process.platform==='win32'?path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe'):'pwsh');
 const selfTest=`public static class AclPureTest {
 static void Must(bool condition){if(!condition)throw new System.Exception("ACL_ASSERT");}
 static void Reject(System.Action action){bool failed=false;try{action();}catch(System.InvalidOperationException){failed=true;}Must(failed);}
 public static void Run(){
  byte[] sid={1,1,0,0,0,0,0,5,18,0,0,0};
  byte[] original={2,0,32,0,1,0,0,0,1,0,20,0,0,0,0,16,1,1,0,0,0,0,0,5,18,0,0,0,9,8,7,6};
  byte[] baseline=(byte[])original.Clone();byte[] result=CleanerRestrictedProbe.AppendUserGenericAll(original,sid);
  Must(result.Length==52&&result[4]==2&&result[2]==52);
  for(int i=0;i<original.Length;i++)Must(original[i]==baseline[i]);
  for(int i=8;i<28;i++)Must(result[i]==original[i]);
  Must(result[28]==0&&result[29]==0&&result[30]==20&&result[35]==16);
  for(int i=0;i<sid.Length;i++)Must(result[36+i]==sid[i]);
  for(int i=28;i<32;i++)Must(result[i+20]==original[i]);
  CleanerRestrictedProbe.VerifyDefaultDaclAddition(original,result,sid);
  CleanerRestrictedProbe.VerifyExactBytes(baseline,original);
  byte[] changed=(byte[])original.Clone();changed[8]=0;Reject(delegate{CleanerRestrictedProbe.VerifyExactBytes(original,changed);});
  result[8]=0;Reject(delegate{CleanerRestrictedProbe.VerifyDefaultDaclAddition(original,result,sid);});
  Reject(delegate{CleanerRestrictedProbe.AppendUserGenericAll(null,sid);});
  Reject(delegate{CleanerRestrictedProbe.AppendUserGenericAll(original,new byte[8]);});
  byte[] malformed=(byte[])original.Clone();malformed[10]=255;Reject(delegate{CleanerRestrictedProbe.AppendUserGenericAll(malformed,sid);});
  byte[] many=new byte[1032];many[0]=2;many[2]=8;many[3]=4;many[5]=1;for(int i=8;i<many.Length;i+=4)many[i+2]=4;Reject(delegate{CleanerRestrictedProbe.AppendUserGenericAll(many,sid);});
  byte[] large=new byte[65532];large[0]=2;large[2]=252;large[3]=255;Reject(delegate{CleanerRestrictedProbe.AppendUserGenericAll(large,sid);});
  byte[] empty={4,0,8,0,0,0,0,0};byte[] first=CleanerRestrictedProbe.AppendUserGenericAll(empty,sid);Must(first[0]==4&&first[4]==1);CleanerRestrictedProbe.VerifyDefaultDaclAddition(empty,first,sid);
 }
}`;
 const code=`$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n${fs.readFileSync(file,'utf8')}\n${selfTest}\n'@\n[AclPureTest]::Run()`;
 const executable=path.isAbsolute(pwsh)?pwsh:require('node:child_process').execFileSync('/usr/bin/which',[pwsh],{encoding:'utf8'}).trim();
 // Keep the exact complete C# and assertions off Windows' 32767-character command line.
 const temp=await fs.promises.mkdtemp(path.join(require('node:os').tmpdir(),'cleaner-acl-pure-'));
 try{const script=path.join(temp,'pure-acl.ps1');await fs.promises.writeFile(script,'\uFEFF'+code,{flag:'wx',mode:0o600});await runProcess(executable,['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',script]);}
 finally{await fs.promises.rm(temp,{recursive:true,force:true});}
});
