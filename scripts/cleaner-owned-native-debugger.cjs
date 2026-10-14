'use strict';
// Ordinary-user debugger launches only its own original child. No attach, privilege, ACL or register writes.
const fs=require('node:fs/promises'),path=require('node:path'),{spawn,execFile}=require('node:child_process');
const runFixed=async(file,args,{timeoutMs,maxOutput})=>require('node:util').promisify(execFile)(file,args,{timeout:timeoutMs,maxBuffer:maxOutput,windowsHide:true,shell:false});
function marker(block,label){const match=String(block).match(new RegExp(label+' ([0-9a-f`]+)','i'));return match?match[1].replaceAll('`','').toLowerCase():null;}
function address(value){if(!/^[0-9a-f]{8,16}$/.test(value||''))throw Error('DEBUGGER_NUMERIC_ADDRESS_REQUIRED');return '0x'+value;}
async function diagnose(executable,out,parentCapability){
 if(process.platform!=='win32'||process.env.GITHUB_ACTIONS!=='true'||process.env.CI!=='true'||(!parentCapability&&process.env.CLEANER_STANDARD_USER_CI!=='1'))throw Error('DISPOSABLE_WINDOWS_USER_ONLY');
 const expectedMutex=parentCapability?'Local\\LaoyuCleanerDiagnostic_'+parentCapability.nonce:'Local\\LaoyuDiskCleanerProcessSingletonStartup';if(parentCapability&&(!/^[0-9a-f]{32}$/.test(parentCapability.nonce)||parentCapability.nonce.length!==32||executable!==path.join(out,'owned-nonce-mutex-probe.exe')))throw Error('FIXED_PARENT_NONCE_PROBE_REQUIRED');
 const runProcess=runFixed,cdb=path.join(process.env['ProgramFiles(x86)'],'Windows Kits/10/Debuggers/x64/cdb.exe'),ps=path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe'),quote=s=>"'"+s.replaceAll("'","''")+"'";
 const code=`$ErrorActionPreference='Stop';$f=${quote(cdb)};$s=Get-AuthenticodeSignature -LiteralPath $f;if($s.Status -ne 'Valid' -or !$s.SignerCertificate -or $s.SignerCertificate.Subject -notmatch 'CN=Microsoft Corporation,'){throw 'MICROSOFT_DEBUGGER_REQUIRED'};@{path=$f;status=[string]$s.Status;signer=$s.SignerCertificate.Subject;sha256=(Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant()}|ConvertTo-Json -Compress`;
 const report={scope:parentCapability?'Original parent identity debugger own fixed nonce-mutex child; same-OS Win32 implementation evidence only, not product or ordinary-user acceptance':'Original executable with no arguments under same ordinary user debugger own-child; fixed export parameters and return values only; never GUI acceptance',executable,targetSha256:require('node:crypto').createHash('sha256').update(await fs.readFile(executable)).digest('hex'),argv:[],expectedMutex,parentCapability:!!parentCapability,events:[],commands:[],startedAt:new Date().toISOString()};
 let child,raw='',buffer='',queue=[],waiter,ended=false,pendingMutex=null,outputBytes=0;
 const timeoutMs=180000,started=Date.now();
 function push(block){queue.push(block);if(waiter){const value=waiter;waiter=null;value();}}
 function prompt(){if(queue.length)return Promise.resolve(queue.shift());if(ended)return Promise.resolve(null);return new Promise((resolve,reject)=>{let timer=setTimeout(()=>{if(waiter===wake)waiter=null;reject(Error('NATIVE_DEBUGGER_PROMPT_TIMEOUT'));},Math.max(1,Math.min(15000,timeoutMs-(Date.now()-started))));const wake=()=>{clearTimeout(timer);resolve(queue.length?queue.shift():null);};waiter=wake;});}
 function send(command){if(!child||ended)throw Error('NATIVE_DEBUGGER_CLOSED');report.commands.push(command);child.stdin.write(command+'\n');}
 async function query(command){send(command);const block=await prompt();if(block===null)throw Error('DEBUGGER_EXITED_DURING_FIXED_READ');return block;}
 const registers='.printf "LAOYU_TID %x\\nLAOYU_RIP %p\\nLAOYU_RAX %p\\nLAOYU_RETURNIP %p\\n", @$tid, @rip, @rax, poi(@rsp)';
 try{
  report.debugger=JSON.parse((await runProcess(ps,['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(code,'utf16le').toString('base64')],{timeoutMs:15000,maxOutput:65536})).stdout.replace(/^\uFEFF/,''));
  const env={...process.env,_NT_SYMBOL_PATH:'',_NT_ALT_SYMBOL_PATH:''};delete env.ELECTRON_RUN_AS_NODE;delete env.CLEANER_UPDATE_ACCEPTANCE_PLAN;delete env.CLEANER_UPDATE_ACCEPTANCE_NONCE;
  child=spawn(cdb,['-G',executable],{env,stdio:['pipe','pipe','pipe'],windowsHide:true});report.debuggerPid=child.pid;
  child.on('error',e=>{report.childError=String(e.message);ended=true;push(null);});child.on('close',(code,signal)=>{report.process={exitCode:code,signalCode:signal};ended=true;push(null);});
  const collect=bytes=>{outputBytes+=bytes.length;if(outputBytes>1024*1024){report.outputLimit=true;child.kill();return;}const text=bytes.toString();raw=(raw+text).slice(-1024*1024);buffer+=text;if(buffer.length>1024*1024){report.outputLimit=true;child.kill();return;}let match;while((match=/\b[0-9a-f]+:[0-9a-f]+> /i.exec(buffer))){push(buffer.slice(0,match.index));buffer=buffer.slice(match.index+match[0].length);}};child.stdout.on('data',collect);child.stderr.on('data',bytes=>{outputBytes+=bytes.length;if(outputBytes>1024*1024){report.outputLimit=true;child.kill();return;}raw=(raw+bytes.toString()).slice(-1024*1024);});
  report.initial=await prompt();if(report.initial===null)throw Error('NATIVE_DEBUGGER_INITIAL_BREAK_MISSING');send('bu KERNELBASE!CreateMutexW; bu ntdll!NtOpenDirectoryObject; g');
  for(let count=0;count<128&&!ended&&Date.now()-started<timeoutMs;count++){
   const stop=await prompt();if(stop===null)break;
   if(/ntdll!NtOpenDirectoryObject/i.test(stop)){
    const read=await query(registers+'; k 6; .printf "LAOYU_ACCESS %x\\nLAOYU_ROOT %p\\nLAOYU_NAME %msu\\n", @edx, poi(@r8+8), poi(@r8+0x10)');
    const row={kind:'NtOpenDirectoryObject',entry:read,desiredAccess:marker(read,'LAOYU_ACCESS'),thread:marker(read,'LAOYU_TID'),expectedReturnIp:marker(read,'LAOYU_RETURNIP')};report.events.push(row);
    send('bd *; gu');row.returnStop=await prompt();if(row.returnStop===null)break;row.returnRead=await query(registers+'; !gle');row.returnThread=marker(row.returnRead,'LAOYU_TID');row.threadMatches=row.thread===row.returnThread;row.returnIp=marker(row.returnRead,'LAOYU_RIP');row.returnObserved=!!row.expectedReturnIp&&row.threadMatches&&row.returnIp===row.expectedReturnIp;row.returnValue=row.returnObserved?marker(row.returnRead,'LAOYU_RAX'):null;send('be *; g');
   }else if(/KERNELBASE!CreateMutexW/i.test(stop)){
    const read=await query(registers+'; .printf "LAOYU_NAME %mu\\n", @r8');const row={kind:'CreateMutexW',entry:read,thread:marker(read,'LAOYU_TID'),targetNameMatched:read.split(/\r?\n/).includes('LAOYU_NAME '+expectedMutex)};report.events.push(row);
    if(row.targetNameMatched){if(pendingMutex)throw Error('NATIVE_DEBUGGER_MULTIPLE_PRODUCT_CALLS');pendingMutex={row,returnIp:marker(read,'LAOYU_RETURNIP')};send('bp /1 '+address(pendingMutex.returnIp)+'; g');}else send('g');
   }else{
    const read=await query(registers+'; !gle');const row={kind:'other-stop',stop,read};report.events.push(row);
    if(pendingMutex&&marker(read,'LAOYU_RIP')===pendingMutex.returnIp&&marker(read,'LAOYU_TID')===pendingMutex.row.thread){pendingMutex.row.returnRead=read;pendingMutex.row.returnValue=marker(read,'LAOYU_RAX');pendingMutex.row.returnThreadMatches=true;report.targetMutexReturnObserved=true;pendingMutex=null;}
    send('g');
   }
  }
  if(!ended){const deadline=Date.now()+5000;while(!ended&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,50));}
  report.naturallyStopped=ended;
 }catch(error){report.error={message:String(error.message),stack:String(error.stack).slice(0,8192)};}
 finally{if(child&&!ended){report.ownedDebuggerStopRequested=true;child.kill();const deadline=Date.now()+5000;while(!ended&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,50));}report.debuggerStopped=ended;report.pendingProductReturn=!!pendingMutex;report.finishedAt=new Date().toISOString();await fs.writeFile(path.join(out,'native-debugger-log.txt'),raw,{flag:'wx'});await fs.writeFile(path.join(out,'native-debugger-report.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});}
 return report;
}
async function diagnoseParentCapability(out){
 if(process.platform!=='win32'||process.env.GITHUB_ACTIONS!=='true'||process.env.CI!=='true'||process.env.CLEANER_STANDARD_USER_CI==='1')throw Error('DISPOSABLE_GHA_ORIGINAL_PARENT_ONLY');
 out=path.resolve(out);await fs.mkdir(out,{recursive:true});const nonce=require('node:crypto').randomBytes(16).toString('hex'),source=path.join(out,'owned-nonce-mutex-probe.cs'),executable=path.join(out,'owned-nonce-mutex-probe.exe');
 const code='using System;using System.Runtime.InteropServices;class Probe{[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr CreateMutex(IntPtr a,bool owner,string name);[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);static int Main(){IntPtr h=CreateMutex(IntPtr.Zero,false,@"Local\\LaoyuCleanerDiagnostic_'+nonce+'");int error=Marshal.GetLastWin32Error();bool closed=h==IntPtr.Zero||CloseHandle(h);Console.WriteLine("OWN_NONCE_CREATE error="+error+" created="+(h!=IntPtr.Zero)+" closed="+closed);return h!=IntPtr.Zero&&error!=183&&closed?0:1;}}';
 await fs.writeFile(source,code,{flag:'wx'});try{await fs.access(executable);throw Error('OWNED_DIAGNOSTIC_EXE_ALREADY_EXISTS');}catch(error){if(error.code!=='ENOENT')throw error;}
 const runProcess=runFixed;await runProcess(path.join(process.env.SystemRoot,'Microsoft.NET/Framework64/v4.0.30319/csc.exe'),['/nologo','/target:exe','/out:'+executable,source],{timeoutMs:30000,maxOutput:65536});return diagnose(executable,out,{nonce});
}
module.exports={diagnose,diagnoseParentCapability,marker,address};
if(require.main===module){if(process.argv.length!==3||process.argv[2]!=='--parent-capability')throw Error('FIXED_PARENT_CAPABILITY_MODE_REQUIRED');diagnoseParentCapability(path.resolve(__dirname,'../verification/core')).then(report=>{console.log(JSON.stringify({scope:report.scope,parentCapability:report.parentCapability,events:report.events.length,error:report.error||null}));process.exitCode=report.debuggerStopped&&report.targetMutexReturnObserved?0:1;}).catch(error=>{console.error(error.stack);process.exitCode=1;});}

