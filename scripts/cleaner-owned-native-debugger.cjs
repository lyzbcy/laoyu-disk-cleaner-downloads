'use strict';
// Ordinary-user debugger launches only its own original child. No attach, privilege, ACL or register writes.
const fs=require('node:fs/promises'),path=require('node:path'),{spawn}=require('node:child_process');
function marker(block,label){const match=String(block).match(new RegExp(label+' ([0-9a-f`]+)','i'));return match?match[1].replaceAll('`','').toLowerCase():null;}
function address(value){if(!/^[0-9a-f]{8,16}$/.test(value||''))throw Error('DEBUGGER_NUMERIC_ADDRESS_REQUIRED');return '0x'+value;}
async function diagnose(executable,out){
 if(process.platform!=='win32'||process.env.GITHUB_ACTIONS!=='true'||process.env.CI!=='true'||process.env.CLEANER_STANDARD_USER_CI!=='1')throw Error('DISPOSABLE_WINDOWS_USER_ONLY');
 const {runProcess}=require('../src/platform/process.cjs'),cdb=path.join(process.env['ProgramFiles(x86)'],'Windows Kits/10/Debuggers/x64/cdb.exe'),ps=path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe'),quote=s=>"'"+s.replaceAll("'","''")+"'";
 const code=`$ErrorActionPreference='Stop';$f=${quote(cdb)};$s=Get-AuthenticodeSignature -LiteralPath $f;if($s.Status -ne 'Valid' -or !$s.SignerCertificate -or $s.SignerCertificate.Subject -notmatch 'CN=Microsoft Corporation,'){throw 'MICROSOFT_DEBUGGER_REQUIRED'};@{path=$f;status=[string]$s.Status;signer=$s.SignerCertificate.Subject;sha256=(Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant()}|ConvertTo-Json -Compress`;
 const report={scope:'Original executable with no arguments under same ordinary user debugger own-child; fixed export parameters and return values only; never GUI acceptance',executable,argv:[],events:[],commands:[],startedAt:new Date().toISOString()};
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
    const read=await query(registers+'; .printf "LAOYU_ACCESS %x\\nLAOYU_ROOT %p\\nLAOYU_NAME %msu\\n", @edx, poi(@r8+8), poi(@r8+0x10)');
    const row={kind:'NtOpenDirectoryObject',entry:read,desiredAccess:marker(read,'LAOYU_ACCESS'),thread:marker(read,'LAOYU_TID'),expectedReturnIp:marker(read,'LAOYU_RETURNIP')};report.events.push(row);
    send('bd *; gu');row.returnStop=await prompt();if(row.returnStop===null)break;row.returnRead=await query(registers+'; !gle');row.returnThread=marker(row.returnRead,'LAOYU_TID');row.threadMatches=row.thread===row.returnThread;row.returnIp=marker(row.returnRead,'LAOYU_RIP');row.returnObserved=!!row.expectedReturnIp&&row.threadMatches&&row.returnIp===row.expectedReturnIp;row.returnValue=row.returnObserved?marker(row.returnRead,'LAOYU_RAX'):null;send('be *; g');
   }else if(/KERNELBASE!CreateMutexW/i.test(stop)){
    const read=await query(registers+'; .printf "LAOYU_NAME %mu\\n", @r8');const row={kind:'CreateMutexW',entry:read,thread:marker(read,'LAOYU_TID'),productNameMatched:/LAOYU_NAME Local\\LaoyuDiskCleanerProcessSingletonStartup(?:\r?\n|$)/.test(read)};report.events.push(row);
    if(row.productNameMatched){if(pendingMutex)throw Error('NATIVE_DEBUGGER_MULTIPLE_PRODUCT_CALLS');pendingMutex={row,returnIp:marker(read,'LAOYU_RETURNIP')};send('bp /1 '+address(pendingMutex.returnIp)+'; g');}else send('g');
   }else{
    const read=await query(registers+'; !gle');const row={kind:'other-stop',stop,read};report.events.push(row);
    if(pendingMutex&&marker(read,'LAOYU_RIP')===pendingMutex.returnIp&&marker(read,'LAOYU_TID')===pendingMutex.row.thread){pendingMutex.row.returnRead=read;pendingMutex.row.returnValue=marker(read,'LAOYU_RAX');pendingMutex.row.returnThreadMatches=true;report.productMutexReturnObserved=true;pendingMutex=null;}
    send('g');
   }
  }
  if(!ended){const deadline=Date.now()+5000;while(!ended&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,50));}
  report.naturallyStopped=ended;
 }catch(error){report.error={message:String(error.message),stack:String(error.stack).slice(0,8192)};}
 finally{if(child&&!ended){report.ownedDebuggerStopRequested=true;child.kill();const deadline=Date.now()+5000;while(!ended&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,50));}report.debuggerStopped=ended;report.pendingProductReturn=!!pendingMutex;report.finishedAt=new Date().toISOString();await fs.writeFile(path.join(out,'native-debugger-log.txt'),raw,{flag:'wx'});await fs.writeFile(path.join(out,'native-debugger-report.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});}
 return report;
}
module.exports={diagnose,marker,address};
