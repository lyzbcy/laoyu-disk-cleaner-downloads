'use strict';
// Original binary, zero arguments, native default profile only. No inspector or injected app entry.
const fs=require('node:fs/promises'),path=require('node:path'),assert=require('node:assert/strict'),{spawn}=require('node:child_process');
const {nativeDialog,delay}=require('./cleaner-owned-gui-session.cjs');
async function runNormalStartup(executable,out,observe){
 if(process.platform!=='win32'||process.env.GITHUB_ACTIONS!=='true'||process.env.CI!=='true'||process.env.CLEANER_STANDARD_USER_CI!=='1')throw Error('DISPOSABLE_WINDOWS_USER_ONLY');
 const env={...process.env};delete env.ELECTRON_RUN_AS_NODE;delete env.CLEANER_UPDATE_ACCEPTANCE_PLAN;delete env.CLEANER_UPDATE_ACCEPTANCE_NONCE;
 const report={status:'failed',scope:'original executable with zero arguments, default OS APPDATA, independent native window observation; no inspector or app function injection',executable,argv:[],startedAt:new Date().toISOString()};let stderr='',childError=null;
 const child=spawn(executable,[],{env,stdio:['ignore','ignore','pipe']});child.on('error',error=>{childError=String(error.message).slice(0,4096);});child.stderr.on('data',bytes=>{stderr=(stderr+bytes).slice(-16384);});report.pid=child.pid;
 try{
  report.nativeWindow=await observe(child.pid,{alive:()=>child.exitCode===null&&child.signalCode===null});assert.equal(report.nativeWindow.status,'passed');const proof=report.nativeWindow.native;assert.equal(path.resolve(proof.actualExecutable).toLowerCase(),path.resolve(executable).toLowerCase());assert([executable,'"'+executable+'"'].some(value=>value.toLowerCase()===String(proof.actualCommandLine).trim().toLowerCase()),'OS command line must contain only the executable');
  const {runProcess}=require('../src/platform/process.cjs');const screen=await runProcess(path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe'),['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',path.join(__dirname,'cleaner-owned-desktop-screen.ps1'),'-Phase','normal','-OutputFile',path.join(out,'ordinary-normal-desktop-screen.png')]);report.screen=JSON.parse(screen.stdout.replace(/^\uFEFF/,''));
  report.closeRequest=await nativeDialog(child.pid,'close',executable);const end=Date.now()+20000;while(child.exitCode===null&&child.signalCode===null&&Date.now()<end)await delay(100);assert.equal(child.exitCode,0);assert.equal(child.signalCode,null);report.normalQuit=true;
  const directory=path.join(process.env.APPDATA,'LaoyuDiskCleaner'),bridge=require('../src/platform/windows-native.cjs').getDefaultWindowsBridge();report.defaultDataDirectory=await fs.realpath(directory);report.defaultDataProof=await bridge.inspect(report.defaultDataDirectory);assert(report.defaultDataProof.ordinary&&!report.defaultDataProof.reparse&&report.defaultDataProof.ownedByCurrentUser&&report.defaultDataProof.privateToCurrentUser);report.status='passed';
 }catch(error){report.error={message:String(error.message).slice(0,4096),stack:String(error.stack).slice(0,8192),nativeCode:error.nativeCode||null,nativeDetails:error.nativeDetails||null};}
 finally{report.stderr=stderr;report.process={exitCode:child.exitCode,signalCode:child.signalCode,childError};report.finishedAt=new Date().toISOString();await fs.writeFile(path.join(out,'ordinary-normal-startup-report.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});}
 return report;
}
module.exports={runNormalStartup};
