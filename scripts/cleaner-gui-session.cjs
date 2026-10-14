'use strict';
const {spawn,execFile}=require('node:child_process'),path=require('node:path');
const delay=ms=>new Promise(r=>setTimeout(r,ms));
const unavailableCodes=new Set(['NATIVE_PERMISSION_REQUIRED','NATIVE_INTERACTIVE_SESSION_REQUIRED','NATIVE_INTERACTIVE_DESKTOP_REQUIRED','NATIVE_ORDINARY_USER_REQUIRED']);
function decodeNativeResult(error,stdout,stderr){
 let result;try{result=JSON.parse(stdout.trim());}catch{}
 const native=result?.nativeError;
 if(native&&typeof native.code==='string'&&typeof native.message==='string')throw Object.assign(Error('Native desktop: '+native.message),{code:unavailableCodes.has(native.code)?'NATIVE_AUTOMATION_UNAVAILABLE':'NATIVE_AUTOMATION_FAILED',nativeCode:native.code,nativeDetails:native.details||null});
 if(error||!result||typeof result!=='object'||Array.isArray(result))throw Object.assign(Error('Native desktop failed: '+(stderr||error?.message||'invalid structured response')),{code:'NATIVE_AUTOMATION_FAILED'});
 return result;
}
async function nativeDialog(pid,action,confirmName='',fixturePath=''){
 if(process.env.GITHUB_ACTIONS!=='true')throw Error('ISOLATED_CI_ONLY');
 const platform=process.platform;let file,args;
 if(platform==='darwin'){file='/usr/bin/osascript';args=['-l','JavaScript',path.join(__dirname,'cleaner-native-dialog-mac.js'),String(pid),action,confirmName];}
 else if(platform==='win32'){file=path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe');args=['-NoLogo','-NoProfile','-NonInteractive','-File',path.join(__dirname,'cleaner-native-dialog-win.ps1'),'-TargetPid',String(pid),'-Action',action,'-ConfirmName',confirmName];if(fixturePath)args.push('-FixturePath',fixturePath);}
 else throw Error('UNSUPPORTED_PLATFORM');
 return new Promise((resolve,reject)=>execFile(file,args,{timeout:15000,maxBuffer:1024*1024,encoding:'utf8'},(error,stdout,stderr)=>{try{resolve(decodeNativeResult(error,stdout,stderr));}catch(e){reject(e);}}));
}
async function startSession(executable,data,{env=process.env}={}){
 let stderr='',endpoint='',childError=null;
 const child=spawn(executable,['--inspect=127.0.0.1:0','--cleaner-data='+data],{env:{...env,ELECTRON_RUN_AS_NODE:undefined},stdio:['ignore','ignore','pipe']});child.once('error',e=>childError=e);child.stderr.on('data',b=>{stderr=(stderr+b).slice(-65536);endpoint=stderr.match(/ws:\/\/127\.0\.0\.1:\d+\/[^\s]+/)?.[0]||'';});
 let ws;const pending=new Map();let next=0;
 const close=async()=>{if(ws?.readyState===1){await evaluate("setTimeout(()=>process.mainModule.require('electron').app.quit(),20);true").catch(()=>{});ws.close();}const end=Date.now()+10000;while(child.exitCode===null&&child.signalCode===null&&Date.now()<end)await delay(50);const normal=child.exitCode===0&&child.signalCode===null;if(!normal&&child.exitCode===null&&child.signalCode===null){child.kill();const stop=Date.now()+3000;while(child.exitCode===null&&child.signalCode===null&&Date.now()<stop)await delay(50);}return {normalQuit:normal,stopped:child.exitCode!==null||child.signalCode!==null,exitCode:child.exitCode,signal:child.signalCode};};
 function evaluate(expression){return new Promise((resolve,reject)=>{const id=++next,timer=setTimeout(()=>{pending.delete(id);reject(Error('INSPECTOR_TIMEOUT'));},15000);pending.set(id,{resolve:v=>{clearTimeout(timer);resolve(v);},reject:e=>{clearTimeout(timer);reject(e);}});ws.send(JSON.stringify({id,method:'Runtime.evaluate',params:{expression,returnByValue:true,awaitPromise:true}}));});}
 try{const end=Date.now()+15000;while(!endpoint&&Date.now()<end){if(childError)throw childError;if(child.exitCode!==null)throw Error('APP_EARLY_EXIT '+stderr);await delay(50);}if(!endpoint)throw Error('INSPECTOR_UNAVAILABLE');
 ws=new WebSocket(endpoint);await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('INSPECTOR_CONNECT_TIMEOUT')),5000);ws.addEventListener('open',()=>{clearTimeout(timer);resolve();},{once:true});ws.addEventListener('error',reject,{once:true});});ws.addEventListener('message',event=>{const row=JSON.parse(event.data),item=pending.get(row.id);if(!item)return;pending.delete(row.id);if(row.error||row.result?.exceptionDetails)item.reject(Error(JSON.stringify(row.error||row.result.exceptionDetails)));else item.resolve(row.result?.result?.value);});
 return {pid:child.pid,diagnostics:()=>stderr,evaluate,renderer:expression=>evaluate("process.mainModule.require('electron').BrowserWindow.getAllWindows()[0].webContents.executeJavaScript("+JSON.stringify(expression)+")"),close};
 }catch(e){await close();throw e;}
}
module.exports={startSession,nativeDialog,delay,decodeNativeResult};
