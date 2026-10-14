'use strict';
// Read-only profile and desktop capability diagnostic. No cleanup fixtures or confirmations.
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict');
const {startSession,nativeDialog,delay}=require('./cleaner-gui-session.cjs');
async function waitVisible(read,{pause=delay,now=Date.now,timeout=45000}={}){const end=now()+timeout;let latest=null;while(now()<end){try{latest=await read();if(latest?.visible)return latest;}catch(e){latest={readError:String(e.message).slice(0,4096)};}await pause(100);}throw Object.assign(Error('VISIBLE_CLIENT_TIMEOUT'),{latest});}
async function main(){
 if(process.platform!=='win32'||process.env.GITHUB_ACTIONS!=='true'||process.env.CI!=='true'||process.env.CLEANER_STANDARD_USER_CI!=='1')throw Error('DISPOSABLE_WINDOWS_CI_USER_ONLY');
 const out=path.resolve(__dirname,'../verification/core'),report={status:'failed',scope:'ordinary newly created OS profile and existing Default desktop capability only; no cleanup, installation, update or release acceptance',startedAt:new Date().toISOString()};let session,bridge;
 try{
  const {runProcess}=require('../src/platform/process.cjs'),ps=path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe');
  const inspected=await runProcess(ps,['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',path.join(__dirname,'cleaner-restricted-probe.ps1'),'-Inspect']);
  const identity=JSON.parse(inspected.stdout.replace(/^\uFEFF/,''));report.identity=identity;
  assert.equal(identity.user,process.env.CLEANER_CI_EXPECTED_SID);assert.equal(identity.owner,identity.user);assert.equal(identity.integrity,'S-1-16-8192');assert.equal(identity.adminMember,false);assert.equal(identity.elevated,false);assert.equal(identity.session,Number(process.env.CLEANER_CI_PARENT_SESSION));assert(identity.session>0);assert.equal(identity.windowStation,'WinSta0');assert.equal(identity.desktop,'Default');assert.equal(identity.profile,process.env.CLEANER_CI_OS_PROFILE);assert.equal(os.homedir(),identity.profile);
  const native=require('../src/platform/windows-native.cjs'),policy=require('../src/core/path-policy.cjs');bridge=native.getDefaultWindowsBridge();const home=await native.getCurrentHome();assert.equal(home,identity.profile);await policy.validateHome(home);report.productionHomeAccepted=true;report.ancestors=[];
  for(const relative of ['AppData','AppData/Local']){const file=path.join(home,...relative.split('/')),proof=await bridge.inspect(file);report.ancestors.push({file,proof});assert(proof.ordinary&&!proof.reparse&&proof.type==='directory'&&proof.ownedByCurrentUser,'original OS-created cache ancestors must pass production rules');}
  const app=path.resolve(process.env.CLEANER_PACKAGED_APP),executable=path.join(app,'LaoyuDiskCleaner.exe'),pkg=JSON.parse(await fs.readFile(path.join(app,'resources/app/package.json'),'utf8'));assert.equal(pkg.name,'laoyu-disk-cleaner');assert.equal(pkg.version,'2.0.0');assert.equal(pkg.main,'src/main/index.cjs');
  const temp=await fs.mkdtemp(path.join(os.tmpdir(),'cleaner-desktop-probe-'));report.ownedTemporaryDirectory=temp;const data=await require('../src/core/settings.cjs').privateDataDirectory(path.join(temp,'data'),{appPath:app});
  session=await startSession(executable,data);
  const identityApp=await waitVisible(()=>session.evaluate("(()=>{const e=process.mainModule.require('electron'),w=e.BrowserWindow.getAllWindows()[0];return {pid:process.pid,execPath:process.execPath,version:e.app.getVersion(),packaged:e.app.isPackaged,visible:w?.isVisible(),sandbox:w?.webContents.getLastWebPreferences().sandbox,data:e.app.getPath('userData')}})()"));report.client=identityApp;assert(identityApp.packaged&&identityApp.visible&&identityApp.sandbox);assert.equal(identityApp.version,'2.0.0');assert.equal(identityApp.execPath,executable);assert.equal(identityApp.data,data);
  const png=await session.evaluate("process.mainModule.require('electron').BrowserWindow.getAllWindows()[0].webContents.capturePage().then(i=>i.toPNG().toString('base64'))");await fs.writeFile(path.join(out,'ordinary-visible-window.png'),Buffer.from(png,'base64'),{flag:'wx'});
  report.nativeAccess=await nativeDialog(session.pid,'probe');
  const screen=await runProcess(ps,['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',path.join(__dirname,'cleaner-desktop-screen.ps1'),'-OutputFile',path.join(out,'ordinary-desktop-screen.png')]);report.screen=JSON.parse(screen.stdout.replace(/^\uFEFF/,''));
  report.status='passed';
 }catch(error){report.error={code:error.code||'ORDINARY_DESKTOP_FAILED',message:String(error.message).slice(0,4096),stack:String(error.stack).slice(0,8192),nativeCode:error.nativeCode||null};if(error.latest)report.latest=error.latest;}
 finally{if(session){try{report.close=await session.close();if(!report.close.normalQuit||!report.close.stopped)report.status='failed';}catch(e){report.status='failed';report.closeError=e.message;}}bridge?.dispose();report.finishedAt=new Date().toISOString();await fs.writeFile(path.join(out,'ordinary-desktop-report.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});}
 console.log(JSON.stringify({scope:report.scope,status:report.status,nativeCode:report.error?.nativeCode||null}));process.exitCode=report.status==='passed'?0:1;
}
module.exports={main,waitVisible};if(require.main===module)main().catch(e=>{console.error(e.message);process.exitCode=1;});
