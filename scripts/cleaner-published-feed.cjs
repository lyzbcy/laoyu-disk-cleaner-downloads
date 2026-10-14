'use strict';
const fs=require('node:fs/promises'),path=require('node:path');
const {startSession,delay}=require('./cleaner-gui-session.cjs');
(async()=>{
 if(process.env.GITHUB_ACTIONS!=='true'||process.platform!=='darwin'||!process.env.RUNNER_TEMP)throw Error('ISOLATED_MAC_CI_ONLY');
 const app=path.resolve('candidate/捞鱼C盘清理大师.app'),root=await fs.mkdtemp(path.join(process.env.RUNNER_TEMP,'cleaner-public-feed-'));await fs.chmod(root,0o700);
 const output=path.resolve('verification/public-feed');await fs.mkdir(output,{recursive:true});
 const data=path.join(root,'data');await fs.mkdir(data,{mode:0o700});
 const s=await startSession(path.join(app,'Contents/MacOS/LaoyuDiskCleaner'),data);const report={scope:'real original packaged client checks production anonymous GitHub releases/latest, same-version current result; no historical upgrade claim',root,app};
 try{
  for(let i=0;i<200;i++){try{const v=await s.renderer('window.cleaner.getStatus()');if(v.state==='idle')break;}catch{}await delay(100);}
  report.identity=await s.evaluate("(()=>{const e=process.mainModule.require('electron'),w=e.BrowserWindow.getAllWindows()[0];return {execPath:process.execPath,version:e.app.getVersion(),packaged:e.app.isPackaged,visible:w.isVisible(),plan:process.env.CLEANER_UPDATE_ACCEPTANCE_PLAN||null,nonce:process.env.CLEANER_UPDATE_ACCEPTANCE_NONCE||null}})()");
  if(!report.identity.packaged||!report.identity.visible||report.identity.version!=='2.0.0'||report.identity.plan||report.identity.nonce)throw Error('ORIGINAL_PACKAGED_IDENTITY_REQUIRED');
  await s.evaluate("(()=>{globalThis.cleanerFeedObserved=[];process.mainModule.require('electron').session.defaultSession.webRequest.onCompleted({urls:['https://api.github.com/repos/lyzbcy/laoyu-disk-cleaner-downloads/releases/latest']},d=>{globalThis.cleanerFeedObserved.push({url:d.url,method:d.method,statusCode:d.statusCode});});return true})()");
  report.result=await s.renderer('window.cleaner.checkUpdates()');for(let i=0;i<20;i++){report.observed=await s.evaluate('globalThis.cleanerFeedObserved');if(report.observed.length)break;await delay(50);}
  if(report.result.state!=='current'||report.result.release?.version!=='2.0.0'||report.result.release?.hasUpdate!==false||report.result.fixtureLocal!==false||!report.observed.some(x=>x.url==='https://api.github.com/repos/lyzbcy/laoyu-disk-cleaner-downloads/releases/latest'&&x.method==='GET'&&x.statusCode===200))throw Error('PUBLIC_PRODUCTION_FEED_NOT_CONFIRMED');
  await delay(300);const png=await s.evaluate("(async()=>{const w=process.mainModule.require('electron').BrowserWindow.getAllWindows()[0];await w.webContents.executeJavaScript('document.fonts.ready');return (await w.webContents.capturePage()).toPNG().toString('base64')})()");await fs.writeFile(path.join(output,'public-feed.png'),Buffer.from(png,'base64'));report.ok=true;
 }catch(e){report.ok=false;report.error=String(e.stack||e);throw e;}finally{report.close=await s.close();await fs.writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2)+'\n');}
 if(!report.close.normalQuit||!report.close.stopped)throw Error('NORMAL_CLOSE_REQUIRED');console.log(JSON.stringify(report,null,2));
})().catch(e=>{console.error(e.stack);process.exitCode=1;});
