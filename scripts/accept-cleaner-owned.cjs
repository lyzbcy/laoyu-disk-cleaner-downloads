'use strict';
// Programmatic real-client acceptance. Does not replace dialogs, IPC, file ops,
// process checks, HOME, or the product entry point. Exit 2 means pending access.
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {createFixtures,verifyFixture,changeFixture,cleanupFixtures}=require('./cleaner-gui-fixtures.cjs');
const {startSession,nativeDialog,delay}=require('./cleaner-owned-gui-session.cjs');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
async function wait(check,message,ms=30000){const end=Date.now()+ms;do{const value=await check();if(value)return value;await delay(100);}while(Date.now()<end);throw Error(message);}
async function main(){
 if(process.env.GITHUB_ACTIONS!=='true')throw Error('ISOLATED_CI_ONLY: local desktop acceptance must use CUA');
 const app=process.env.CLEANER_PACKAGED_APP;if(!app||!path.isAbsolute(app))throw Error('CLEANER_PACKAGED_APP must identify a real candidate directory');
 if(process.getuid?.()===0)throw Error('ORDINARY_USER_REQUIRED');
 const home=await require('../src/platform/windows-native.cjs').getCurrentHome();assert.equal(home,os.homedir(),'OS token profile must agree; HOME is never replaced');
 const executable=path.join(app,process.platform==='darwin'?'Contents/MacOS/LaoyuDiskCleaner':'LaoyuDiskCleaner.exe'),resources=path.join(app,process.platform==='darwin'?'Contents/Resources/app':'resources/app');
 const pkg=JSON.parse(await fs.readFile(path.join(resources,'package.json'),'utf8'));assert.equal(pkg.name,'laoyu-disk-cleaner');assert.equal(pkg.main,'src/main/index.cjs');
 const base=path.resolve(__dirname,'../verification/core/gui');await fs.mkdir(base,{recursive:true});const evidence=await fs.mkdtemp(path.join(base,process.platform+'-'+process.arch+'-'));
 const ownedDataRoot=await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()),'cleaner-owned-gui-data-'));const data=await require('../src/core/settings.cjs').privateDataDirectory(path.join(ownedDataRoot,'data'),{appPath:app});
 const report={scope:'programmatic packaged GUI and native confirmation/file actions only',status:'running',platform:process.platform,arch:process.arch,version:pkg.version,app,home,evidence,ownedDataRoot,startedAt:new Date().toISOString(),cases:[],nativeDialogs:[],pending:['installation','update/rollback','human first-use and visual review']};
 let session,fixtures;const save=()=>fs.writeFile(path.join(evidence,'report.json'),JSON.stringify(report,null,2)+'\n');await save();
 try{
  session=await startSession(executable,data);
  const metadata=await wait(()=>session.evaluate("(()=>{const e=process.mainModule.require('electron'),w=e.BrowserWindow.getAllWindows()[0];return w&&w.isVisible()?{packaged:e.app.isPackaged,pid:process.pid,electron:process.versions.electron,home:process.mainModule.require('node:os').homedir(),data:e.app.getPath('userData'),visible:w.isVisible(),url:w.webContents.getURL(),sandbox:w.webContents.getLastWebPreferences().sandbox}:null})()"),'VISIBLE_WINDOW_TIMEOUT');
  assert.equal(metadata.packaged,true);assert.equal(metadata.home,home);assert.equal(metadata.data,data);assert.equal(metadata.electron,'44.7.0');assert.equal(metadata.sandbox,true);assert.equal(metadata.url,require('node:url').pathToFileURL(path.join(resources,'build/renderer/index.html')).href);report.client=metadata;
  report.nativeAccess=await nativeDialog(session.pid,'probe');
  fixtures=await createFixtures({home,onCreated:entry=>fs.appendFile(path.join(evidence,'fixture-created.jsonl'),JSON.stringify(entry)+'\n',{mode:0o600})});await fs.writeFile(path.join(evidence,'fixture-manifest.json'),JSON.stringify(fixtures,null,2)+'\n');
  const status=()=>session.renderer('window.cleaner.getStatus()');
  const click=label=>session.renderer(`(()=>{const all=Array.from(document.querySelectorAll('button')).filter(b=>b.textContent.trim()===${JSON.stringify(label)});if(all.length!==1||all[0].disabled)throw Error('DOM_BUTTON_UNAVAILABLE');all[0].click();return true;})()`);
  const input=async(selector,value,select=false)=>session.renderer(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e||e.disabled)throw Error('DOM_INPUT_UNAVAILABLE');Object.getOwnPropertyDescriptor(${select?'HTMLSelectElement':'HTMLInputElement'}.prototype,'value').set.call(e,${JSON.stringify(value)});e.dispatchEvent(new Event(${JSON.stringify(select?'change':'input')},{bubbles:true}));return true;})()`);
  const shot=async name=>{const value=await session.evaluate("process.mainModule.require('electron').BrowserWindow.getAllWindows()[0].webContents.capturePage().then(i=>i.toPNG().toString('base64'))");await fs.writeFile(path.join(evidence,name+'.png'),Buffer.from(value,'base64'));};
  await wait(async()=>{const s=await status();return s.state==='idle'&&s.disks.some(d=>d.source==='statfs')?s:null;},'INITIAL_DISKS_OR_IDLE_TIMEOUT');await shot('initial');
  async function scan(){const before=await status();await click(before.report?'重新扫描':'开始只读扫描');return wait(async()=>{const s=await status();return s.state==='idle'&&s.report&&s.report.id!==before.report?.id?s:null;},'SCAN_TIMEOUT',120000);}
  let scanned=await scan();report.scan={complete:scanned.report.complete,issues:scanned.report.issues,visited:scanned.report.visited,ownedRootEntries:scanned.report.entries.filter(entry=>entry.rootId==='pip-cache').slice(0,100)};
  for(const entry of fixtures.entries){const actual=scanned.report.entries.find(e=>e.rootId==='pip-cache'&&e.relativePath===entry.relativePath);assert.ok(actual,'owned fixture must appear in actual scan');assert.equal(actual.eligible,entry.role!=='recent','actual process/age/policy gates must permit old owned fixtures');await verifyFixture(fixtures,entry);}
  await shot('scan');
  async function selectOne(entry,mode){
   const clear=await session.renderer("Array.from(document.querySelectorAll('button')).some(b=>b.textContent.trim()==='清除选择'&&!b.disabled)");if(clear)await click('清除选择');
   await input('select[aria-label="处理方式"]',mode,true);await input('input[aria-label="搜索扫描结果"]',entry.relativePath);
   await wait(()=>session.renderer(`(()=>{const inputs=Array.from(document.querySelectorAll('input[type=checkbox]')).filter(e=>e.getAttribute('aria-label')===${JSON.stringify('选择 '+entry.relativePath)});return inputs.length===1&&!inputs[0].disabled;})()`),'OWNED_ROW_NOT_SELECTABLE');
   await session.renderer(`(()=>{const matches=Array.from(document.querySelectorAll('input[type=checkbox]')).filter(e=>e.getAttribute('aria-label')===${JSON.stringify('选择 '+entry.relativePath)});if(matches.length!==1||matches[0].disabled)throw Error('EXACT_OWNED_CHECKBOX_REQUIRED');matches[0].click();return true;})()`);
   await wait(()=>session.renderer("document.querySelectorAll('input[type=checkbox]:checked').length===1"),'EXACT_SELECTION_REQUIRED');await click('预览所选操作');
   await wait(()=>session.renderer("!!document.querySelector('.plan-modal')"),'PLAN_MODAL_REQUIRED');const selected=await session.renderer("Array.from(document.querySelectorAll('.plan-files .file-path')).map(e=>e.textContent)");assert.deepEqual(selected,[entry.relativePath]);await shot(entry.role+'-preview');
  }
  async function native(action,mode){const name=mode==='permanent'?'确认不可恢复并永久删除':'确认移到回收站';const observed=await nativeDialog(session.pid,action,name);assert.equal(observed.defaultButton,'取消');report.nativeDialogs.push(observed);await save();return observed;}
  const cases=process.platform==='darwin'?[{role:'cancel',action:'enter'},{role:'cancel',action:'escape'},{role:'changed',action:'confirm'},{role:'trash',action:'confirm'},{role:'permanent',action:'confirm'}]:['cancel','changed','trash','permanent'].map(role=>({role,action:role==='cancel'?'cancel':'confirm'}));
  for(const {role,action} of cases){
   const entry=fixtures.entries.find(e=>e.role===role),mode=role==='trash'?'trash':'permanent';scanned=await scan();await selectOne(entry,mode);const before=await status();await click('继续到系统再次确认');
   await wait(async()=>{const s=await status();return s.state==='confirming';},'NATIVE_CONFIRMATION_STATE_REQUIRED');
   // No mocked acknowledgement: inspect then invoke the actual OS button.
   await native('inspect',mode);let changed;if(role==='changed')changed=await changeFixture(fixtures);
   await native(action,mode);
   const done=await wait(async()=>{const s=await status();return s.state==='idle'&&(role==='cancel'||s.result?.operationId!==before.result?.operationId)?s:null;},'ACTION_SETTLE_TIMEOUT',120000);
   if(role==='cancel'){await verifyFixture(fixtures,entry);assert.equal(done.result?.operationId,before.result?.operationId);report.cases.push({role,action,untouched:true,nativeCanceled:true,returnedToIdle:true,operationUnchanged:true});}
   else{
    const result=done.result;assert.ok(result);assert.equal(result.outcomes.length,1);
    if(role==='changed'){assert.equal(result.succeeded,0);assert.equal(result.handledBytes,0);await verifyFixture(fixtures,entry);report.cases.push({role,result,changed});}
    else{
     assert.equal(result.succeeded,1);assert.equal(result.handledBytes,entry.bytes);assert.equal(result.removedBytes,mode==='permanent'?entry.bytes:0);assert.equal(result.movedToTrashBytes,mode==='trash'?entry.bytes:0);await assert.rejects(fs.lstat(entry.file),{code:'ENOENT'});
     assert.ok(result.beforeDisks.length&&result.afterDisks.length&&result.freeSpaceChanges.length,'real before/after measurements required');for(const delta of result.freeSpaceChanges){const b=result.beforeDisks.find(d=>d.id===delta.diskId),a=result.afterDisks.find(d=>d.id===delta.diskId);assert.equal(delta.bytes,a.freeBytes-b.freeBytes);}
     let trash;if(role==='trash'){
      if(process.platform==='darwin'){const target=path.join(home,'.Trash',path.basename(entry.file)),st=await fs.lstat(target);assert.ok(st.isFile()&&!st.isSymbolicLink());trash={sha256:sha(await fs.readFile(target)),bytes:st.size};}
      else trash=await nativeDialog(session.pid,'trash','',entry.file);
      assert.equal(trash.sha256,entry.sha256);assert.equal(trash.bytes,entry.bytes);
     }
     report.cases.push({role,result,trash});
    }
   }
   await shot(role+'-'+action+'-result');await save();
  }
  for(const role of ['recent','unselected','cancel','changed'])await verifyFixture(fixtures,fixtures.entries.find(e=>e.role===role));report.sentinelsPreserved=true;
  await shot('final');report.status='passed';
 }catch(error){report.status=error.code==='NATIVE_AUTOMATION_UNAVAILABLE'?'pending':'failed';report.error=error.stack||error.message;report.nativeError=error.nativeCode?{code:error.nativeCode,details:error.nativeDetails||null}:null;}
 finally{
  if(session){try{report.close=await session.close();report.scopedEscape=session.diagnostics().split('\n').filter(line=>line.startsWith('SCOPED_CONFIRMATION_ESCAPE ')).slice(-12).map(line=>line.slice(0,2048));if(!report.close.normalQuit||!report.close.stopped)report.status='failed';}catch(error){report.status='failed';report.closeError=error.message;}}
  if(fixtures&&report.close?.stopped){try{await cleanupFixtures(fixtures);report.ownedRemainingFixturesRemoved=true;}catch(error){report.status='failed';report.fixtureCleanupError=error.message;}}
  report.finishedAt=new Date().toISOString();await save();
 }
 console.log(JSON.stringify({status:report.status,evidence,pending:report.pending,nativeCode:report.nativeError?.code||null}));process.exitCode=report.status==='passed'?0:report.status==='pending'?2:1;
}
if(require.main===module)main().catch(e=>{console.error(e.message);process.exitCode=1;});
module.exports={main};
