'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {verifyManifest,copyProduction}=require('../scripts/candidate-bootstrap.cjs');
test('fixed asset manifest rejects untrusted or ambiguous identity',()=>{
 const valid={repository:'lyzbcy/laoyu-disk-cleaner-downloads',release:412830796,source:'f3fe2af0aacb331566793c678c9b21440cfe51d1',assets:[{id:1,name:'laoyu-disk-cleaner-2.0.0-win-x64.zip',size:123,sha256:'a'.repeat(64)}]};
 assert(verifyManifest(valid));for(const patch of [{repository:'attacker/repo'},{release:-1},{source:'unknown'},{assets:[{...valid.assets[0],name:'../escape.zip'}]},{assets:[valid.assets[0],valid.assets[0]]}])assert.throws(()=>verifyManifest({...valid,...patch}));
});
test('production module copy preserves original bytes and refuses an existing destination',async()=>{
 const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),root=await fs.mkdtemp(path.join(os.tmpdir(),'candidate-bootstrap-test-'));
 try{const source=path.join(root,'candidate/resources/app'),out=path.join(root,'workspace');await fs.mkdir(path.join(source,'src/platform'),{recursive:true});await fs.mkdir(out);await fs.writeFile(path.join(source,'package.json'),JSON.stringify({name:'laoyu-disk-cleaner',version:'2.0.0',main:'src/main/index.cjs'}));const bytes=Buffer.from('unchanged\r\nmodule.exports=1;\r\n');await fs.writeFile(path.join(source,'src/platform/process.cjs'),bytes);const proof=await copyProduction(source,out);assert.equal(proof.files.length,1);assert.deepEqual(await fs.readFile(path.join(out,'src/platform/process.cjs')),bytes);await assert.rejects(copyProduction(source,out));}finally{await fs.rm(root,{recursive:true,force:true});}
});
