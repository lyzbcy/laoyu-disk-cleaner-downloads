"""Fixed, hidden draft input. No caller-selected repository, URL or source path."""
import hashlib,json,os,pathlib,shutil,stat,urllib.request,urllib.error,urllib.parse,zipfile
root=pathlib.Path(__file__).resolve().parent.parent
manifest=json.loads((root/'manifests/stage-acl-build-input.json').read_text())
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs): return None
url='https://api.github.com/repos/lyzbcy/laoyu-disk-cleaner-downloads/releases/assets/'+str(manifest['assetId'])
request=urllib.request.Request(url,headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/octet-stream','User-Agent':'cleaner-public-build'})
try: response=urllib.request.build_opener(NoRedirect).open(request,timeout=60)
except urllib.error.HTTPError as error:
 if error.code not in (301,302,303,307,308): raise
 signed=error.headers['Location'];parsed=urllib.parse.urlparse(signed)
 if parsed.scheme!='https' or not parsed.hostname or not parsed.hostname.endswith('.githubusercontent.com'): raise RuntimeError('UNEXPECTED_ASSET_HOST')
 response=urllib.request.urlopen(urllib.request.Request(signed,headers={'User-Agent':'cleaner-public-build'}),timeout=60)
with response: data=response.read(manifest['bytes']+1)
if len(data)!=manifest['bytes'] or hashlib.sha256(data).hexdigest()!=manifest['sha256']: raise RuntimeError('INPUT_BYTES_MISMATCH')
folder=root/'build-input';folder.mkdir(exist_ok=False);archive=folder/'source.zip';archive.write_bytes(data);source=folder/'source';source.mkdir()
with zipfile.ZipFile(archive) as zipped:
 infos=zipped.infolist()
 if len(infos)>3000 or sum(x.file_size for x in infos)>64*1024*1024: raise RuntimeError('INPUT_EXPANSION_BOUND')
 for info in infos:
  relative=pathlib.PurePosixPath(info.filename)
  if relative.is_absolute() or '..' in relative.parts or '\\' in info.filename or ':' in info.filename or stat.S_ISLNK(info.external_attr>>16) or info.file_size>20*1024*1024: raise RuntimeError('INPUT_PATH_OR_TYPE_REJECTED')
  target=source.joinpath(*relative.parts)
  target.resolve().relative_to(source.resolve())
  if info.is_dir(): target.mkdir(parents=True,exist_ok=True)
  else:
   target.parent.mkdir(parents=True,exist_ok=True)
   with target.open('xb') as output: output.write(zipped.read(info))
# Clear only generated evidence copied into this new disposable source tree.
for relative in ['verification/packages','verification/core','verification/gui','verification/install-update','verification/restricted-probe']:
 target=source/relative
 if target.exists(): shutil.rmtree(target)
for name in ['actual-source-startup-green-20261013.json','actual-source-startup-20261013.png','actual-packaged-startup-green-20261013.json','actual-packaged-startup-20261013.png']:
 (source/'verification'/name).unlink(missing_ok=True)
print(json.dumps({'inputVerified':True,'sourceCommit':manifest['sourceCommit'],'bytes':len(data),'privateDraftRemainsUnpublished':True}))
