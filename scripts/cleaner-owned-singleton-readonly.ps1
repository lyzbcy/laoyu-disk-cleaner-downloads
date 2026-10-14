param([Parameter(Mandatory=$true)][string]$DataDirectory)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:CI -ne 'true' -or $env:CLEANER_STANDARD_USER_CI -ne '1'){throw 'DISPOSABLE_WINDOWS_USER_ONLY'}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class CleanerSingletonReadOnly {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetLongPathName(string path,StringBuilder result,uint size);
 public static string LongPath(string path){StringBuilder result=new StringBuilder(32768);uint count=GetLongPathName(path,result,32768);if(count==0||count>=32768)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());return result.ToString();}
 [StructLayout(LayoutKind.Sequential)] struct UNICODE_STRING { public ushort Length,MaximumLength;public IntPtr Buffer; }
 [StructLayout(LayoutKind.Sequential)] struct OBJECT_ATTRIBUTES { public int Length;public IntPtr RootDirectory,ObjectName;public uint Attributes;public IntPtr SecurityDescriptor,SecurityQualityOfService; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateMutex(IntPtr attributes,bool initialOwner,string name);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenMutex(uint access,bool inherit,string name);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr value);
 [DllImport("ntdll.dll")] static extern int NtOpenDirectoryObject(out IntPtr result,uint access,ref OBJECT_ATTRIBUTES attributes);
 [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr handle,int type,uint info,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr descriptor,uint revision,uint info,out IntPtr text,out uint length);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
 static string Security(IntPtr handle) {
  IntPtr owner,group,dacl,sacl,descriptor,text;uint length;
  uint error=GetSecurityInfo(handle,6,5,out owner,out group,out dacl,out sacl,out descriptor);
  if(error!=0)return "GetSecurityInfoError:"+error;
  try{if(!ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor,1,5,out text,out length))return "ConvertSecurityError:"+Marshal.GetLastWin32Error();try{return Marshal.PtrToStringUni(text);}finally{LocalFree(text);}}finally{LocalFree(descriptor);}
 }
 public static object OwnedNonceMutex(string nonce){
  if(nonce==null||nonce.Length!=32||!System.Text.RegularExpressions.Regex.IsMatch(nonce,"^[0-9a-f]{32}$"))throw new InvalidOperationException("EXACT_OWNED_NONCE_REQUIRED");
  string name="Local\\LaoyuCleanerDiagnostic_"+nonce;IntPtr handle=CreateMutex(IntPtr.Zero,false,name);int error=Marshal.GetLastWin32Error();bool closed=handle==IntPtr.Zero||CloseHandle(handle);
  return new {name=name,initialOwner=false,createdNew=handle!=IntPtr.Zero&&error!=183,alreadyExisted=error==183,win32Error=error,closed=closed,accepted=handle!=IntPtr.Zero&&error!=183&&closed,scope="Own nonce object only; no wait, ownership, ACL edit or product mutex substitution"};
 }
 public static object Mutex(){
  const string name="Local\\LaoyuDiskCleanerProcessSingletonStartup";
  IntPtr handle=OpenMutex(0x20000,false,name);int error=handle==IntPtr.Zero?Marshal.GetLastWin32Error():0;
  try{return new {name=name,access="READ_CONTROL",opened=handle!=IntPtr.Zero,win32Error=error,security=handle==IntPtr.Zero?null:Security(handle)};}finally{if(handle!=IntPtr.Zero)CloseHandle(handle);}
 }
 public static object Directory(int session){
  string name="\\Sessions\\"+session+"\\BaseNamedObjects";
  IntPtr buffer=Marshal.StringToHGlobalUni(name),unicode=IntPtr.Zero,handle=IntPtr.Zero;
  try{UNICODE_STRING value=new UNICODE_STRING{Length=(ushort)(name.Length*2),MaximumLength=(ushort)((name.Length+1)*2),Buffer=buffer};unicode=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));Marshal.StructureToPtr(value,unicode,false);OBJECT_ATTRIBUTES attributes=new OBJECT_ATTRIBUTES{Length=Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),ObjectName=unicode,Attributes=0x40};int status=NtOpenDirectoryObject(out handle,0x20000,ref attributes);return new {name=name,access="READ_CONTROL",opened=status>=0,ntstatus="0x"+unchecked((uint)status).ToString("X8"),security=status<0?null:Security(handle)};}finally{if(handle!=IntPtr.Zero)CloseHandle(handle);if(unicode!=IntPtr.Zero)Marshal.FreeHGlobal(unicode);Marshal.FreeHGlobal(buffer);}
 }
 public static object Win32Directory(int session){
  string name="\\Sessions\\"+session+"\\BaseNamedObjects";
  IntPtr buffer=Marshal.StringToHGlobalUni(name),unicode=IntPtr.Zero,handle=IntPtr.Zero;
  try{UNICODE_STRING value=new UNICODE_STRING{Length=(ushort)(name.Length*2),MaximumLength=(ushort)((name.Length+1)*2),Buffer=buffer};unicode=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));Marshal.StructureToPtr(value,unicode,false);OBJECT_ATTRIBUTES attributes=new OBJECT_ATTRIBUTES{Length=Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),ObjectName=unicode,Attributes=0x40};int status=NtOpenDirectoryObject(out handle,0xf,ref attributes);return new {name=name,access="0xf observed BaseGetNamedObjectDirectory request; open/close only",opened=status>=0,ntstatus="0x"+unchecked((uint)status).ToString("X8"),security=status<0?null:Security(handle)};}finally{if(handle!=IntPtr.Zero)CloseHandle(handle);if(unicode!=IntPtr.Zero)Marshal.FreeHGlobal(unicode);Marshal.FreeHGlobal(buffer);}
 }
}
'@
$full=[CleanerSingletonReadOnly]::LongPath([IO.Path]::GetFullPath($DataDirectory))
$temp=[CleanerSingletonReadOnly]::LongPath([IO.Path]::GetFullPath([IO.Path]::GetTempPath()))
if(!$full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -ne 'data' -or [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($full)) -notmatch '^cleaner-desktop-probe-[a-zA-Z0-9]+$'){throw 'OWNED_DATA_DIRECTORY_REQUIRED'}
$session=[Diagnostics.Process]::GetCurrentProcess().SessionId
$paths=@($full,[IO.Path]::Combine($full,'lockfile'))|ForEach-Object {
 try{if(!(Test-Path -LiteralPath $_)){@{path=$_;exists=$false}}else{$item=Get-Item -Force -LiteralPath $_;$acl=Get-Acl -LiteralPath $_;@{path=$_;exists=$true;attributes=[string]$item.Attributes;owner=$acl.Owner;sddl=$acl.Sddl}}}catch{@{path=$_;error=[string]$_.Exception.Message}}
}
@{scope='Fixed security reads plus new owned nonce mutex create-and-close; no wait, ownership or ACL mutation';ownedNonceMutex=[CleanerSingletonReadOnly]::OwnedNonceMutex($env:CLEANER_CI_DESKTOP_NONCE);sessionId=$session;mutex=[CleanerSingletonReadOnly]::Mutex();objectDirectory=[CleanerSingletonReadOnly]::Directory($session);win32NamespaceOpen=[CleanerSingletonReadOnly]::Win32Directory($session);paths=@($paths)}|ConvertTo-Json -Depth 6 -Compress
