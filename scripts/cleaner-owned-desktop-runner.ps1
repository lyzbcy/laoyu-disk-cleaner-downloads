param([string]$NodeExe, [string]$ProjectRoot, [switch]$FullSuite)
# Isolated GitHub Actions only. Account/password exist solely in this process/temporary Windows SAM.
$ErrorActionPreference = 'Stop'
$env:PSModulePath = $PSHOME + '\Modules;' + [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
$ownedSource=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'cleaner-owned-desktop.cs'))
$ownedSource=[Text.RegularExpressions.Regex]::Replace($ownedSource,'(?m)^using [^;]+;\r?\n','')
$runnerSource=@'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
public static class CleanerOwnedDesktopRunner {

  public static Dictionary<string,object> Diagnostic = new Dictionary<string,object>{{"scope","new ordinary OS account/profile and CI-owned interactive desktop; unique token logon-session station ACE temporarily added, exact restoration required; Default/profile ACLs never changed"}};
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenMutex(uint access,bool inherit,string name);
  [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr handle,int type,uint info,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
  [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
  [DllImport("ntdll.dll")] static extern int NtOpenDirectoryObject(out IntPtr handle,uint access,ref ObjectAttributes attributes);
  static object ParentNamespaceSecurity() {
    string name="\\Sessions\\"+System.Diagnostics.Process.GetCurrentProcess().SessionId+"\\BaseNamedObjects";var row=new Dictionary<string,object>{{"name",name},{"scope","parent original identity; READ_CONTROL owner and DACL only"}};IntPtr text=Marshal.StringToHGlobalUni(name),unicode=IntPtr.Zero,handle=IntPtr.Zero;
    try{var value=new UnicodeString{Length=(ushort)(name.Length*2),MaximumLength=(ushort)((name.Length+1)*2),Buffer=text};unicode=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));Marshal.StructureToPtr(value,unicode,false);var attributes=new ObjectAttributes{Length=(uint)Marshal.SizeOf(typeof(ObjectAttributes)),ObjectName=unicode,Attributes=0x40};int status=NtOpenDirectoryObject(out handle,0x20000,ref attributes);row["ntstatus"]="0x"+unchecked((uint)status).ToString("X8");row["opened"]=status>=0;if(status>=0){IntPtr owner,group,dacl,sacl,descriptor;uint code=GetSecurityInfo(handle,6,5,out owner,out group,out dacl,out sacl,out descriptor);row["securityError"]=code;if(code==0){try{uint length=GetSecurityDescriptorLength(descriptor);if(length<20||length>65536)throw new InvalidOperationException("NAMESPACE_SECURITY_BOUND");byte[] bytes=new byte[length];Marshal.Copy(descriptor,bytes,0,(int)length);row["descriptorBase64"]=Convert.ToBase64String(bytes);row["sddl"]=new System.Security.AccessControl.RawSecurityDescriptor(bytes,0).GetSddlForm(System.Security.AccessControl.AccessControlSections.Owner|System.Security.AccessControl.AccessControlSections.Access);}finally{LocalFree(descriptor);}}}}catch(Exception e){row["error"]=e.Message.Substring(0,Math.Min(e.Message.Length,2048));}finally{if(handle!=IntPtr.Zero)row["closed"]=CloseHandle(handle);if(unicode!=IntPtr.Zero)Marshal.FreeHGlobal(unicode);Marshal.FreeHGlobal(text);}return row;
  }
  static object ProductMutexSecurity(string phase) {
    const string name="Local\\LaoyuDiskCleanerProcessSingletonStartup";var row=new Dictionary<string,object>{{"scope","parent original identity; fixed product mutex READ_CONTROL only"},{"phase",phase},{"name",name},{"sessionId",System.Diagnostics.Process.GetCurrentProcess().SessionId}};
    IntPtr handle=OpenMutex(0x20000,false,name);int error=handle==IntPtr.Zero?Marshal.GetLastWin32Error():0;row["opened"]=handle!=IntPtr.Zero;row["win32Error"]=error;
    try{if(handle!=IntPtr.Zero){IntPtr owner,group,dacl,sacl,descriptor;uint code=GetSecurityInfo(handle,6,5,out owner,out group,out dacl,out sacl,out descriptor);row["securityError"]=code;if(code==0){try{uint length=GetSecurityDescriptorLength(descriptor);if(length<20||length>65536)throw new InvalidOperationException("MUTEX_SECURITY_BOUND");byte[] bytes=new byte[length];Marshal.Copy(descriptor,bytes,0,(int)length);row["sddl"]=new System.Security.AccessControl.RawSecurityDescriptor(bytes,0).GetSddlForm(System.Security.AccessControl.AccessControlSections.Owner|System.Security.AccessControl.AccessControlSections.Access);}finally{LocalFree(descriptor);}}}}catch(Exception e){row["readError"]=e.Message.Substring(0,Math.Min(e.Message.Length,2048));}finally{if(handle!=IntPtr.Zero)row["handleClosed"]=CloseHandle(handle);}
    return row;
  }
  [StructLayout(LayoutKind.Sequential)] struct GenericMapping { public uint Read,Write,Execute,All; }
  [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();
  [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(uint thread);
  [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
  [DllImport("user32.dll",SetLastError=true)] static extern bool GetUserObjectSecurity(IntPtr handle,ref uint info,[Out] byte[] bytes,uint size,out uint needed);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool DuplicateTokenEx(SafeAccessTokenHandle token,uint access,IntPtr attributes,int level,int type,out SafeAccessTokenHandle copy);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool AccessCheck(byte[] descriptor,SafeAccessTokenHandle token,uint desired,ref GenericMapping mapping,IntPtr privileges,ref uint size,out uint granted,out bool allowed);
  static byte[] ReadDesktopSecurity(IntPtr handle) { uint info=7,needed;var bytes=new byte[65536];Check(GetUserObjectSecurity(handle,ref info,bytes,(uint)bytes.Length,out needed));if(needed<20||needed>bytes.Length)throw new InvalidOperationException("DESKTOP_SECURITY_BOUND");Array.Resize(ref bytes,(int)needed);return bytes; }
  static Dictionary<string,object> DesktopEvidence(SafeAccessTokenHandle token) {
    var rows=new Dictionary<string,object>();
    foreach(string kind in new[]{"windowStation","desktop"}) {
      try { byte[] bytes=ReadDesktopSecurity(kind=="windowStation"?GetProcessWindowStation():GetThreadDesktop(GetCurrentThreadId()));
        var row=new Dictionary<string,object>{{"ok",true},{"descriptorBase64",Convert.ToBase64String(bytes)},{"sddl",new System.Security.AccessControl.RawSecurityDescriptor(bytes,0).GetSddlForm(System.Security.AccessControl.AccessControlSections.All)},{"observedIn","parent; AccessCheck uses the designated token; actual child token evidence is separate"}};
        if(token!=null) { SafeAccessTokenHandle copy;Check(DuplicateTokenEx(token,8,IntPtr.Zero,2,2,out copy));using(copy) { var mapping=kind=="windowStation"?new GenericMapping{Read=0x20303,Write=0x2001C,Execute=0x20060,All=0xF037F}:new GenericMapping{Read=0x20041,Write=0x200BE,Execute=0x20100,All=0xF01FF};IntPtr privileges=Marshal.AllocHGlobal(65536);try { uint size=65536,granted;bool allowed;Check(AccessCheck(bytes,copy,0x02000000,ref mapping,privileges,ref size,out granted,out allowed));row["accessCheckAllowed"]=allowed;row["grantedMask"]=granted;row["requested"]="MAXIMUM_ALLOWED; diagnostic only, not a full-control gate"; }finally {Marshal.FreeHGlobal(privileges);} } }
        rows[kind]=row;
      } catch(Exception error) { var native=error as Win32Exception;rows[kind]=new Dictionary<string,object>{{"ok",false},{"nativeErrorCode",native==null?(object)null:native.NativeErrorCode},{"error",error.Message.Substring(0,Math.Min(error.Message.Length,2048))}}; }
    } return rows;
  }
  static bool SameDesktopDescriptors(Dictionary<string,object> before,Dictionary<string,object> after) { foreach(string kind in new[]{"windowStation","desktop"}) { var a=before[kind] as Dictionary<string,object>;var b=after[kind] as Dictionary<string,object>;if(!(bool)a["ok"]||!(bool)b["ok"]||!Equals(a["descriptorBase64"],b["descriptorBase64"]))return false; }return true; }

  [DllImport("advapi32.dll",SetLastError=true)] static extern bool ImpersonateLoggedOnUser(SafeAccessTokenHandle token);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool RevertToSelf();
  public static bool ReadOnlyProbeThreadEnded=true;
  public static void InIsolatedThread(Action inspect,Action revert) {
    Exception failure=null;ReadOnlyProbeThreadEnded=false;
    var worker=new System.Threading.Thread(delegate(){try{inspect();}catch(Exception e){failure=e;}finally{try{revert();}catch(Exception e){failure=e;}}});
    worker.IsBackground=true;worker.Start();if(!worker.Join(30000))throw new InvalidOperationException("READ_ONLY_PROBE_THREAD_TIMEOUT");ReadOnlyProbeThreadEnded=true;if(failure!=null)throw new InvalidOperationException("READ_ONLY_PROBE_THREAD_FAILED",failure);
  }
  public sealed class TokenHandleHandoff<T>:IDisposable where T:class,IDisposable {
    readonly object gate=new object();T pending;bool closed;
    public void Offer(T value){if(value==null)throw new ArgumentNullException("value");lock(gate){if(!closed&&pending==null){pending=value;return;}}value.Dispose();}
    public T Take(){lock(gate){if(closed||pending==null)throw new InvalidOperationException("TOKEN_HANDLE_NOT_READY");closed=true;T value=pending;pending=null;return value;}}
    public void Dispose(){T value;lock(gate){closed=true;value=pending;pending=null;}if(value!=null)value.Dispose();}
  }
  static SafeAccessTokenHandle ReadActualChildToken(SafeAccessTokenHandle source,IntPtr process){
    using(var handoff=new TokenHandleHandoff<SafeAccessTokenHandle>()){
      InIsolatedThread(delegate{Check(ImpersonateLoggedOnUser(source));SafeAccessTokenHandle actual;bool opened=OpenProcessToken(process,0xA,out actual);if(!opened){int error=Marshal.GetLastWin32Error();if(actual!=null)actual.Dispose();throw new Win32Exception(error);}handoff.Offer(actual);},delegate{Check(RevertToSelf());});
      return handoff.Take();
    }
  }
  static List<Dictionary<string,object>> TargetFileAccess(SafeAccessTokenHandle token,string node,string project,bool fullSuite) {
    var rows=new List<Dictionary<string,object>>();
    InIsolatedThread(delegate {Check(ImpersonateLoggedOnUser(token));
      foreach(string file in new[]{node,project,Path.Combine(project,"scripts",fullSuite?"cleaner-owned-suite.cjs":"cleaner-owned-desktop-probe.cjs"),Path.Combine(project,"candidate","LaoyuDiskCleaner.exe"),Path.Combine(project,"candidate","resources","app","package.json")}) {
        var row=new Dictionary<string,object>{{"path",file},{"scope","read-only CreateFile under designated ordinary logon token"}};rows.Add(row);
        try {bool dir=String.Equals(file,project,StringComparison.OrdinalIgnoreCase);var security=new SecurityAttributes{Length=Marshal.SizeOf(typeof(SecurityAttributes)),Inherit=false};using(var handle=CreateFile(file,dir?0x81u:0xA0000000u,7,ref security,3,dir?0x02000000u:0u,IntPtr.Zero)){int code=Marshal.GetLastWin32Error();row["accessible"]=!handle.IsInvalid;row["requestedMask"]=dir?0x81u:0xA0000000u;if(handle.IsInvalid)row["nativeError"]=code;}}
        catch(Exception e){row["accessible"]=false;row["error"]=e.Message;}
      }
    },delegate{Check(RevertToSelf());});return rows;
  }
  public static bool MayDeleteAccount(bool created,bool ownedStopped,bool profileLoadAttempted,bool profileLoaded,bool profileDeleted) { return created && ownedStopped && !profileLoaded && (!profileLoadAttempted || profileDeleted); }
  public static string RequestedDesktop() { return @"winsta0\default"; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct UserInfo { public string Name, Password; public uint PasswordAge, Priv; public string Home, Comment; public uint Flags; public string Script; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Member { public string Name; }
  [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
  [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes { public uint Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr Descriptor, Quality; }
  [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
  [StructLayout(LayoutKind.Sequential)] struct Privileges { public uint Count; public Luid Id; public uint Attributes; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Profile { public uint Size, Flags; public string UserName, ProfilePath, DefaultPath, ServerName, PolicyPath; public IntPtr Handle; }
  [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup { public uint Size; public string Reserved, Desktop, Title; public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags; public ushort Show,ReservedSize; public IntPtr ReservedData,Input,Output,Error; }
  [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process, Thread; public uint Pid, Tid; }
  [StructLayout(LayoutKind.Sequential)] struct JobBasic { public long ProcessTime, JobTime; public uint Flags; public UIntPtr Min,Max; public uint Active; public UIntPtr Affinity; public uint Priority,Scheduling; }
  [StructLayout(LayoutKind.Sequential)] struct JobAccounting { public long UserTime,KernelTime,PeriodUserTime,PeriodKernelTime; public uint PageFaults,TotalProcesses,ActiveProcesses,TerminatedProcesses; }
  [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong Read,Write,Other,ReadBytes,WriteBytes,OtherBytes; }
  [StructLayout(LayoutKind.Sequential)] struct JobExtended { public JobBasic Basic; public IoCounters Io; public UIntPtr ProcessMemory,JobMemory,PeakProcess,PeakJob; }
  [DllImport("netapi32.dll", CharSet=CharSet.Unicode)] static extern uint NetUserAdd(string server,uint level,ref UserInfo info,out uint parameter);
  [DllImport("netapi32.dll", CharSet=CharSet.Unicode)] static extern uint NetUserDel(string server,string user);
  [DllImport("netapi32.dll", CharSet=CharSet.Unicode)] static extern uint NetLocalGroupAddMembers(string server,string group,uint level,ref Member member,uint count);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LogonUser(string user,string domain,string password,uint type,uint provider,out SafeAccessTokenHandle token);
  [DllImport("userenv.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LoadUserProfile(SafeAccessTokenHandle token,ref Profile profile);
  [DllImport("userenv.dll", SetLastError=true)] static extern bool UnloadUserProfile(SafeAccessTokenHandle token,IntPtr profile);
  [DllImport("userenv.dll", SetLastError=true)] static extern bool CreateEnvironmentBlock(out IntPtr environment,SafeAccessTokenHandle token,bool inherit);
  [DllImport("userenv.dll")] static extern bool DestroyEnvironmentBlock(IntPtr environment);
  [DllImport("userenv.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool GetUserProfileDirectory(SafeAccessTokenHandle token,StringBuilder path,ref uint size);
  [DllImport("userenv.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool DeleteProfile(string sid,string path,string computer);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessWithTokenW(SafeAccessTokenHandle token,uint logon,string app,StringBuilder command,uint flags,IntPtr environment,string directory,ref Startup startup,out ProcessInfo process);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out SafeAccessTokenHandle token);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid id);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle token,bool disable,ref Privileges state,uint size,IntPtr old,IntPtr returned);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFile(string path,uint access,uint share,ref SecurityAttributes security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr security,string name);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int type,ref JobExtended info,uint size);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int type,out JobAccounting info,uint size,IntPtr returned);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
  [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
  [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool ProcessIdToSessionId(uint pid,out uint session);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool contained);
  static Dictionary<string,object> ProcessBoundary(IntPtr process,uint pid){var row=new Dictionary<string,object>{{"pid",pid},{"readOnly",true}};uint value;bool ok=GetExitCodeProcess(process,out value);row["exitCodeReadable"]=ok;if(ok)row["exitCode"]=value;else row["exitCodeError"]=Marshal.GetLastWin32Error();ok=ProcessIdToSessionId(pid,out value);row["sessionReadable"]=ok;if(ok)row["session"]=value;else row["sessionError"]=Marshal.GetLastWin32Error();bool contained;ok=IsProcessInJob(process,IntPtr.Zero,out contained);row["jobReadable"]=ok;if(ok)row["inAnyJob"]=contained;else row["jobReadError"]=Marshal.GetLastWin32Error();return row;}
  static void Check(bool ok) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(SafeAccessTokenHandle token,int type,IntPtr info,uint size,out uint needed);
  [StructLayout(LayoutKind.Sequential)] struct SidAttribute {public IntPtr Sid;public uint Attributes;}
  static string TokenLogonSid(SafeAccessTokenHandle token){IntPtr bytes=Marshal.AllocHGlobal(65536);try{uint needed;Check(GetTokenInformation(token,2,bytes,65536,out needed));int count=Marshal.ReadInt32(bytes),offset=IntPtr.Size==8?8:4,stride=Marshal.SizeOf(typeof(SidAttribute));if(count<1||count>4096||offset+count*stride>needed)throw new InvalidOperationException("TOKEN_GROUPS_BOUND");var sids=new List<string>();var attributes=new List<uint>();for(int i=0;i<count;i++){var row=(SidAttribute)Marshal.PtrToStructure(IntPtr.Add(bytes,offset+i*stride),typeof(SidAttribute));if((row.Attributes&0xc0000000)==0xc0000000){long pointer=row.Sid.ToInt64(),start=bytes.ToInt64();if(pointer<start||pointer>start+needed-8)throw new InvalidOperationException("TOKEN_LOGON_POINTER_BOUND");int length=8+Marshal.ReadByte(row.Sid,1)*4;if(length>68||pointer+length>start+needed)throw new InvalidOperationException("TOKEN_LOGON_SID_BOUND");sids.Add(new SecurityIdentifier(row.Sid).Value);attributes.Add(row.Attributes);}}return CleanerOwnedDesktop.RequireLogonSid(sids.ToArray(),attributes.ToArray());}finally{Marshal.FreeHGlobal(bytes);}}
  static Dictionary<string,object> ExistingImpersonate(){SafeAccessTokenHandle current;Check(OpenProcessToken(GetCurrentProcess(),8,out current));using(current){Luid id;Check(LookupPrivilegeValue(null,"SeImpersonatePrivilege",out id));IntPtr bytes=Marshal.AllocHGlobal(65536);try{uint needed;Check(GetTokenInformation(current,3,bytes,65536,out needed));int count=Marshal.ReadInt32(bytes);if(count<0||count>4096||4+count*12>needed)throw new InvalidOperationException("TOKEN_PRIVILEGES_BOUND");for(int i=0;i<count;i++){int p=4+i*12;if((uint)Marshal.ReadInt32(bytes,p)==id.Low&&Marshal.ReadInt32(bytes,p+4)==id.High){uint attributes=(uint)Marshal.ReadInt32(bytes,p+8);return new Dictionary<string,object>{{"present",true},{"enabled",(attributes&2)!=0},{"attributes",attributes},{"modified",false}};}}return new Dictionary<string,object>{{"present",false},{"enabled",false},{"modified",false}};}finally{Marshal.FreeHGlobal(bytes);}}}
  static void Enable(string name) {
    SafeAccessTokenHandle token; Check(OpenProcessToken(GetCurrentProcess(),0x28,out token));
    using(token) { var state=new Privileges { Count=1,Attributes=2 }; Check(LookupPrivilegeValue(null,name,out state.Id)); Check(AdjustTokenPrivileges(token,false,ref state,0,IntPtr.Zero,IntPtr.Zero)); int error=Marshal.GetLastWin32Error(); if(error!=0) throw new Win32Exception(error); }
  }
  static string ProfilePath(SafeAccessTokenHandle token) { uint size=0; GetUserProfileDirectory(token,null,ref size); if(size<1||size>32768) throw new InvalidOperationException("PROFILE_PATH_BOUND"); var path=new StringBuilder((int)size); Check(GetUserProfileDirectory(token,path,ref size)); return path.ToString(); }
  static IntPtr TestEnvironment(IntPtr native,string user,string sid,string profile,string desktopNonce,string logonSid) {
    var entries=new List<string>(); int offset=0;
    while(true) { string entry=Marshal.PtrToStringUni(IntPtr.Add(native,offset)); if(entry.Length==0) break; offset+=(entry.Length+1)*2; if(offset>262144) throw new InvalidOperationException("ENVIRONMENT_BOUND"); entries.Add(entry); }
    // Preserve every OS-created USERPROFILE/HOME/TEMP entry unchanged; only append test assertions/context.
    entries.Add("CLEANER_CI_EXPECTED_LOGON_SID="+logonSid); entries.Add("CLEANER_CI_DESKTOP_NONCE="+desktopNonce); entries.Add("CLEANER_STANDARD_USER_CI=1"); entries.Add("CLEANER_CI_EXPECTED_USERNAME="+user); entries.Add("CLEANER_CI_EXPECTED_SID="+sid); entries.Add("CLEANER_CI_OS_PROFILE="+profile);

    entries.Add("GITHUB_ACTIONS=true"); entries.Add("CI=true");
    entries.Add("GITHUB_WORKSPACE="+Environment.GetEnvironmentVariable("GITHUB_WORKSPACE"));
    entries.Add("CLEANER_CI_PARENT_SESSION="+System.Diagnostics.Process.GetCurrentProcess().SessionId);
    entries.Add("CLEANER_PACKAGED_APP="+Path.Combine(Environment.GetEnvironmentVariable("GITHUB_WORKSPACE"),"candidate"));
    entries.Sort(StringComparer.OrdinalIgnoreCase); return Marshal.StringToHGlobalUni(String.Join("\0",entries.ToArray())+"\0\0");
  }
  // Bounded policies are exercised without native calls by the compile-only test.
  public static bool WaitForOwnedJobExit(Func<uint> active,Action<int> sleep,int attempts) {
    if(attempts<1||attempts>101) throw new ArgumentOutOfRangeException("attempts");
    for(int i=0;i<attempts;i++) { if(active()==0) return true; if(i+1<attempts) sleep(200); }
    return false;
  }
  public static int RetryProfileDelete(Func<int> attempt,Action<int> sleep,int attempts) {
    if(attempts<1||attempts>101) throw new ArgumentOutOfRangeException("attempts");
    int error=0; for(int i=0;i<attempts;i++) { error=attempt(); if(error!=32) return error; if(i+1<attempts) sleep(200); }
    return error;
  }
  public static int Run(string node,string project,Action<string,string> grantOutput,bool fullSuite) {
    Diagnostic["scope"]=fullSuite?"original candidate GUI and isolated owned file actions plus visible installer/default-data reopen in disposable ordinary-user interactive desktop":"ordinary-user CI-owned interactive desktop startup diagnostic only";
    if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true") throw new InvalidOperationException("ISOLATED_GHA_ONLY");
    if(!Path.IsPathRooted(node)||!Path.IsPathRooted(project)||node.Contains("\"")||project.Contains("\"")||!String.Equals(Path.GetFullPath(project),Path.GetFullPath(Environment.GetEnvironmentVariable("GITHUB_WORKSPACE")),StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("INVALID_RUNNER_PATH");
    Diagnostic["parentNamespaceSecurity"]=ParentNamespaceSecurity();Diagnostic["parentProductMutexBefore"]=ProductMutexSecurity("before-new-account");
    string user="cln"+Guid.NewGuid().ToString("N").Substring(0,12), password;
    CleanerOwnedDesktop ownedDesktop=null;
    byte[] random=new byte[24]; using(var rng=RandomNumberGenerator.Create()) rng.GetBytes(random); password=Convert.ToBase64String(random)+"aA1!"; Array.Clear(random,0,random.Length);
    bool created=false,profileLoadAttempted=false,profileDeleted=false,profileLoaded=false,profileEverLoaded=false,processExited=false; string stage="account-create",sidValue=null,logonSid=null; SecurityIdentifier sid=null; SafeAccessTokenHandle token=null; IntPtr nativeEnv=IntPtr.Zero,testEnv=IntPtr.Zero,job=IntPtr.Zero; Profile profile=new Profile(); ProcessInfo process=new ProcessInfo(); int exit=1;
    var cleanup=new List<string>();
    try {
      var info=new UserInfo { Name=user,Password=password,Priv=1,Flags=0x10201,Comment="Disposable candidate desktop diagnostic user" }; uint parameter; uint status=NetUserAdd(null,1,ref info,out parameter); if(status!=0) throw new Win32Exception((int)status); created=true;
      stage="users-group"; string group=new SecurityIdentifier("S-1-5-32-545").Translate(typeof(NTAccount)).Value.Split('\\')[1]; var member=new Member { Name=Environment.MachineName+"\\"+user }; status=NetLocalGroupAddMembers(null,group,3,ref member,1); if(status!=0) throw new Win32Exception((int)status);
      sid=(SecurityIdentifier)new NTAccount(Environment.MachineName,user).Translate(typeof(SecurityIdentifier)); sidValue=sid.Value;
      stage="profile-privileges"; Enable("SeBackupPrivilege"); Enable("SeRestorePrivilege");
      stage="standard-user-logon"; Check(LogonUser(user,".",password,2,0,out token));
      stage="os-profile-load"; profile.Size=(uint)Marshal.SizeOf(typeof(Profile)); profile.Flags=1; profile.UserName=user; profileLoadAttempted=true; Check(LoadUserProfile(token,ref profile)); profileLoaded=true; profileEverLoaded=true;
      stage="ci-owned-interactive-desktop";logonSid=TokenLogonSid(token);Diagnostic["expectedLogonSid"]=logonSid;ownedDesktop=new CleanerOwnedDesktop(sidValue,logonSid,Guid.NewGuid().ToString("N"));ownedDesktop.Prepare();Diagnostic["ownedDesktop"]=ownedDesktop.Evidence;
      string actualProfile=ProfilePath(token); Diagnostic["profile"]=actualProfile;Diagnostic["sid"]=sidValue;Diagnostic["requestedDesktop"]=ownedDesktop.RequestedDesktop;Diagnostic["desktopBefore"]=DesktopEvidence(token); stage="os-environment-block"; Check(CreateEnvironmentBlock(out nativeEnv,token,false)); testEnv=TestEnvironment(nativeEnv,user,sidValue,actualProfile,ownedDesktop.RequestedDesktop.Substring("winsta0\\LaoyuCleaner_".Length),logonSid);
      stage="ci-owned-artifact-permission"; grantOutput(sidValue,actualProfile);
      Diagnostic["prelaunchTargetFiles"]=TargetFileAccess(token,node,project,fullSuite);Diagnostic["prelaunchOwnedDesktopAccess"]=ownedDesktop.Access(token.DangerousGetHandle());
      string output=Path.Combine(project,"verification","core","windows-standard-user-bootstrap.txt"); var security=new SecurityAttributes { Length=Marshal.SizeOf(typeof(SecurityAttributes)),Inherit=true };
      using(var outFile=CreateFile(output,0x40000000,3,ref security,2,0,IntPtr.Zero)) using(var input=CreateFile("NUL",0x80000000,3,ref security,3,0,IntPtr.Zero)) {
        if(outFile.IsInvalid||input.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        stage="owned-child-job"; job=CreateJobObject(IntPtr.Zero,null); Check(job!=IntPtr.Zero); var limits=new JobExtended(); limits.Basic.Flags=0x2000; Check(SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(JobExtended))));
        var startup=new Startup { Size=(uint)Marshal.SizeOf(typeof(Startup)),Desktop=ownedDesktop.RequestedDesktop,Flags=0x100,Input=input.DangerousGetHandle(),Output=outFile.DangerousGetHandle(),Error=outFile.DangerousGetHandle() };
        string suite=Path.Combine(project,"scripts",fullSuite?"cleaner-owned-suite.cjs":"cleaner-owned-desktop-probe.cjs"); string command="\""+node+"\" \""+suite+"\"";
        stage="create-process-with-existing-primary-token"; Diagnostic["launchApi"]="CreateProcessWithTokenW; existing primary token; logonFlags=0; explicit owned desktop";Diagnostic["existingSeImpersonatePrivilege"]=ExistingImpersonate();Check(CreateProcessWithTokenW(token,0,node,new StringBuilder(command),0x404,testEnv,project,ref startup,out process));Diagnostic["createProcessSucceeded"]=true;Diagnostic["createdChildPid"]=process.Pid;Diagnostic["createdProcessHandleNonzero"]=process.Process!=IntPtr.Zero;Diagnostic["createdThreadHandleNonzero"]=process.Thread!=IntPtr.Zero;Diagnostic["createdChildReadOnly"]=ProcessBoundary(process.Process,process.Pid);Diagnostic["parentReadOnly"]=ProcessBoundary(GetCurrentProcess(),(uint)System.Diagnostics.Process.GetCurrentProcess().Id);
        stage="assign-owned-child-job";Check(AssignProcessToJobObject(job,process.Process));Diagnostic["ownedJobAssigned"]=true;
        stage="open-actual-child-token";SafeAccessTokenHandle actualChild=ReadActualChildToken(token,process.Process);Diagnostic["actualChildTokenOpened"]=true;using(actualChild){stage="verify-actual-child-logon";string actualLogon=TokenLogonSid(actualChild);Diagnostic["actualChildLogonSid"]=actualLogon;if(actualLogon!=logonSid)throw new InvalidOperationException("ACTUAL_CHILD_LOGON_SESSION_MISMATCH");Diagnostic["actualChildAccess"]=DesktopEvidence(actualChild);stage="verify-actual-child-profile";Diagnostic["actualChildProfile"]=ProfilePath(actualChild);}
        stage="verify-launch-security";ownedDesktop.VerifyStillPrepared();
        stage="resume-owned-child";if(ResumeThread(process.Thread)==UInt32.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error());
        Console.WriteLine("STANDARD_USER_STARTED user="+user+" sid="+sidValue+" nativeProfile="+actualProfile+" accountGroup=Users");
        stage="owned-child-result"; uint wait=WaitForSingleObject(process.Process,fullSuite?900000u:360000u); if(wait!=0) throw new InvalidOperationException("OWNED_TEST_PROCESS_TIMEOUT_OR_WAIT_FAILURE"); processExited=true; uint code; Check(GetExitCodeProcess(process.Process,out code)); Diagnostic["childExitCode"]=code;exit=code==0?0:1;
      }
    } catch(Exception error) { var cause=error.GetBaseException();var nativeCause=cause as Win32Exception;Diagnostic["error"]=new Dictionary<string,object>{{"stage",stage},{"type",error.GetType().Name},{"message",error.Message.Substring(0,Math.Min(error.Message.Length,4096))},{"rootType",cause.GetType().Name},{"rootMessage",cause.Message.Substring(0,Math.Min(cause.Message.Length,4096))},{"nativeErrorCode",nativeCause==null?(object)null:nativeCause.NativeErrorCode}};Console.Error.WriteLine("STANDARD_USER_RUNNER_FAILED stage="+stage+" type="+error.GetType().Name+" message="+error.Message); exit=1; }
    finally {
      // Only our suspended child and private job may be terminated. Closing a
      // kill-on-close handle alone does not mean descendants released the profile.
      bool ownedStopped=ReadOnlyProbeThreadEnded;
      if(process.Process!=IntPtr.Zero&&!processExited) { TerminateProcess(process.Process,1); if(WaitForSingleObject(process.Process,10000)!=0) { ownedStopped=false; cleanup.Add("owned-root-stop-timeout"); } }
      if(job!=IntPtr.Zero) {
        try {
          Check(TerminateJobObject(job,1));
          bool settled=WaitForOwnedJobExit(delegate { JobAccounting info; Check(QueryInformationJobObject(job,1,out info,(uint)Marshal.SizeOf(typeof(JobAccounting)),IntPtr.Zero)); return info.ActiveProcesses; },System.Threading.Thread.Sleep,51);
          if(!settled) { ownedStopped=false; cleanup.Add("owned-job-stop-timeout"); }
          Diagnostic["ownedJobEmpty"]=settled;Console.WriteLine("STANDARD_USER_JOB_SETTLED="+settled);
        } catch(Exception error) { ownedStopped=false; cleanup.Add("owned-job-stop="+error.Message); }
        CloseHandle(job);
      }
      if(process.Thread!=IntPtr.Zero) CloseHandle(process.Thread); if(process.Process!=IntPtr.Zero) CloseHandle(process.Process);
      if(testEnv!=IntPtr.Zero) Marshal.FreeHGlobal(testEnv); if(nativeEnv!=IntPtr.Zero) DestroyEnvironmentBlock(nativeEnv);
      bool desktopRestored=true;
      Diagnostic["parentProductMutexAfter"]=ProductMutexSecurity("after-owned-job-cleanup-before-desktop-restore");
      if(ownedDesktop!=null){var desktopErrors=ownedDesktop.Restore(ownedStopped);Diagnostic["ownedDesktop"]=ownedDesktop.Evidence;cleanup.AddRange(desktopErrors);desktopRestored=desktopErrors.Count==0;}
      if(profileLoaded&&ownedStopped) { if(UnloadUserProfile(token,profile.Handle)) profileLoaded=false; else cleanup.Add("profile-unload="+Marshal.GetLastWin32Error()); }
      if(created&&sidValue!=null&&profileEverLoaded&&!profileLoaded&&ownedStopped&&desktopRestored) {
        int attempts=0; int deletionError=RetryProfileDelete(delegate { attempts++; return DeleteProfile(sidValue,null,null)?0:Marshal.GetLastWin32Error(); },System.Threading.Thread.Sleep,51);
        Console.WriteLine("STANDARD_USER_PROFILE_DELETE_ATTEMPTS="+attempts+" error="+deletionError);
        profileDeleted=deletionError==0;Diagnostic["profileDeleteError"]=deletionError;if(deletionError!=0) cleanup.Add("new-profile-delete="+deletionError);
      }
      if(token!=null) { Diagnostic["desktopAfter"]=DesktopEvidence(token); token.Dispose(); }
      if(desktopRestored&&MayDeleteAccount(created,ownedStopped,profileLoadAttempted,profileLoaded,profileDeleted)) { uint status=NetUserDel(null,user);Diagnostic["accountDeleteError"]=status; if(status!=0) cleanup.Add("new-account-delete="+status); }
      else if(created) { Diagnostic["accountRetained"]=true;cleanup.Add("new-account-retained-job-or-profile-cleanup-unconfirmed"); }
      Diagnostic["profileLoadAttempted"]=profileLoadAttempted;Diagnostic["profileDeleted"]=profileDeleted;Diagnostic["profileStillLoaded"]=profileLoaded;
      password=null;
      Console.WriteLine("STANDARD_USER_CLEANUP accountCreated="+created+" errors="+String.Join(",",cleanup.ToArray())); if(cleanup.Count>0) exit=1;
    }
    Diagnostic["exit"]=exit;Diagnostic["cleanupErrors"]=cleanup;return exit;
  }
}
'@
Add-Type -TypeDefinition ($runnerSource + [Environment]::NewLine + $ownedSource)
# No arguments is a compile-only/EOF check; no account/profile/native action is performed.
if (!$NodeExe -and !$ProjectRoot) { [Console]::Out.WriteLine([CleanerOwnedDesktopRunner]::RequestedDesktop()); exit 0 }
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'ISOLATED_GHA_ONLY' }
$outputDirectory = [IO.Path]::Combine($ProjectRoot, 'verification', 'core')
[IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
$grantOutput = [Action[string,string]] {
  param($sidValue, $actualProfile)
  # Only the disposable CI checkout gets read/execute; only its evidence directory gets Modify.
  $sourceAcl = [IO.Directory]::GetAccessControl($ProjectRoot)
  $readRule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sidValue), 'ReadAndExecute', [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit', [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
  $sourceAcl.AddAccessRule($readRule)
  [IO.Directory]::SetAccessControl($ProjectRoot, $sourceAcl)
  $acl = [IO.Directory]::GetAccessControl($outputDirectory)
  $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sidValue), 'Modify', [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit', [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
  $acl.AddAccessRule($rule)
  [IO.Directory]::SetAccessControl($outputDirectory, $acl)

}
$code=[CleanerOwnedDesktopRunner]::Run($NodeExe, $ProjectRoot, $grantOutput, [bool]$FullSuite)
[IO.File]::WriteAllText((Join-Path $outputDirectory 'owned-launcher-report.json'),([CleanerOwnedDesktopRunner]::Diagnostic|ConvertTo-Json -Depth 16),(New-Object Text.UTF8Encoding($false)))
exit $code
