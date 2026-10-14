using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class CleanerRestrictedProbe {
 [StructLayout(LayoutKind.Sequential)] struct SidEntry { public IntPtr Sid; public uint Attributes; }
 [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
 [StructLayout(LayoutKind.Sequential)] struct Privilege { public Luid Id; public uint Attributes; }
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup { public uint Size; public string Reserved,Desktop,Title; public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags; public ushort Show,ReservedSize; public IntPtr ReservedData,Input,Output,Error; }
 [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process,Thread; public uint Pid,Tid; }
 [StructLayout(LayoutKind.Sequential)] struct JobBasic { public long ProcessTime,JobTime; public uint Flags; public UIntPtr Min,Max; public uint Active; public UIntPtr Affinity; public uint Priority,Scheduling; }
 [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong Read,Write,Other,ReadBytes,WriteBytes,OtherBytes; }
 [StructLayout(LayoutKind.Sequential)] struct JobExtended { public JobBasic Basic; public IoCounters Io; public UIntPtr ProcessMemory,JobMemory,PeakProcess,PeakJob; }
 [StructLayout(LayoutKind.Sequential)] struct JobAccounting { public long UserTime,KernelTime,PeriodUserTime,PeriodKernelTime; public uint PageFaults,TotalProcesses,ActiveProcesses,TerminatedProcesses; }
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out SafeAccessTokenHandle token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(SafeAccessTokenHandle token,int kind,IntPtr value,uint length,out uint required);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool SetTokenInformation(SafeAccessTokenHandle token,int kind,IntPtr value,uint length);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool CreateRestrictedToken(SafeAccessTokenHandle source,uint flags,uint disableCount,[In] SidEntry[] disabled,uint privilegeCount,IntPtr privileges,uint restrictCount,IntPtr restrict,out SafeAccessTokenHandle token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool DuplicateTokenEx(SafeAccessTokenHandle token,uint access,IntPtr attrs,int level,int type,out SafeAccessTokenHandle copy);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool CheckTokenMembership(SafeAccessTokenHandle token,IntPtr sid,out bool member);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeName(string system,ref Luid id,StringBuilder name,ref uint size);
 [DllImport("userenv.dll",SetLastError=true)] static extern bool CreateEnvironmentBlock(out IntPtr environment,SafeAccessTokenHandle token,bool inherit);
 [DllImport("userenv.dll")] static extern bool DestroyEnvironmentBlock(IntPtr environment);
 [DllImport("userenv.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetUserProfileDirectory(SafeAccessTokenHandle token,StringBuilder path,ref uint size);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessAsUserW(SafeAccessTokenHandle token,string app,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string directory,ref Startup startup,out ProcessInfo process);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref JobExtended value,uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,out JobAccounting value,uint size,IntPtr required);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr GetProcessWindowStation();
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr GetThreadDesktop(uint tid);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetUserObjectInformation(IntPtr handle,int kind,StringBuilder data,uint length,out uint required);
 [StructLayout(LayoutKind.Sequential)] struct GenericMapping {public uint Read,Write,Execute,All;}
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AccessCheck(byte[] descriptor,SafeAccessTokenHandle token,uint desired,ref GenericMapping mapping,IntPtr privileges,ref uint privilegeBytes,out uint granted,out bool allowed);
 [DllImport("user32.dll",SetLastError=true)] static extern bool GetUserObjectSecurity(IntPtr handle,ref uint information,[Out] byte[] descriptor,uint size,out uint needed);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetKernelObjectSecurity(IntPtr handle,uint information,[Out] byte[] descriptor,uint size,out uint needed);
 static Dictionary<string,object> Evidence(Func<Dictionary<string,object>> read){try{return read();}catch(Exception error){var native=error as Win32Exception;string message=error.Message;return new Dictionary<string,object>{{"ok",false},{"errorType",error.GetType().Name},{"nativeErrorCode",native==null?(object)null:native.NativeErrorCode},{"message",message.Substring(0,Math.Min(message.Length,2048))}};}}
 static GenericMapping Mapping(string kind){
  if(kind=="windowStation")return new GenericMapping{Read=0x20303,Write=0x2001C,Execute=0x20060,All=0xF037F};
  if(kind=="desktop")return new GenericMapping{Read=0x20041,Write=0x200BE,Execute=0x20100,All=0xF01FF};
  throw new InvalidOperationException("UNSUPPORTED_GENERIC_MAPPING");
 }
 static Dictionary<string,object> CheckAccess(byte[] bytes,SafeAccessTokenHandle token,string kind){
  if(kind!="desktop"&&kind!="windowStation")return new Dictionary<string,object>{{"status","notEvaluated"},{"reason","raw DACL only; no object-specific mapping assumed"}};
  return Evidence(delegate{
  SafeAccessTokenHandle copy;Check(DuplicateTokenEx(token,8,IntPtr.Zero,2,2,out copy));using(copy){
   IntPtr privileges=Marshal.AllocHGlobal(65536);try{uint size=65536,granted;bool allowed;var mapping=Mapping(kind);
    Check(AccessCheck(bytes,copy,0x02000000,ref mapping,privileges,ref size,out granted,out allowed));
    return new Dictionary<string,object>{{"ok",true},{"allowed",allowed},{"grantedMask",granted},{"requested","MAXIMUM_ALLOWED"},{"genericMapping",kind},{"fullMappedAccess",allowed&&(granted&mapping.All)==mapping.All}};
   }finally{Marshal.FreeHGlobal(privileges);}
  }
 });}
 static Dictionary<string,object> DescriptorEvidence(byte[] bytes,string user,SafeAccessTokenHandle token,string kind){
  if(bytes.Length>65536)throw new InvalidOperationException("SECURITY_DESCRIPTOR_BOUND");
  var sd=new RawSecurityDescriptor(bytes,0);var acl=sd.DiscretionaryAcl;var rows=new List<Dictionary<string,object>>();
  if(acl!=null){if(acl.Count>256)throw new InvalidOperationException("ACL_ACE_BOUND");foreach(GenericAce ace in acl){
   var known=ace as KnownAce;var qualified=ace as QualifiedAce;string sid=known==null?null:known.SecurityIdentifier.Value;
   byte[] binary=new byte[ace.BinaryLength];ace.GetBinaryForm(binary,0);
   rows.Add(new Dictionary<string,object>{{"type",ace.AceType.ToString()},{"flags",(int)ace.AceFlags},{"sid",sid},{"principal",sid==user?"user":sid=="S-1-5-32-544"?"Administrators":sid=="S-1-5-18"?"SYSTEM":"other"},{"rights",known==null?(object)null:unchecked((uint)known.AccessMask)},{"qualifier",qualified==null?null:qualified.AceQualifier.ToString()},{"binaryBase64",Convert.ToBase64String(binary)}});
  }}
  string sddl=sd.GetSddlForm(AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);
  if(sddl.Length>65536)throw new InvalidOperationException("SECURITY_SDDL_BOUND");
  return new Dictionary<string,object>{{"ok",true},{"owner",sd.Owner==null?null:sd.Owner.Value},{"group",sd.Group==null?null:sd.Group.Value},{"sddl",sddl},{"daclPresent",(sd.ControlFlags&ControlFlags.DiscretionaryAclPresent)!=0},{"nullDacl",acl==null},{"aces",rows},{"accessCheck",CheckAccess(bytes,token,kind)},{"boundary","DACL diagnostic only; mandatory integrity and runtime initialization not proven"}};
 }
 static Dictionary<string,object> DefaultDaclEvidence(SafeAccessTokenHandle token){return Evidence(delegate{
  var info=Info(token,6);try{IntPtr pointer=Marshal.ReadIntPtr(info);RawAcl acl=null;
   if(pointer!=IntPtr.Zero){int size=(ushort)Marshal.ReadInt16(pointer,2);if(size<8||size>65535)throw new InvalidOperationException("DEFAULT_DACL_BOUND");byte[] raw=new byte[size];Marshal.Copy(pointer,raw,0,size);acl=new RawAcl(raw,0);}
   string user=TokenSid(token,1);var sd=new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent,new SecurityIdentifier(TokenSid(token,4)),new SecurityIdentifier(TokenSid(token,5)),null,acl);byte[] bytes=new byte[sd.BinaryLength];sd.GetBinaryForm(bytes,0);
   var result=DescriptorEvidence(bytes,user,token,"defaultDacl");result["scope"]="TokenDefaultDacl projected with token owner/group; not an existing object descriptor";return result;
  }finally{Marshal.FreeHGlobal(info);}
 });}
 // Pure bounded ACL construction: preserve every original ACE byte and its order.
 // No OS API is called here, so malformed input and preservation can be tested locally.
 static int U16(byte[] bytes,int offset){return bytes[offset]|(bytes[offset+1]<<8);}
 static void Put16(byte[] bytes,int offset,int value){bytes[offset]=(byte)value;bytes[offset+1]=(byte)(value>>8);}
 static int AclEnd(byte[] acl){
  if(acl==null||acl.Length<8||acl.Length>65535||(acl[0]!=2&&acl[0]!=4)||U16(acl,2)!=acl.Length||U16(acl,4)>256)throw new InvalidOperationException("DEFAULT_DACL_BOUND");
  int offset=8;for(int i=0;i<U16(acl,4);i++){if(offset+4>acl.Length)throw new InvalidOperationException("ACE_HEADER_BOUND");int size=U16(acl,offset+2);if(size<4||(size&3)!=0||offset+size>acl.Length)throw new InvalidOperationException("ACE_SIZE_BOUND");offset+=size;}return offset;
 }
 public static byte[] AppendUserGenericAll(byte[] original,byte[] userSid){
  int end=AclEnd(original);if(U16(original,4)>=256)throw new InvalidOperationException("ACL_ACE_BOUND");if(userSid==null||userSid.Length<8||userSid[0]!=1||userSid[1]>15||userSid.Length!=8+4*userSid[1])throw new InvalidOperationException("USER_SID_BOUND");
  int size=8+userSid.Length;if(original.Length+size>65535)throw new InvalidOperationException("DEFAULT_DACL_BOUND");
  byte[] result=new byte[original.Length+size];Array.Copy(original,0,result,0,end);Array.Copy(original,end,result,end+size,original.Length-end);
  Put16(result,2,result.Length);Put16(result,4,U16(original,4)+1);
  result[end]=0;result[end+1]=0;Put16(result,end+2,size);result[end+7]=0x10; // ACCESS_ALLOWED, no flags, GENERIC_ALL.
  Array.Copy(userSid,0,result,end+8,userSid.Length);return result;
 }
 public static void VerifyDefaultDaclAddition(byte[] before,byte[] actual,byte[] userSid){
  byte[] expected=AppendUserGenericAll(before,userSid);if(actual==null||actual.Length!=expected.Length)throw new InvalidOperationException("DEFAULT_DACL_READBACK_MISMATCH");
  for(int i=0;i<expected.Length;i++)if(actual[i]!=expected[i])throw new InvalidOperationException("DEFAULT_DACL_READBACK_MISMATCH");
 }
 public static void VerifyExactBytes(byte[] before,byte[] actual){
  if(before==null||actual==null||before.Length!=actual.Length)throw new InvalidOperationException("SOURCE_DEFAULT_DACL_CHANGED");
  for(int i=0;i<before.Length;i++)if(before[i]!=actual[i])throw new InvalidOperationException("SOURCE_DEFAULT_DACL_CHANGED");
 }
 static byte[] ReadDefaultDacl(SafeAccessTokenHandle token){
  var info=Info(token,6);try{IntPtr acl=Marshal.ReadIntPtr(info);if(acl==IntPtr.Zero)throw new InvalidOperationException("NULL_DEFAULT_DACL_EXPERIMENT_REFUSED");int size=(ushort)Marshal.ReadInt16(acl,2);if(size<8)throw new InvalidOperationException("DEFAULT_DACL_BOUND");byte[] bytes=new byte[size];Marshal.Copy(acl,bytes,0,size);AclEnd(bytes);return bytes;}finally{Marshal.FreeHGlobal(info);}
 }
 static Dictionary<string,object> ApplyUserDefaultDacl(SafeAccessTokenHandle restricted,string user){
  byte[] before=ReadDefaultDacl(restricted);var sid=new SecurityIdentifier(user);byte[] sidBytes=new byte[sid.BinaryLength];sid.GetBinaryForm(sidBytes,0);byte[] updated=AppendUserGenericAll(before,sidBytes);
  IntPtr acl=IntPtr.Zero,info=IntPtr.Zero;try{
   acl=Marshal.AllocHGlobal(updated.Length);Marshal.Copy(updated,0,acl,updated.Length);info=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(info,acl);
   Check(SetTokenInformation(restricted,6,info,(uint)IntPtr.Size));byte[] actual=ReadDefaultDacl(restricted);VerifyDefaultDaclAddition(before,actual,sidBytes);
   return new Dictionary<string,object>{{"ok",true},{"scope","new restricted token only; append current user GENERIC_ALL; existing object ACLs unchanged; startup hypothesis unproven"},{"user",user},{"genericAll",0x10000000},{"beforeBase64",Convert.ToBase64String(before)},{"afterBase64",Convert.ToBase64String(actual)},{"originalAceBytesAndOrderPreserved",true},{"nativeReadbackVerified",true}};
  }finally{if(info!=IntPtr.Zero)Marshal.FreeHGlobal(info);if(acl!=IntPtr.Zero)Marshal.FreeHGlobal(acl);}
 }
 static void VerifyTokenUnchanged(Dictionary<string,object> baseline,Dictionary<string,object> actual){
  foreach(var key in baseline.Keys){
   if(key=="groups"||key=="privileges"){
    var left=(List<Dictionary<string,object>>)baseline[key];var right=(List<Dictionary<string,object>>)actual[key];if(left.Count!=right.Count)throw new InvalidOperationException("TOKEN_CHANGED_DURING_DACL_EXPERIMENT");
    for(int i=0;i<left.Count;i++)foreach(var field in left[i].Keys)if(!Equals(left[i][field],right[i][field]))throw new InvalidOperationException("TOKEN_CHANGED_DURING_DACL_EXPERIMENT");
   }else if(!Equals(baseline[key],actual[key]))throw new InvalidOperationException("TOKEN_CHANGED_DURING_DACL_EXPERIMENT");
  }
 }
 static Dictionary<string,object> ObjectEvidence(IntPtr handle,bool userObject,SafeAccessTokenHandle token,string kind){return Evidence(delegate{
  if(handle==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());uint info=7,needed;byte[] bytes=new byte[65536];
  if(userObject)Check(GetUserObjectSecurity(handle,ref info,bytes,(uint)bytes.Length,out needed));else Check(GetKernelObjectSecurity(handle,info,bytes,(uint)bytes.Length,out needed));
  if(needed<20||needed>bytes.Length)throw new InvalidOperationException("OBJECT_SECURITY_BOUND");Array.Resize(ref bytes,(int)needed);
  var result=DescriptorEvidence(bytes,TokenSid(token,1),token,kind);if(userObject)result["actualName"]=ObjectName(handle);return result;
 });}
 static Dictionary<string,object> ParentSecurity(SafeAccessTokenHandle token){return new Dictionary<string,object>{{"defaultDacl",DefaultDaclEvidence(token)},{"windowStation",ObjectEvidence(GetProcessWindowStation(),true,token,"windowStation")},{"desktop",ObjectEvidence(GetThreadDesktop(GetCurrentThreadId()),true,token,"desktop")},{"objectsObservedIn","trusted parent; AccessCheck evaluated using designated token"}};}
 static Dictionary<string,object> ChildSecurity(ProcessInfo process,SafeAccessTokenHandle token){
  var result=new Dictionary<string,object>{{"windowStation","unavailableFromParent"},{"requestedDesktop","winsta0\\default"},{"threadDesktop",ObjectEvidence(GetThreadDesktop(process.Tid),true,token,"desktop")},{"process",ObjectEvidence(process.Process,false,token,"process")},{"thread",ObjectEvidence(process.Thread,false,token,"thread")}};
  result["actualToken"]=Evidence(delegate{SafeAccessTokenHandle child;Check(OpenProcessToken(process.Process,8,out child));using(child){return new Dictionary<string,object>{{"user",TokenSid(child,1)},{"owner",TokenSid(child,4)},{"integrity",TokenSid(child,25)},{"defaultDacl",DefaultDaclEvidence(child)}};}});return result;
 }
 static void Check(bool value){if(!value)throw new Win32Exception(Marshal.GetLastWin32Error());}
 static IntPtr Info(SafeAccessTokenHandle token,int kind){uint bytes;GetTokenInformation(token,kind,IntPtr.Zero,0,out bytes);if(bytes<1||bytes>1048576)throw new InvalidOperationException("TOKEN_INFO_BOUND");IntPtr value=Marshal.AllocHGlobal((int)bytes);try{Check(GetTokenInformation(token,kind,value,bytes,out bytes));return value;}catch{Marshal.FreeHGlobal(value);throw;}}
 static string Sid(IntPtr value){return new SecurityIdentifier(value).Value;}
 static string ObjectName(IntPtr handle){uint bytes;var value=new StringBuilder(256);Check(GetUserObjectInformation(handle,2,value,512,out bytes));return value.ToString();}
 static string Profile(SafeAccessTokenHandle token){uint bytes=32768;var value=new StringBuilder((int)bytes);Check(GetUserProfileDirectory(token,value,ref bytes));return value.ToString();}
 static string TokenSid(SafeAccessTokenHandle token,int kind){var p=Info(token,kind);try{return Sid(Marshal.ReadIntPtr(p));}finally{Marshal.FreeHGlobal(p);}}
 static int Number(SafeAccessTokenHandle token,int kind){var p=Info(token,kind);try{return Marshal.ReadInt32(p);}finally{Marshal.FreeHGlobal(p);}}
 static IntPtr AllocateSid(string text){var sid=new SecurityIdentifier(text);byte[] bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);var ptr=Marshal.AllocHGlobal(bytes.Length);Marshal.Copy(bytes,0,ptr,bytes.Length);return ptr;}
 static List<Dictionary<string,object>> Groups(SafeAccessTokenHandle token){var p=Info(token,2);try{int count=Marshal.ReadInt32(p);if(count<0||count>4096)throw new InvalidOperationException("TOKEN_GROUP_BOUND");var result=new List<Dictionary<string,object>>();int stride=Marshal.SizeOf(typeof(SidEntry));for(int i=0;i<count;i++){var entry=(SidEntry)Marshal.PtrToStructure(IntPtr.Add(p,IntPtr.Size+i*stride),typeof(SidEntry));result.Add(new Dictionary<string,object>{{"sid",Sid(entry.Sid)},{"attributes",entry.Attributes}});}return result;}finally{Marshal.FreeHGlobal(p);}}
 static List<Dictionary<string,object>> Privileges(SafeAccessTokenHandle token){var p=Info(token,3);try{int count=Marshal.ReadInt32(p);if(count<0||count>4096)throw new InvalidOperationException("TOKEN_PRIVILEGE_BOUND");var result=new List<Dictionary<string,object>>();int stride=Marshal.SizeOf(typeof(Privilege));for(int i=0;i<count;i++){var entry=(Privilege)Marshal.PtrToStructure(IntPtr.Add(p,4+i*stride),typeof(Privilege));uint length=256;var name=new StringBuilder((int)length);Check(LookupPrivilegeName(null,ref entry.Id,name,ref length));result.Add(new Dictionary<string,object>{{"name",name.ToString()},{"attributes",entry.Attributes}});}return result;}finally{Marshal.FreeHGlobal(p);}}
 static bool Admin(SafeAccessTokenHandle token){IntPtr sid=AllocateSid("S-1-5-32-544");SafeAccessTokenHandle copy;try{Check(DuplicateTokenEx(token,8,IntPtr.Zero,2,2,out copy));using(copy){bool member;Check(CheckTokenMembership(copy,sid,out member));return member;}}finally{Marshal.FreeHGlobal(sid);}}
 static Dictionary<string,object> Describe(SafeAccessTokenHandle token){return new Dictionary<string,object>{{"user",TokenSid(token,1)},{"owner",TokenSid(token,4)},{"integrity",TokenSid(token,25)},{"elevated",Number(token,20)!=0},{"elevationType",Number(token,18)},{"session",Number(token,12)},{"groups",Groups(token)},{"privileges",Privileges(token)},{"adminMember",Admin(token)},{"profile",Profile(token)}};}
 public static Dictionary<string,object> Inspect(){SafeAccessTokenHandle token;Check(OpenProcessToken(GetCurrentProcess(),0xA,out token));using(token){var result=Describe(token);result["windowStation"]=ObjectName(GetProcessWindowStation());result["desktop"]=ObjectName(GetThreadDesktop(GetCurrentThreadId()));result["pid"]=Process.GetCurrentProcess().Id;result["HOME"]=Environment.GetEnvironmentVariable("HOME");result["USERPROFILE"]=Environment.GetEnvironmentVariable("USERPROFILE");return result;}}
 public static bool OrdinaryGroup(string sid,uint flags,string user){return sid==user||(flags&0xC0000000)==0xC0000000||(flags&0x20)!=0||sid=="S-1-1-0"||sid=="S-1-2-0"||sid=="S-1-2-1"||sid=="S-1-5-4"||sid=="S-1-5-11"||sid=="S-1-5-32-545"||sid=="S-1-5-113";}
 static string Logon(Dictionary<string,object> value){var ids=new List<string>();foreach(var row in (List<Dictionary<string,object>>)value["groups"])if(((uint)row["attributes"]&0xC0000000)==0xC0000000)ids.Add((string)row["sid"]);ids.Sort();if(ids.Count==0)throw new InvalidOperationException("LOGON_SID_MISSING");return String.Join(";",ids.ToArray());}
 static void Verify(Dictionary<string,object> original,Dictionary<string,object> value,List<string> disabled){if(!Equals(original["user"],value["user"])||!Equals(value["user"],value["owner"])||!Equals(value["integrity"],"S-1-16-8192")||(bool)value["adminMember"]||(bool)value["elevated"]||!Equals(original["session"],value["session"])||!Equals(original["profile"],value["profile"]))throw new InvalidOperationException("RESTRICTED_TOKEN_IDENTITY");if(Logon(original)!=Logon(value))throw new InvalidOperationException("LOGON_SID_CHANGED");foreach(var group in (List<Dictionary<string,object>>)value["groups"]){if(disabled.Contains((string)group["sid"])&&(((uint)group["attributes"]&0x10)==0||((uint)group["attributes"]&4)!=0))throw new InvalidOperationException("GROUP_NOT_DENY_ONLY");}foreach(var privilege in (List<Dictionary<string,object>>)value["privileges"]){if(((uint)privilege["attributes"]&2)!=0&&(string)privilege["name"]!="SeChangeNotifyPrivilege")throw new InvalidOperationException("PRIVILEGE_STILL_ENABLED");}}
 static uint Active(IntPtr job){JobAccounting info;Check(QueryInformationJobObject(job,1,out info,(uint)Marshal.SizeOf(typeof(JobAccounting)),IntPtr.Zero));return info.ActiveProcesses;}
 public static Dictionary<string,object> Run(string node,string project,string output){
  if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true"||Environment.GetEnvironmentVariable("CI")!="true")throw new InvalidOperationException("ISOLATED_CI_ONLY");
  foreach(string value in new[]{node,project,output})if(!Path.IsPathRooted(value)||value.Contains("\"")||value.Contains("\r")||value.Contains("\n"))throw new InvalidOperationException("INVALID_PATH");
  if(!String.Equals(Path.GetFullPath(project),Path.GetFullPath(Environment.GetEnvironmentVariable("GITHUB_WORKSPACE")),StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("WRONG_WORKSPACE");
  SafeAccessTokenHandle source=null,restricted=null;IntPtr environment=IntPtr.Zero,job=IntPtr.Zero;ProcessInfo process=new ProcessInfo();bool assigned=false,finished=false;var allocated=new List<IntPtr>();var report=new Dictionary<string,object>{{"ok",false},{"scope","same-SID restricted-token DefaultDacl experiment; modifies only newly created token; not GUI acceptance"}};
  try{
   Check(OpenProcessToken(GetCurrentProcess(),0xF01FF,out source));var before=Describe(source);report["before"]=before;report["sourceSecurity"]=ParentSecurity(source);byte[] sourceDefaultDaclBefore=ReadDefaultDacl(source);report["sourceDefaultDaclBefore"]=Convert.ToBase64String(sourceDefaultDaclBefore);string user=(string)before["user"];var disabled=new List<SidEntry>();var ids=new List<string>();foreach(var row in (List<Dictionary<string,object>>)before["groups"]){string sid=(string)row["sid"];if(!OrdinaryGroup(sid,(uint)row["attributes"],user)){IntPtr p=AllocateSid(sid);allocated.Add(p);disabled.Add(new SidEntry{Sid=p,Attributes=0});ids.Add(sid);}}
   Check(CreateRestrictedToken(source,1,(uint)disabled.Count,disabled.ToArray(),0,IntPtr.Zero,0,IntPtr.Zero,out restricted));
   IntPtr owner=AllocateSid(user),ownerInfo=Marshal.AllocHGlobal(IntPtr.Size),medium=AllocateSid("S-1-16-8192"),label=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SidEntry)));allocated.Add(owner);allocated.Add(ownerInfo);allocated.Add(medium);allocated.Add(label);Marshal.WriteIntPtr(ownerInfo,owner);Check(SetTokenInformation(restricted,4,ownerInfo,(uint)IntPtr.Size));Marshal.StructureToPtr(new SidEntry{Sid=medium,Attributes=0x20},label,false);Check(SetTokenInformation(restricted,25,label,(uint)(Marshal.SizeOf(typeof(SidEntry))+new SecurityIdentifier("S-1-16-8192").BinaryLength)));
   var after=Describe(restricted);report["restricted"]=after;report["restrictedSecurity"]=ParentSecurity(restricted);Verify(before,after,ids);report["disabledGroups"]=ids;
   report["defaultDaclExperiment"]=new Dictionary<string,object>{{"ok",false},{"scope","new restricted token only; current user GENERIC_ALL append; hypothesis unproven"}};
   report["defaultDaclExperiment"]=ApplyUserDefaultDacl(restricted,user);
   var afterDefaultDacl=Describe(restricted);report["restrictedAfterDefaultDacl"]=afterDefaultDacl;report["restrictedSecurityAfterDefaultDacl"]=ParentSecurity(restricted);VerifyTokenUnchanged(after,afterDefaultDacl);Verify(before,afterDefaultDacl,ids);
   byte[] sourceDefaultDaclAfter=ReadDefaultDacl(source);report["sourceDefaultDaclAfter"]=Convert.ToBase64String(sourceDefaultDaclAfter);VerifyExactBytes(sourceDefaultDaclBefore,sourceDefaultDaclAfter);report["sourceDefaultDaclUnchanged"]=true;
   Check(CreateEnvironmentBlock(out environment,restricted,true));
   job=CreateJobObject(IntPtr.Zero,null);Check(job!=IntPtr.Zero);var limits=new JobExtended();limits.Basic.Flags=0x2000;Check(SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(JobExtended))));
   var startup=new Startup{Size=(uint)Marshal.SizeOf(typeof(Startup)),Desktop="winsta0\\default"};var command=new StringBuilder("\""+node+"\" \""+Path.Combine(project,"scripts","cleaner-restricted-probe.cjs")+"\" \""+output+"\"");
   Check(CreateProcessAsUserW(restricted,node,command,IntPtr.Zero,IntPtr.Zero,false,0x404,environment,project,ref startup,out process));Check(AssignProcessToJobObject(job,process.Process));assigned=true;report["childSecurity"]=ChildSecurity(process,restricted);if(ResumeThread(process.Thread)==0xFFFFFFFF)throw new Win32Exception(Marshal.GetLastWin32Error());report["pid"]=process.Pid;
   uint wait=WaitForSingleObject(process.Process,120000);if(wait!=0)throw new InvalidOperationException("PROBE_PROCESS_TIMEOUT_OR_WAIT_FAILED");uint exit;Check(GetExitCodeProcess(process.Process,out exit));report["exitCode"]=exit;
   for(int i=0;i<100&&Active(job)!=0;i++)System.Threading.Thread.Sleep(100);if(Active(job)!=0)throw new InvalidOperationException("PROBE_DESCENDANTS_STILL_RUNNING");finished=true;report["ownedJobEmpty"]=true;report["ok"]=exit==0;return report;
  }catch(Exception error){report["error"]=error.ToString();return report;}finally{try{if(!finished&&process.Process!=IntPtr.Zero){if(assigned)Check(TerminateJobObject(job,99));else Check(TerminateProcess(process.Process,99));if(WaitForSingleObject(process.Process,10000)!=0)throw new InvalidOperationException("PROBE_CLEANUP_WAIT_FAILED");if(assigned){for(int i=0;i<100&&Active(job)!=0;i++)System.Threading.Thread.Sleep(100);if(Active(job)!=0)throw new InvalidOperationException("PROBE_CLEANUP_DESCENDANTS");}report["ownedJobEmpty"]=true;}}catch(Exception cleanup){report["ok"]=false;report["cleanupError"]=cleanup.ToString();}if(process.Thread!=IntPtr.Zero)CloseHandle(process.Thread);if(process.Process!=IntPtr.Zero)CloseHandle(process.Process);if(job!=IntPtr.Zero)CloseHandle(job);if(environment!=IntPtr.Zero)DestroyEnvironmentBlock(environment);if(restricted!=null)restricted.Dispose();if(source!=null)source.Dispose();foreach(var p in allocated)Marshal.FreeHGlobal(p);}
 }
}
