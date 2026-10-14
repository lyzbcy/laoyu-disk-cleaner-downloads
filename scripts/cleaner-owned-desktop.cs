using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
// Test infrastructure only. Never loaded by the production application.
public sealed class CleanerOwnedDesktop {
 const uint StationMask=0xF037F, DesktopMask=0xF01FF;
 readonly string sid,nonce; IntPtr station,input,desktop; byte[] stationBefore,defaultBefore,stationExpected,desktopExpected,ownAce; bool stationWriteAttempted;
 public readonly Dictionary<string,object> Evidence=new Dictionary<string,object>();
 public string RequestedDesktop { get {return "winsta0\\"+DesktopName(nonce);} }
 public static bool ValidSid(string value) { if(!Regex.IsMatch(value??"",@"^S-1-5-21-\d+-\d+-\d+-\d+$"))return false;uint rid;return UInt32.TryParse(value.Substring(value.LastIndexOf('-')+1),out rid)&&rid>=1000; }
 public static string DesktopName(string nonce) {if(!Regex.IsMatch(nonce??"","^[0-9a-f]{32}$"))throw new InvalidOperationException("OWNED_DESKTOP_NONCE_REQUIRED");return "LaoyuCleaner_"+nonce;}
 public static string RequireLogonSid(string[] sids,uint[] attributes){if(sids==null||attributes==null||sids.Length!=attributes.Length||sids.Length>4096)throw new InvalidOperationException("TOKEN_GROUP_BOUND");string found=null;for(int i=0;i<sids.Length;i++){if((attributes[i]&0xc0000000)!=0xc0000000)continue;if((attributes[i]&4)==0||(attributes[i]&16)!=0||!Regex.IsMatch(sids[i]??"",@"^S-1-5-5-\d+-\d+$"))throw new InvalidOperationException("ENABLED_LOGON_SID_REQUIRED");var parts=sids[i].Split('-');uint a,b;if(!UInt32.TryParse(parts[4],out a)||!UInt32.TryParse(parts[5],out b)||found!=null)throw new InvalidOperationException("UNIQUE_LOGON_SID_REQUIRED");found=sids[i];}if(found==null)throw new InvalidOperationException("UNIQUE_LOGON_SID_REQUIRED");return found;}
 public CleanerOwnedDesktop(string userSid,string tokenLogonSid,string id) {if(!ValidSid(userSid))throw new InvalidOperationException("NEW_LOCAL_ORDINARY_SID_REQUIRED");RequireLogonSid(new[]{tokenLogonSid},new uint[]{0xc0000007});DesktopName(id);sid=tokenLogonSid;nonce=id;Evidence["accountSid"]=userSid;Evidence["tokenLogonSid"]=tokenLogonSid;Evidence["authority"]="Microsoft standard interactive client logon-session SID grant; temporary noninherited WinSta0 ACE and owned desktop only";}
 static ushort U16(byte[] b,int p){return (ushort)(b[p]|b[p+1]<<8);} static uint U32(byte[] b,int p){return (uint)(b[p]|b[p+1]<<8|b[p+2]<<16|b[p+3]<<24);} static void W16(byte[] b,int p,int v){b[p]=(byte)v;b[p+1]=(byte)(v>>8);} static void W32(byte[] b,int p,uint v){for(int i=0;i<4;i++)b[p+i]=(byte)(v>>(8*i));}
 public static bool Equal(byte[] a,byte[] b){if(a==null||b==null||a.Length!=b.Length)return false;for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false;return true;}
 public static byte[] Ace(byte[] sid,uint mask){if(sid==null||sid.Length<12||sid.Length>68||sid[0]!=1||sid.Length!=8+sid[1]*4)throw new InvalidOperationException("SID_BINARY_BOUND");var b=new byte[8+sid.Length];b[0]=0;b[1]=0;W16(b,2,b.Length);W32(b,4,mask);Buffer.BlockCopy(sid,0,b,8,sid.Length);return b;}
 static int Dacl(byte[] d){if(d==null||d.Length<28||d.Length>65536||d[0]!=1||(U16(d,2)&0x8004)!=0x8004)throw new InvalidOperationException("SELF_RELATIVE_DACL_REQUIRED");uint pos=U32(d,16);if(pos<20||pos>d.Length-8)throw new InvalidOperationException("DACL_OFFSET_BOUND");int p=(int)pos,n=U16(d,p+2);if(n<8||p+n>d.Length)throw new InvalidOperationException("DACL_SIZE_BOUND");int end=p+8;for(int i=0;i<U16(d,p+4);i++){if(end+4>p+n||U16(d,end+2)<4||end+U16(d,end+2)>p+n)throw new InvalidOperationException("ACE_BOUND");end+=U16(d,end+2);}return p;}
 static int AceEnd(byte[] d,int p){int end=p+8;for(int i=0;i<U16(d,p+4);i++)end+=U16(d,end+2);return end;}
 static byte[] Replace(byte[] d,int start,int oldLength,byte[] value){int delta=value.Length-oldLength;if(d.Length+delta>65536)throw new InvalidOperationException("DESCRIPTOR_BOUND");var b=new byte[d.Length+delta];Buffer.BlockCopy(d,0,b,0,start);Buffer.BlockCopy(value,0,b,start,value.Length);Buffer.BlockCopy(d,start+oldLength,b,start+value.Length,d.Length-start-oldLength);for(int pos=4;pos<=16;pos+=4){uint offset=U32(d,pos);if(offset>=start+oldLength&&offset!=0)W32(b,pos,(uint)(offset+delta));}return b;}
 public static byte[] Append(byte[] d,byte[] ace){int p=Dacl(d),end=AceEnd(d,p),length=U16(d,p+2);if(ace==null||ace.Length<4||U16(ace,2)!=ace.Length||length+ace.Length>65535||U16(d,p+4)==65535)throw new InvalidOperationException("APPEND_ACE_BOUND");var b=Replace(d,end,0,ace);W16(b,p+2,length+ace.Length);W16(b,p+4,U16(d,p+4)+1);return b;}
 public static byte[] Remove(byte[] d,byte[] ace){int p=Dacl(d),end=p+8,found=-1,count=0;for(int i=0;i<U16(d,p+4);i++){int n=U16(d,end+2);var item=new byte[n];Buffer.BlockCopy(d,end,item,0,n);if(Equal(item,ace)){count++;found=end;}end+=n;}if(count!=1)throw new InvalidOperationException("UNIQUE_OWNED_ACE_REQUIRED");var b=Replace(d,found,ace.Length,new byte[0]);W16(b,p+2,U16(d,p+2)-ace.Length);W16(b,p+4,U16(d,p+4)-1);return b;}
 static byte[] Acl(byte[] d){int p=Dacl(d);var b=new byte[U16(d,p+2)];Buffer.BlockCopy(d,p,b,0,b.Length);return b;}
 static byte[] Component(byte[] d,int p,bool acl){uint offset=U32(d,p);if(offset==0)return new byte[0];if(offset>d.Length-8)throw new InvalidOperationException("COMPONENT_OFFSET_BOUND");int n=acl?U16(d,(int)offset+2):8+4*d[(int)offset+1];if(offset+n>d.Length)throw new InvalidOperationException("COMPONENT_SIZE_BOUND");var b=new byte[n];Buffer.BlockCopy(d,(int)offset,b,0,n);return b;}
 static bool SameDescriptor(byte[] a,byte[] b){Dacl(a);Dacl(b);return a[0]==b[0]&&a[1]==b[1]&&U16(a,2)==U16(b,2)&&Equal(Component(a,4,false),Component(b,4,false))&&Equal(Component(a,8,false),Component(b,8,false))&&Equal(Component(a,12,true),Component(b,12,true))&&Equal(Acl(a),Acl(b));}
 public static bool SameExceptAppended(byte[] before,byte[] actual,byte[] ace){return SameDescriptor(Append(before,ace),actual);}
 [StructLayout(LayoutKind.Sequential)] struct Security {public int Size;public IntPtr Descriptor;[MarshalAs(UnmanagedType.Bool)]public bool Inherit;}
 [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();
 [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(uint tid);
 [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
 [DllImport("kernel32.dll",EntryPoint="SetLastError")] static extern void ClearLastError(uint error);
 [DllImport("user32.dll",SetLastError=true)] static extern bool GetUserObjectSecurity(IntPtr h,ref uint info,byte[] bytes,uint length,out uint needed);
 [DllImport("user32.dll",SetLastError=true)] static extern bool SetUserObjectSecurity(IntPtr h,ref uint info,byte[] descriptor);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetUserObjectInformationW(IntPtr h,int index,StringBuilder name,uint length,out uint needed);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenWindowStationW(string name,bool inherit,uint access);
 [DllImport("user32.dll",SetLastError=true)] static extern bool CloseWindowStation(IntPtr h);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenDesktopW(string name,uint flags,bool inherit,uint access);
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr OpenInputDesktop(uint flags,bool inherit,uint access);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateDesktopW(string name,IntPtr device,IntPtr mode,uint flags,uint access,ref Security attributes);
 [DllImport("user32.dll",SetLastError=true)] static extern bool SwitchDesktop(IntPtr h);
 [DllImport("user32.dll",SetLastError=true)] static extern bool CloseDesktop(IntPtr h);
 static void Check(bool ok){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error());}
 static string Name(IntPtr h){if(h==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());uint n;var s=new StringBuilder(256);Check(GetUserObjectInformationW(h,2,s,512,out n));return s.ToString();}
 static byte[] Read(IntPtr h){uint info=7,n;var b=new byte[65536];Check(GetUserObjectSecurity(h,ref info,b,(uint)b.Length,out n));if(n<20||n>b.Length)throw new InvalidOperationException("SD_BOUND");Array.Resize(ref b,(int)n);return b;}
 static void WriteDacl(IntPtr h,byte[] d){uint info=4;Check(SetUserObjectSecurity(h,ref info,d));}
 string InputName(){IntPtr h=OpenInputDesktop(0,false,1);Check(h!=IntPtr.Zero);try{return Name(h);}finally{Check(CloseDesktop(h));}}
 [StructLayout(LayoutKind.Sequential)] struct GenericMapping {public uint Read,Write,Execute,All;}
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr token,uint access,IntPtr attributes,int level,int type,out IntPtr copy);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AccessCheck(byte[] descriptor,IntPtr token,uint desired,ref GenericMapping mapping,IntPtr privileges,ref uint size,out uint granted,out bool allowed);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 public Dictionary<string,object> Access(IntPtr token){
  var result=new Dictionary<string,object>();IntPtr copy;Check(DuplicateTokenEx(token,8,IntPtr.Zero,2,2,out copy));
  try{foreach(string kind in new[]{"windowStation","ownedDesktop"}){var mapping=kind=="windowStation"?new GenericMapping{Read=0x20303,Write=0x2001C,Execute=0x20060,All=0xF037F}:new GenericMapping{Read=0x20041,Write=0x200BE,Execute=0x20100,All=0xF01FF};var bytes=Read(kind=="windowStation"?station:desktop);IntPtr buffer=Marshal.AllocHGlobal(65536);try{uint size=65536,granted;bool allowed;Check(AccessCheck(bytes,copy,0x02000000,ref mapping,buffer,ref size,out granted,out allowed));result[kind]=new Dictionary<string,object>{{"allowed",allowed},{"grantedMask",granted},{"descriptorBase64",Convert.ToBase64String(bytes)},{"requested","MAXIMUM_ALLOWED; designated ordinary logon token, actual owned objects"}};}finally{Marshal.FreeHGlobal(buffer);}}}finally{Check(CloseHandle(copy));}return result;
 }
 public void Prepare(){
  if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true"||Environment.GetEnvironmentVariable("CI")!="true")throw new InvalidOperationException("DISPOSABLE_GHA_ONLY");
  if(Name(GetProcessWindowStation())!="WinSta0"||Name(GetThreadDesktop(GetCurrentThreadId()))!="Default"||System.Diagnostics.Process.GetCurrentProcess().SessionId==0)throw new InvalidOperationException("PARENT_INTERACTIVE_DEFAULT_REQUIRED");
  input=OpenInputDesktop(0,false,0x20181);Check(input!=IntPtr.Zero);if(Name(input)!="Default")throw new InvalidOperationException("ORIGINAL_INPUT_DEFAULT_REQUIRED");defaultBefore=Read(input);Evidence["defaultBefore"]=Convert.ToBase64String(defaultBefore);
  station=OpenWindowStationW("WinSta0",false,0x60000|StationMask);Check(station!=IntPtr.Zero);stationBefore=Read(station);Evidence["stationBefore"]=Convert.ToBase64String(stationBefore);
  string name=DesktopName(nonce);IntPtr collision=OpenDesktopW(name,0,false,1);if(collision!=IntPtr.Zero){CloseDesktop(collision);throw new InvalidOperationException("DESKTOP_NAME_COLLISION");}int error=Marshal.GetLastWin32Error();if(error!=2)throw new Win32Exception(error);
  var id=new SecurityIdentifier(sid);var binary=new byte[id.BinaryLength];id.GetBinaryForm(binary,0);ownAce=Ace(binary,StationMask);stationExpected=Append(stationBefore,ownAce);stationWriteAttempted=true;WriteDacl(station,stationExpected);var actual=Read(station);if(!SameExceptAppended(stationBefore,actual,ownAce))throw new InvalidOperationException("STATION_ACE_READBACK_MISMATCH");Evidence["stationPrepared"]=Convert.ToBase64String(actual);
  byte[] d=Append(defaultBefore,Ace(binary,DesktopMask));desktopExpected=d;IntPtr memory=Marshal.AllocHGlobal(d.Length);try{Marshal.Copy(d,0,memory,d.Length);var security=new Security{Size=Marshal.SizeOf(typeof(Security)),Descriptor=memory,Inherit=false};ClearLastError(0);desktop=CreateDesktopW(name,IntPtr.Zero,IntPtr.Zero,0,0x60183,ref security);error=Marshal.GetLastWin32Error();Check(desktop!=IntPtr.Zero);if(error==183)throw new InvalidOperationException("DESKTOP_NAME_COLLISION");}finally{Marshal.FreeHGlobal(memory);}
  if(!SameDescriptor(d,Read(desktop)))throw new InvalidOperationException("NEW_DESKTOP_DACL_READBACK_MISMATCH");Evidence["desktopName"]=name;Evidence["desktopDescriptor"]=Convert.ToBase64String(Read(desktop));
  if(!Equal(defaultBefore,Read(input)))throw new InvalidOperationException("DEFAULT_DESKTOP_CHANGED");Check(SwitchDesktop(desktop));if(InputName()!=name)throw new InvalidOperationException("INPUT_DESKTOP_SWITCH_UNCONFIRMED");Evidence["inputDesktopPrepared"]=name;
 }
 public void VerifyStillPrepared(){if(!SameExceptAppended(stationBefore,Read(station),ownAce)||!Equal(defaultBefore,Read(input))||!SameDescriptor(desktopExpected,Read(desktop)))throw new InvalidOperationException("LAUNCH_API_CHANGED_DESKTOP_SECURITY");Evidence["securityUnchangedAfterCreate"]=true;}
 public List<string> Restore(bool ownedStopped){
  var errors=new List<string>();if(!ownedStopped)errors.Add("owned-actors-still-running");
  // Each cleanup action is independent: a failed switch must not skip ACE restoration.
  if(input!=IntPtr.Zero){try{Check(SwitchDesktop(input));if(InputName()!="Default")throw new InvalidOperationException("INPUT_SWITCHBACK_UNCONFIRMED");Evidence["inputDesktopRestored"]="Default";}catch(Exception e){errors.Add("switchback="+e.Message);}}
  if(desktop!=IntPtr.Zero){if(ownedStopped){try{Check(CloseDesktop(desktop));desktop=IntPtr.Zero;Evidence["ownedDesktopClosed"]=true;}catch(Exception e){errors.Add("desktop-close="+e.Message);}}else errors.Add("owned-desktop-retained");}
  if(stationWriteAttempted&&station!=IntPtr.Zero){try{var actual=Read(station);bool expected=SameExceptAppended(stationBefore,actual,ownAce);if(!expected)errors.Add("station-unrelated-change-preserved");byte[] restored=Remove(actual,ownAce);WriteDacl(station,restored);var after=Read(station);Evidence["stationAfter"]=Convert.ToBase64String(after);bool exact=Equal(stationBefore,after);Evidence["stationRestoredExactly"]=exact;if(!exact)errors.Add("station-restore-not-byte-identical");}catch(Exception e){errors.Add("station-restore="+e.Message);}}
  if(input!=IntPtr.Zero){try{var after=Read(input);Evidence["defaultAfter"]=Convert.ToBase64String(after);bool exact=Equal(defaultBefore,after);Evidence["defaultUnchangedExactly"]=exact;if(!exact)errors.Add("default-desktop-not-byte-identical");}catch(Exception e){errors.Add("default-readback="+e.Message);}try{Check(CloseDesktop(input));input=IntPtr.Zero;}catch(Exception e){errors.Add("input-handle-close="+e.Message);}}
  if(station!=IntPtr.Zero){try{Check(CloseWindowStation(station));station=IntPtr.Zero;}catch(Exception e){errors.Add("station-handle-close="+e.Message);}}
  Evidence["cleanupErrors"]=errors;return errors;
 }
}
