param([Parameter(Mandatory=$true)][int]$TargetPid,[ValidateSet('probe','inspect','cancel','confirm','trash','close')][string]$Action='probe',[string]$ConfirmName,[string]$FixturePath)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$nativeDetails=$null
try {
if($env:GITHUB_ACTIONS -ne 'true'){throw 'ISOLATED_CI_ONLY'}
if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'NATIVE_ORDINARY_USER_REQUIRED'}
$env:PSModulePath=$PSHOME+'\Modules;'+[Environment]::GetEnvironmentVariable('PSModulePath','Machine')
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -TypeDefinition @'
using System;using System.Text;using System.Runtime.InteropServices;
public static class CleanerDesktopIdentity {
 [DllImport("user32.dll")] public static extern IntPtr GetProcessWindowStation();
 [DllImport("user32.dll")] public static extern IntPtr GetThreadDesktop(uint thread);
 [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetUserObjectInformation(IntPtr handle,int index,StringBuilder text,int length,out int needed);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr OpenInputDesktop(uint flags,bool inherit,uint access);
 [DllImport("user32.dll",SetLastError=true)] static extern bool CloseDesktop(IntPtr desktop);
 public static string InputName(){IntPtr h=OpenInputDesktop(0,false,1);if(h==IntPtr.Zero)throw new System.ComponentModel.Win32Exception();try{return Name(h);}finally{if(!CloseDesktop(h))throw new System.ComponentModel.Win32Exception();}}
 [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr handle,int index);
 [DllImport("user32.dll",SetLastError=true)] static extern bool EnumDesktopWindows(IntPtr desktop,EnumWindow callback,IntPtr parameter);
 [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr parent,EnumWindow callback,IntPtr parameter);
 delegate bool EnumWindow(IntPtr window,IntPtr parameter);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr window,StringBuilder value,int length);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr window,StringBuilder value,int length);
 [DllImport("user32.dll")] static extern IntPtr GetWindow(IntPtr window,uint command);
 [DllImport("user32.dll")] static extern IntPtr GetParent(IntPtr window);
 [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
 [DllImport("user32.dll")] static extern bool IsWindowEnabled(IntPtr window);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr SendMessageTimeout(IntPtr window,uint message,IntPtr wParam,IntPtr lParam,uint flags,uint timeout,out IntPtr result);
 static string Text(IntPtr window,bool className){var value=new StringBuilder(512);if(className)GetClassName(window,value,512);else GetWindowText(window,value,512);return value.ToString();}
 static void TargetWindow(IntPtr window,uint pid,string desktop){uint actual;uint thread=GetWindowThreadProcessId(window,out actual);if(thread==0||actual!=pid||Name(GetThreadDesktop(thread))!=desktop)throw new InvalidOperationException("NATIVE_TARGET_SAME_PID_DESKTOP_REQUIRED");}
 static object[] BoundedDialogAncestors(IntPtr control,IntPtr dialog,uint pid,string desktop){
  var chain=new System.Collections.Generic.List<object>();var seen=new System.Collections.Generic.HashSet<long>();IntPtr current=control;
  for(int depth=0;depth<8;depth++){if(current==IntPtr.Zero||!seen.Add(current.ToInt64()))break;TargetWindow(current,pid,desktop);if(!IsWindowVisible(current))break;if(current==dialog)return chain.ToArray();if((GetWindowLong(current,-16)&0x40000000)==0)break;IntPtr parent=GetParent(current);chain.Add(new System.Collections.Generic.Dictionary<string,object>{{"handle",current.ToInt64()},{"parent",parent.ToInt64()},{"className",Text(current,true)}});current=parent;}
  throw new InvalidOperationException("NATIVE_DIALOG_ANCESTRY_REQUIRED");
 }
 public static object[] NativeWindows(uint pid,string desktop){
  var result=new System.Collections.Generic.List<object>();Exception failure=null;
  bool ok=EnumDesktopWindows(GetThreadDesktop(GetCurrentThreadId()),delegate(IntPtr window,IntPtr unused){try{uint actual;GetWindowThreadProcessId(window,out actual);if(actual!=pid||!IsWindowVisible(window))return true;TargetWindow(window,pid,desktop);if(result.Count>=16)throw new InvalidOperationException("NATIVE_WINDOW_BOUND");var buttons=new System.Collections.Generic.List<object>();string type=Text(window,true);if(type=="#32770")EnumChildWindows(window,delegate(IntPtr button,IntPtr parameter){try{if(Text(button,true)!="Button")return true;TargetWindow(button,pid,desktop);if(buttons.Count>=32)throw new InvalidOperationException("NATIVE_BUTTON_BOUND");var ancestry=BoundedDialogAncestors(button,window,pid,desktop);buttons.Add(new System.Collections.Generic.Dictionary<string,object>{{"dialogAncestorVerified",true},{"ancestry",ancestry},{"handle",button.ToInt64()},{"parent",GetParent(button).ToInt64()},{"name",Text(button,false)},{"style",GetWindowLong(button,-16)},{"enabled",IsWindowEnabled(button)}});return true;}catch(Exception e){failure=e;return false;}},IntPtr.Zero);if(failure!=null)return false;result.Add(new System.Collections.Generic.Dictionary<string,object>{{"handle",window.ToInt64()},{"owner",GetWindow(window,4).ToInt64()},{"title",Text(window,false)},{"className",type},{"pid",pid},{"desktop",desktop},{"buttons",buttons.ToArray()}});return true;}catch(Exception e){failure=e;return false;}},IntPtr.Zero);
  if(failure!=null)throw failure;if(!ok)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());return result.ToArray();
 }
 public static void ClickButton(long dialog,long button,long browser,uint pid,string desktop,string title,string name){
  IntPtr host=new IntPtr(dialog),control=new IntPtr(button);TargetWindow(host,pid,desktop);TargetWindow(control,pid,desktop);TargetWindow(new IntPtr(browser),pid,desktop);BoundedDialogAncestors(control,host,pid,desktop);
  if(InputName()!=desktop||Text(host,true)!="#32770"||Text(host,false)!=title||GetWindow(host,4).ToInt64()!=browser||Text(control,true)!="Button"||Text(control,false)!=name||!IsWindowVisible(host)||!IsWindowEnabled(control))throw new InvalidOperationException("NATIVE_EXACT_DIALOG_BUTTON_REQUIRED");IntPtr value;if(SendMessageTimeout(control,0xf5,IntPtr.Zero,IntPtr.Zero,2,5000,out value)==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
 }
 public static string Name(IntPtr handle){var text=new StringBuilder(512);int needed;if(!GetUserObjectInformation(handle,2,text,1024,out needed))throw new System.ComponentModel.Win32Exception();return text.ToString();}
}
'@
$target=[Diagnostics.Process]::GetProcessById($TargetPid)
if($target.SessionId -eq 0 -or $target.SessionId -ne [Diagnostics.Process]::GetCurrentProcess().SessionId){throw 'NATIVE_INTERACTIVE_SESSION_REQUIRED'}
$nonce=$env:CLEANER_CI_DESKTOP_NONCE
if($nonce -cnotmatch '^[0-9a-f]{32}$'){throw 'CI_OWNED_DESKTOP_NONCE_REQUIRED'}
$expectedDesktop='LaoyuCleaner_'+$nonce
$controllerDesktop=[CleanerDesktopIdentity]::Name([CleanerDesktopIdentity]::GetThreadDesktop([CleanerDesktopIdentity]::GetCurrentThreadId()))
$inputDesktop=[CleanerDesktopIdentity]::InputName()
if([CleanerDesktopIdentity]::Name([CleanerDesktopIdentity]::GetProcessWindowStation()) -cne 'WinSta0' -or $controllerDesktop -cne $expectedDesktop -or $inputDesktop -cne $expectedDesktop){throw 'NATIVE_INTERACTIVE_DESKTOP_REQUIRED'}
$instance=Get-CimInstance Win32_Process -Filter "ProcessId = $TargetPid"
$owner=Invoke-CimMethod -InputObject $instance -MethodName GetOwnerSid
if($owner.ReturnValue -ne 0 -or $owner.Sid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'NATIVE_SAME_USER_REQUIRED'}
if($Action -eq 'trash'){
 if(!$FixturePath -or ![IO.Path]::IsPathRooted($FixturePath)){throw 'FIXTURE_PATH_REQUIRED'}
 $shell=New-Object -ComObject Shell.Application;$matches=@();foreach($item in $shell.NameSpace(10).Items()){
  if([IO.Path]::GetFileName($item.Path) -eq [IO.Path]::GetFileName($FixturePath) -or $item.Name -eq [IO.Path]::GetFileName($FixturePath)){
   if($item.ExtendedProperty('System.Recycle.DeletedFrom') -eq [IO.Path]::GetDirectoryName($FixturePath)){$matches+=@{sha256=(Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash.ToLowerInvariant();bytes=(Get-Item -LiteralPath $item.Path).Length}}
  }
 }
 if($matches.Count -ne 1){throw 'NATIVE_TRASH_PAYLOAD_NOT_UNIQUE'};$matches[0]|ConvertTo-Json -Compress;exit 0
}
$condition=[Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ProcessIdProperty,$TargetPid)
$windows=[Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,$condition)
$windowDesktops=@();foreach($window in $windows){$windowPid=[uint32]0;$windowTid=[CleanerDesktopIdentity]::GetWindowThreadProcessId([IntPtr]$window.Current.NativeWindowHandle,[ref]$windowPid);if(!$windowTid -or $windowPid -ne $TargetPid){throw 'NATIVE_TARGET_WINDOW_PID_REQUIRED'};$windowDesktop=[CleanerDesktopIdentity]::Name([CleanerDesktopIdentity]::GetThreadDesktop($windowTid));if($windowDesktop -cne $expectedDesktop){throw 'NATIVE_TARGET_SAME_DESKTOP_REQUIRED'};$windowDesktops+=@{tid=$windowTid;desktop=$windowDesktop}}
if($Action -eq 'probe'){$details=@();foreach($window in $windows){$details+=@{title=([string]$window.Current.Name).Substring(0,[Math]::Min(512,([string]$window.Current.Name).Length));className=$window.Current.ClassName;handle=$window.Current.NativeWindowHandle}};@{controllerDesktop=$controllerDesktop;inputDesktop=$inputDesktop;windowDesktops=$windowDesktops;pid=$TargetPid;platform='win32';accessible=($windows.Count -gt 0);windowCount=$windows.Count;sessionId=$target.SessionId;sid=$owner.Sid;actualCommandLine=([string]$instance.CommandLine).Substring(0,[Math]::Min(4096,([string]$instance.CommandLine).Length));actualExecutable=$instance.ExecutablePath;windows=$details}|ConvertTo-Json -Depth 6 -Compress;exit 0}
if($windows.Count -lt 1){throw 'NATIVE_WINDOW_MISSING'}
if($Action -eq 'close'){if(!$ConfirmName -or ![String]::Equals([IO.Path]::GetFullPath($ConfirmName),[IO.Path]::GetFullPath([string]$instance.ExecutablePath),[StringComparison]::OrdinalIgnoreCase)){throw 'NATIVE_CLOSE_EXECUTABLE_REQUIRED'};if($windows.Count -ne 1 -or $windows[0].Current.ClassName -ne 'Chrome_WidgetWin_1'){throw 'NATIVE_CLOSE_SINGLE_BROWSER_WINDOW_REQUIRED'};$pattern=[Windows.Automation.WindowPattern]$windows[0].GetCurrentPattern([Windows.Automation.WindowPattern]::Pattern);$pattern.Close();@{pid=$TargetPid;normalCloseRequested=$true;controllerDesktop=$controllerDesktop;inputDesktop=$inputDesktop}|ConvertTo-Json -Compress;exit 0}
if($ConfirmName -cne '确认不可恢复并永久删除' -and $ConfirmName -cne '确认移到回收站'){throw 'FIXED_CONFIRMATION_NAME_REQUIRED'}
$expectedTitle=if($ConfirmName -ceq '确认不可恢复并永久删除'){'再次确认永久删除'}else{'确认移动到系统回收站'}
$browsers=@($windows|Where-Object {$_.Current.ClassName -ceq 'Chrome_WidgetWin_1'})
if($browsers.Count -ne 1){throw 'NATIVE_SINGLE_BROWSER_OWNER_REQUIRED'}
$browser=[long]$browsers[0].Current.NativeWindowHandle
$nativeWindows=@([CleanerDesktopIdentity]::NativeWindows([uint32]$TargetPid,$expectedDesktop))
$nativeDetails=@{pid=$TargetPid;controllerDesktop=$controllerDesktop;inputDesktop=$inputDesktop;confirmName=$ConfirmName;expectedTitle=$expectedTitle;browserOwner=$browser;uiaWindowCount=$windows.Count;windows=$nativeWindows}
$found=@();foreach($window in $nativeWindows){
 if($window.className -cne '#32770' -or $window.title -cne $expectedTitle -or $window.owner -ne $browser){continue}
 $cancel=@($window.buttons|Where-Object {$_.name -ceq '取消' -and $_.dialogAncestorVerified -eq $true});$confirm=@($window.buttons|Where-Object {$_.name -ceq $ConfirmName -and $_.dialogAncestorVerified -eq $true})
 if($cancel.Count -eq 1 -and $confirm.Count -eq 1){
  $default=@($window.buttons|Where-Object {($_.style -band 15) -eq 1})
  if($default.Count -ne 1 -or $default[0].name -cne '取消'){throw 'NATIVE_DEFAULT_NOT_CANCEL'}
  $found+=@{window=$window;cancel=$cancel[0];confirm=$confirm[0]}
 }
}
$nativeDetails['foundCount']=$found.Count
if($found.Count -ne 1){throw 'NATIVE_DIALOG_NOT_UNIQUE'}
$result=@{pid=$TargetPid;platform='win32';defaultButton='取消';buttons=@('取消',$ConfirmName);action=$Action;nativeWindow=$found[0].window;discovery='EnumDesktopWindows/EnumChildWindows; exact PID desktop title browser owner and bounded same-PID visible native Button ancestry'}
if($Action -eq 'cancel' -or $Action -eq 'confirm'){$button=$found[0][$Action];if(!$button.enabled){throw 'NATIVE_BUTTON_DISABLED'};[CleanerDesktopIdentity]::ClickButton([long]$found[0].window.handle,[long]$button.handle,$browser,[uint32]$TargetPid,$expectedDesktop,$expectedTitle,[string]$button.name)}
$result|ConvertTo-Json -Depth 8 -Compress

} catch {
 $message=$_.Exception.Message;$code='NATIVE_DRIVER_ERROR'
 if($message -cmatch '^[A-Z][A-Z0-9_]+$'){$code=$message}
 @{nativeError=@{code=$code;message=$message;details=$nativeDetails}}|ConvertTo-Json -Depth 10 -Compress
 exit 1
}
