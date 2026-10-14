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
$found=@();$dialogWindows=@();foreach($window in $windows){
 $buttons=$window.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ControlTypeProperty,[Windows.Automation.ControlType]::Button))
 $cancel=@($buttons|Where-Object {$_.Current.Name -eq '取消'});$confirm=@($buttons|Where-Object {$_.Current.Name -eq $ConfirmName})
 $buttonDetails=@($buttons|Select-Object -First 100|ForEach-Object {@{name=([string]$_.Current.Name).Substring(0,[Math]::Min(512,([string]$_.Current.Name).Length));handle=$_.Current.NativeWindowHandle;enabled=$_.Current.IsEnabled;className=$_.Current.ClassName;style=if($_.Current.NativeWindowHandle -ne 0){[CleanerDesktopIdentity]::GetWindowLong([IntPtr]$_.Current.NativeWindowHandle,-16)}else{$null}}})
 $dialogWindows+=@{title=([string]$window.Current.Name).Substring(0,[Math]::Min(512,([string]$window.Current.Name).Length));className=$window.Current.ClassName;handle=$window.Current.NativeWindowHandle;cancelMatches=$cancel.Count;confirmMatches=$confirm.Count;buttons=$buttonDetails}
 $nativeDetails=@{pid=$TargetPid;controllerDesktop=$controllerDesktop;inputDesktop=$inputDesktop;confirmName=$ConfirmName;windowCount=$windows.Count;windows=@($dialogWindows|Select-Object -First 8)}
 if($cancel.Count -eq 1 -and $confirm.Count -eq 1){
  $default=@($buttons|Where-Object {$_.Current.NativeWindowHandle -ne 0 -and ([CleanerDesktopIdentity]::GetWindowLong([IntPtr]$_.Current.NativeWindowHandle,-16) -band 15) -eq 1})
  if($default.Count -ne 1 -or $default[0].Current.Name -ne '取消'){throw 'NATIVE_DEFAULT_NOT_CANCEL'}
  $found+=@{cancel=$cancel[0];confirm=$confirm[0]}
 }
}
if($found.Count -ne 1){$nativeDetails['foundCount']=$found.Count;throw 'NATIVE_DIALOG_NOT_UNIQUE'}
$result=@{pid=$TargetPid;platform='win32';defaultButton='取消';buttons=@('取消',$ConfirmName);action=$Action}
if($Action -eq 'cancel' -or $Action -eq 'confirm'){$button=$found[0][$Action];if(!$button.Current.IsEnabled){throw 'NATIVE_BUTTON_DISABLED'};([Windows.Automation.InvokePattern]$button.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern)).Invoke()}
$result|ConvertTo-Json -Compress

} catch {
 $message=$_.Exception.Message;$code='NATIVE_DRIVER_ERROR'
 if($message -cmatch '^[A-Z][A-Z0-9_]+$'){$code=$message}
 @{nativeError=@{code=$code;message=$message;details=$nativeDetails}}|ConvertTo-Json -Depth 10 -Compress
 exit 1
}
