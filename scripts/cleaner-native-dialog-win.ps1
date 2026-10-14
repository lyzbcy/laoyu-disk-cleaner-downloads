param([Parameter(Mandatory=$true)][int]$TargetPid,[ValidateSet('probe','inspect','cancel','confirm','trash')][string]$Action='probe',[string]$ConfirmName,[string]$FixturePath)
$ErrorActionPreference='Stop'
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
 [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr handle,int index);
 public static string Name(IntPtr handle){var text=new StringBuilder(512);int needed;if(!GetUserObjectInformation(handle,2,text,1024,out needed))throw new System.ComponentModel.Win32Exception();return text.ToString();}
}
'@
$target=[Diagnostics.Process]::GetProcessById($TargetPid)
if($target.SessionId -eq 0 -or $target.SessionId -ne [Diagnostics.Process]::GetCurrentProcess().SessionId){throw 'NATIVE_INTERACTIVE_SESSION_REQUIRED'}
if([CleanerDesktopIdentity]::Name([CleanerDesktopIdentity]::GetProcessWindowStation()) -ne 'WinSta0' -or [CleanerDesktopIdentity]::Name([CleanerDesktopIdentity]::GetThreadDesktop([CleanerDesktopIdentity]::GetCurrentThreadId())) -ne 'Default'){throw 'NATIVE_INTERACTIVE_DESKTOP_REQUIRED'}
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
if($windows.Count -lt 1){throw 'NATIVE_WINDOW_MISSING'}
if($Action -eq 'probe'){@{pid=$TargetPid;platform='win32';accessible=$true;windowCount=$windows.Count;sessionId=$target.SessionId;sid=$owner.Sid}|ConvertTo-Json -Compress;exit 0}
$found=@();foreach($window in $windows){
 $buttons=$window.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ControlTypeProperty,[Windows.Automation.ControlType]::Button))
 $cancel=@($buttons|Where-Object {$_.Current.Name -eq '取消'});$confirm=@($buttons|Where-Object {$_.Current.Name -eq $ConfirmName})
 if($cancel.Count -eq 1 -and $confirm.Count -eq 1){
  $default=@($buttons|Where-Object {$_.Current.NativeWindowHandle -ne 0 -and ([CleanerDesktopIdentity]::GetWindowLong([IntPtr]$_.Current.NativeWindowHandle,-16) -band 15) -eq 1})
  if($default.Count -ne 1 -or $default[0].Current.Name -ne '取消'){throw 'NATIVE_DEFAULT_NOT_CANCEL'}
  $found+=@{cancel=$cancel[0];confirm=$confirm[0]}
 }
}
if($found.Count -ne 1){throw 'NATIVE_DIALOG_NOT_UNIQUE'}
$result=@{pid=$TargetPid;platform='win32';defaultButton='取消';buttons=@('取消',$ConfirmName);action=$Action}
if($Action -eq 'cancel' -or $Action -eq 'confirm'){$button=$found[0][$Action];if(!$button.Current.IsEnabled){throw 'NATIVE_BUTTON_DISABLED'};([Windows.Automation.InvokePattern]$button.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern)).Invoke()}
$result|ConvertTo-Json -Compress

} catch {
 $message=$_.Exception.Message;$code='NATIVE_DRIVER_ERROR'
 if($message -cmatch '^[A-Z][A-Z0-9_]+$'){$code=$message}
 @{nativeError=@{code=$code;message=$message}}|ConvertTo-Json -Compress
 exit 1
}
