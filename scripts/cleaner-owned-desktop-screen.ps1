param([Parameter(Mandatory=$true)][string]$OutputFile,[ValidateSet('inspected','normal','gui-failure')][string]$Phase='inspected')
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
if($env:GITHUB_ACTIONS -ne 'true' -or $env:CI -ne 'true' -or $env:CLEANER_STANDARD_USER_CI -ne '1'){throw 'DISPOSABLE_WINDOWS_CI_USER_ONLY'}
$name=if($Phase -eq 'normal'){'ordinary-normal-desktop-screen.png'}elseif($Phase -eq 'gui-failure'){'gui-failure-desktop-screen.png'}else{'ordinary-desktop-screen.png'}
$expected=Join-Path (Join-Path $env:GITHUB_WORKSPACE 'verification/core') $name
if(![String]::Equals([IO.Path]::GetFullPath($OutputFile),[IO.Path]::GetFullPath($expected),[StringComparison]::OrdinalIgnoreCase)){throw 'FIXED_SCREEN_EVIDENCE_PATH_REQUIRED'}
Add-Type -TypeDefinition @'
using System;using System.ComponentModel;using System.Text;using System.Runtime.InteropServices;
public static class CleanerInputDesktop {
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr OpenInputDesktop(uint flags,bool inherit,uint access);
 [DllImport("user32.dll",SetLastError=true)] static extern bool CloseDesktop(IntPtr desktop);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetUserObjectInformationW(IntPtr obj,int index,StringBuilder data,uint size,out uint needed);
 [DllImport("user32.dll")] public static extern IntPtr GetThreadDesktop(uint thread);
 [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
 public static string ControllerName(){return Name(GetThreadDesktop(GetCurrentThreadId()));}
 static string Name(IntPtr h){uint needed;var name=new StringBuilder(256);if(!GetUserObjectInformationW(h,2,name,512,out needed))throw new Win32Exception(Marshal.GetLastWin32Error());return name.ToString();}
 public static string InputName(){IntPtr h=OpenInputDesktop(0,false,1);if(h==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());try{uint needed;var name=new StringBuilder(256);if(!GetUserObjectInformationW(h,2,name,512,out needed))throw new Win32Exception(Marshal.GetLastWin32Error());return name.ToString();}finally{if(!CloseDesktop(h))throw new Win32Exception(Marshal.GetLastWin32Error());}}
}
'@
$desktop=[CleanerInputDesktop]::InputName()
$nonce=$env:CLEANER_CI_DESKTOP_NONCE
if($nonce -cnotmatch '^[0-9a-f]{32}$'){throw 'CI_OWNED_DESKTOP_NONCE_REQUIRED'}
$expectedDesktop='LaoyuCleaner_'+$nonce
$controllerDesktop=[CleanerInputDesktop]::ControllerName()
if($desktop -cne $expectedDesktop -or $controllerDesktop -cne $expectedDesktop){throw 'ACTUAL_INPUT_OWNED_DESKTOP_REQUIRED'}
Add-Type -AssemblyName System.Drawing,System.Windows.Forms
$screen=[Windows.Forms.SystemInformation]::VirtualScreen
if($screen.Width -lt 1 -or $screen.Height -lt 1 -or $screen.Width -gt 8192 -or $screen.Height -gt 8192){throw 'SCREEN_DIMENSION_BOUND'}
$bitmap=New-Object Drawing.Bitmap($screen.Width,$screen.Height)
$graphics=$null;$stream=$null
try{
 $graphics=[Drawing.Graphics]::FromImage($bitmap)
 $graphics.CopyFromScreen($screen.Left,$screen.Top,0,0,$screen.Size)
 $stream=[IO.File]::Open($OutputFile,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 $bitmap.Save($stream,[Drawing.Imaging.ImageFormat]::Png)
}finally{if($stream){$stream.Dispose()};if($graphics){$graphics.Dispose()};$bitmap.Dispose()}
@{scope='actual CI-owned input desktop pixels; no input action';inputDesktop=$desktop;controllerDesktop=$controllerDesktop;width=$screen.Width;height=$screen.Height}|ConvertTo-Json -Compress
