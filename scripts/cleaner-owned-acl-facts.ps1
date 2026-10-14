param([Parameter(Mandatory=$true)][string]$TargetPath)
$ErrorActionPreference='Stop'
$env:PSModulePath=$PSHOME+'\Modules;'+[Environment]::GetEnvironmentVariable('PSModulePath','Machine')
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
if($env:GITHUB_ACTIONS -ne 'true' -or $env:CI -ne 'true' -or $env:CLEANER_STANDARD_USER_CI -ne '1'){throw 'DISPOSABLE_WINDOWS_USER_ONLY'}
if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ORDINARY_USER_REQUIRED'}
$nativeHome=[Environment]::GetFolderPath('UserProfile')
$full=[IO.Path]::GetFullPath($TargetPath)
if(!$nativeHome -or !$full.StartsWith($nativeHome+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'OWNED_PROFILE_PATH_REQUIRED'}
$item=Get-Item -LiteralPath $full -Force
if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'ORDINARY_OWNED_FILE_REQUIRED'}
$acl=Get-Acl -LiteralPath $full
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid){throw 'OWNED_FILE_REQUIRED'}
@{ownerSid=$sid;sddl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access);accessProtected=$acl.AreAccessRulesProtected}|ConvertTo-Json -Compress
