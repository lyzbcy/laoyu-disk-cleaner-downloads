param([switch]$Inspect,[string]$NodeExe,[string]$ProjectRoot,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
$env:PSModulePath=$PSHOME+'\Modules;'+[Environment]::GetEnvironmentVariable('PSModulePath','Machine')
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
if($env:GITHUB_ACTIONS -ne 'true' -or $env:CI -ne 'true'){throw 'ISOLATED_CI_ONLY'}
Add-Type -Path (Join-Path $PSScriptRoot 'cleaner-restricted-probe.cs')
if($Inspect){[Console]::Out.WriteLine(([CleanerRestrictedProbe]::Inspect()|ConvertTo-Json -Depth 12 -Compress));exit 0}
if(!$OutputDirectory -or !$NodeExe -or !$ProjectRoot){throw 'INVALID_ARGUMENTS'}
$expected=Join-Path $env:GITHUB_WORKSPACE 'verification\restricted-probe'
if([IO.Path]::GetFullPath($OutputDirectory) -ne [IO.Path]::GetFullPath($expected)){throw 'INVALID_OUTPUT'}
New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop|Out-Null
$before=[CleanerRestrictedProbe]::Inspect()
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'parent-token.json'),($before|ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)))
try{$report=[CleanerRestrictedProbe]::Run($NodeExe,$ProjectRoot,$OutputDirectory)}catch{$report=@{ok=$false;error=$_.Exception.ToString();scope='same-SID restricted token probe, not GUI acceptance'}}
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'launcher.json'),($report|ConvertTo-Json -Depth 15),(New-Object Text.UTF8Encoding($false)))
if(!$report.ok){exit 1}
