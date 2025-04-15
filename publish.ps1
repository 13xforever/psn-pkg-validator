#!/usr/bin/pwsh
Clear-Host
$trim = $true
$target = "net9.0"
if ($PSVersionTable.PSVersion.Major -lt 6)
{
    Write-Host 'Restarting using pwsh...'
    pwsh $PSCommandPath
    return
}

Write-Host 'Clearing bin/obj...' -ForegroundColor Cyan
Remove-Item -LiteralPath PsnPkgCheck/bin -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath PsnPkgCheck/obj -Recurse -Force -ErrorAction SilentlyContinue

if ($IsWindows -or ($PSVersionTable.Platform -eq 'Win32NT'))
{
    Write-Host 'Building Windows binaries...' -ForegroundColor Cyan
    dotnet publish -v:q -r win-x64 -f $target --self-contained -c Release -o distrib/win/ PsnPkgCheck/PsnPkgCheck.csproj /p:PublishTrimmed=$trim /p:PublishSingleFile=True
}

Write-Host 'Building Linux binary...' -ForegroundColor Cyan
dotnet publish -v:q -r linux-x64 -f $target --self-contained -c Linux -o distrib/lin/ PsnPkgCheck/PsnPkgCheck.csproj /p:PublishTrimmed=$trim /p:PublishSingleFile=True
if (($LASTEXITCODE -eq 0) -and ($IsLinux -or ($PSVersionTable.Platform -eq 'Unix')))
{
    chmod +x distrib/lin/PsnPkgCheck
}

Write-Host 'Clearing extra files in distrib...' -ForegroundColor Cyan
Get-ChildItem -LiteralPath distrib -Include *.pdb,*.config -Recurse | Remove-Item

Write-Host 'Zipping...' -ForegroundColor Cyan
if (Test-Path -LiteralPath distrib/win/PsnPkgCheck.exe)
{
    Compress-Archive -LiteralPath distrib/win/PsnPkgCheck.exe -DestinationPath distrib/PsnPkgCheck-win-x64-NEW.zip -CompressionLevel Optimal -Force
}
if (Test-Path -LiteralPath distrib/lin/PsnPkgCheck)
{
    Compress-Archive -LiteralPath distrib/lin/PsnPkgCheck -DestinationPath distrib/PsnPkgCheck-linux-x64-NEW.zip -CompressionLevel Optimal -Force
}

Write-Host 'Done' -ForegroundColor Cyan


