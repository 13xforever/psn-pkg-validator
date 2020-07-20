@echo off
rmdir /S /Q "PsnPkgCheck/bin"
rmdir /S /Q "PsnPkgCheck/obj"
dotnet build -c Release -r win-x64 PsnPkgCheck/PsnPkgCheck.csproj
dotnet publish -r win-x64 -c Release -o distrib/ PsnPkgCheck/PsnPkgCheck.csproj /p:PublishTrimmed=true;PublishSingleFile=true
dotnet build -c Release -r linux-x64 PsnPkgCheck/PsnPkgCheck.csproj
dotnet publish -r linux-x64 -c Release -o distrib/ PsnPkgCheck/PsnPkgCheck.csproj /p:PublishTrimmed=true;PublishSingleFile=true
