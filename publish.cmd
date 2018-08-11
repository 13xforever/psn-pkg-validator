@echo off
rem dotnet build -c Release /p:Platform="Any CPU"
dotnet publish -r win-x64 -c Release /p:Platform="Any CPU"
