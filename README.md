PSN PKG Validator
=================

This tool can check whether the PKG was signed by Sony, and whether it is corrupted or not.

Usage
=====

Simply drag-and-drop files and/or folders you want to check onto the executable.
Alternatively if you prefer to run from console, just supply paths you want to check.

System Requirements
===================

.NET Core 2.1 system prerequisites apply, see `Supported OS versions` and `.NET Core dependencies` sections in [documentation](https://docs.microsoft.com/en-us/dotnet/core/windows-prerequisites?tabs=netcore2x).

How to build
============

For developing and running this project you will need
* .NET Core SDK 2.1 or newer
* any text editor, but Visual Studio or Visual Studio Code are recommended

Additionally, if you want to build native code executables, you will need C++ compiler toolchain and dependencies.

Windows:
* Visual C++ Build Tools (tested with 15.1 toolset)
	* Remember to run `publish.cmd` from within the appropriate environment (`x64 Native Tools Command Prompt for VS 2017` or equivalent for generating x64 binary)

Linux:
* Clang 3.9 or newer
	* `explort CppCompilerAndLinker=clang-6.0` if you have newer version
* on Ubuntu you might need to additionally install `libcurl4-openssl-dev` and `libkrb5-dev` or equivalent
