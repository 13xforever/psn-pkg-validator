PSN PKG Validator
=================

This tool can check whether the PKG was signed by Sony, and whether it is corrupted or not.

Usage
=====

Simply drag-and-drop files and/or folders you want to check onto the executable.
Alternatively if you prefer to run from console, just supply paths you want to check.

But what does it all mean?
--------------------------

PKG Validator presents result in two columns: `Signature` and `Checksum`.

`Signature` validates if the PKG is authentic and was produced by Sony, it does this by calculating various security values that are present in the header structure. Most PKGs have several levels of layered protection that is designed to make sure that nothing was modified. Any result other than green `ok` means that the PKG wasn't made by Sony, and nothing more.

`Checksum` on the other hand is a simple full PKG file hash validation that tells if it was corrupted in the transfer or not. It does not care if the file was produced by Sony itself, or made with homebrew tools. You want this to be green `ok` for all your PKGs, always.

![Quick guide to results](https://user-images.githubusercontent.com/36445/49114564-52b17300-f2ba-11e8-9d8b-5ab567deff56.png)

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
