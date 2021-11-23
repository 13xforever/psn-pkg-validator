PSN PKG Validator
=================

This tool can check whether the PKG was signed by Sony (pre-PS4), and whether it is corrupted or not.

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

.NET 6.0 system prerequisites apply, see `Supported OS versions` and `.NET Dependencies` sections in [documentation](https://docs.microsoft.com/en-us/dotnet/core/install/windows?tabs=net60#dependencies).

How to build
============

For developing and running this project you will need
* .NET Core SDK 6.0 or newer
* any text editor, but Visual Studio or Visual Studio Code are recommended
