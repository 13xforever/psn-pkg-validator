PSN PKG Validator
=================

This tool can check whether the PKG was signed by Sony (pre-PS4), and whether it is corrupted or not.

Usage
=====

Simply drag-and-drop files and/or folders you want to check onto the executable.
Alternatively if you prefer to run from console, just supply paths you want to check.

But what does it all mean?
--------------------------

PKG Validator presents result in three columns: `Header`, `Metadata`, and `Package`.

`Header` and `Metadata` validate if the PKG is authentic and was produced by Sony,
it does this by calculating various security values that are present in the
file structure.
Most PKGs have several levels of layered protection that are designed to make sure
that nothing was modified. Any result other than green `ok` or yellow `idu` means
that the PKG wasn't made by Sony, and nothing more.

`Package` on the other hand is a simple full file content hash validation
that tells if it was corrupted in the transfer or not. It does not care
if the file was produced by Sony itself, or made with homebrew tools.
You want this to be green `ok` for all your PKGs, always.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./screenshots/dark.png">
  <source media="(prefers-color-scheme: light)" srcset="./screenshots/light.png">
  <img alt="Quick guide to results" src="./screenshots/dark.png">
</picture>

System Requirements
===================

.NET 9.0 system prerequisites apply, see `Supported OS versions` and `.NET Dependencies` sections in [documentation](https://learn.microsoft.com/en-us/dotnet/core/install/).

How to build
============

For developing and running this project you will need
* .NET Core SDK 9.0 or newer
* any text editor, but Visual Studio or Visual Studio Code are recommended
