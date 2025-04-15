using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PsnPkgCheck;

internal static class Program
{
    private const string Title = "PSN PKG Validator v1.3.3";
    private const string HeaderPkgName = "Package name";
    private const string HeaderSignature = "Signature";
    private const string HeaderChecksum = "Checksum";

    private static readonly string[] Animation =
    [
        ".....",
        "o....",
        ".o...",
        "..o..",
        "...o.",
        "....o",
        ".....",
        "....o",
        "...o.",
        "..o..",
        ".o...",
        "o....",
        ".....",
        "o...o",
        ".o.o.",
        "..O..",
        ".o.o.",
        "o...o"
    ];

    internal static async Task Main(string[] args)
    {
        try
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Drag .pkg files and/or folders onto this .exe to verify the packages.");
                var isFirstChar = true;
                var completedPath = false;
                var path = new StringBuilder();
                do
                {
                    var keyInfo = Console.ReadKey(true);
                    if (isFirstChar)
                    {
                        isFirstChar = false;
                        if (keyInfo.KeyChar != '"')
                            return;
                    }
                    else
                    {
                        if (keyInfo.KeyChar == '"')
                        {
                            completedPath = true;
                            args = [path.ToString()];
                        }
                        else
                            path.Append(keyInfo.KeyChar);
                    }
                } while (!completedPath);
                Console.Clear();
            }

            Console.OutputEncoding = new UTF8Encoding(false);
            Console.Title = Title;
            Console.CursorVisible = false;
            Console.WriteLine("Scanning for PKGs...");
            var pkgList = new List<FileInfo>();
            Console.ForegroundColor = ConsoleColor.Yellow;
            foreach (var item in args)
            {
                var path = item.Trim('"');
                if (File.Exists(path))
                    pkgList.Add(new(path));
                else if (Directory.Exists(path))
                    pkgList.AddRange(GetFilePaths(path, "*.pkg", SearchOption.AllDirectories).Select(p => new FileInfo(p)));
                else
                    Console.WriteLine("Unknown path: " + path);
            }
            Console.ResetColor();
            if (pkgList.Count == 0)
            {
                Console.WriteLine("No packages were found. Check paths, and try again.");
                return;
            }

            var longestFilename = Math.Max(pkgList.Max(i => i.Name.Length), HeaderPkgName.Length);
            var sigWidth = Math.Max(HeaderSignature.Length, 8);
            var csumWidth = Math.Max(HeaderChecksum.Length, 5);
            var csumsWidth = 1 + sigWidth + 1 + csumWidth + 1;
            var idealWidth = longestFilename + csumsWidth;
            try
            {
                if (idealWidth > Console.LargestWindowWidth)
                {
                    longestFilename = Console.LargestWindowWidth - csumsWidth;
                    idealWidth = Console.LargestWindowWidth;
                }
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (idealWidth > Console.WindowWidth)
                    {
                        Console.BufferWidth = Math.Max(Console.BufferWidth, idealWidth);
                        Console.WindowWidth = idealWidth;
                    }
                    Console.BufferHeight = Math.Max(Console.BufferHeight, Math.Min(9999, pkgList.Count + 10));
                }
            }
            catch (PlatformNotSupportedException) { }
            Console.WriteLine($"{HeaderPkgName.Trim(longestFilename).PadRight(longestFilename)} {HeaderSignature.PadLeft(sigWidth)} {HeaderChecksum.PadLeft(csumWidth)}");
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (sender, eventArgs) => { cts.Cancel(); };
            var t = new Thread(() =>
            {
                try
                {
                    var indicatorIdx = 0;
                    while (!cts.Token.IsCancellationRequested)
                    {
                        Task.Delay(1000, cts.Token).ConfigureAwait(false).GetAwaiter().GetResult();
                        if (cts.Token.IsCancellationRequested)
                            return;

                        PkgChecker.Sync.Wait(cts.Token);
                        try
                        {
                            var frame = Animation[(indicatorIdx++) % Animation.Length];
                            var currentProgress = PkgChecker.CurrentFileProcessedBytes;
                            Console.Title = $"{Title} [{(double)(PkgChecker.ProcessedBytes + currentProgress) / PkgChecker.TotalFileSize * 100:0.00}%] {frame}";
                            if (PkgChecker.CurrentPadding > 0)
                            {
                                Console.CursorVisible = false;
                                var (top, left) = (Console.CursorTop, Console.CursorLeft);
                                Console.Write($"{(double)currentProgress / PkgChecker.CurrentFileSize * 100:0}%".PadLeft(PkgChecker.CurrentPadding));
                                Console.CursorTop = top;
                                Console.CursorLeft = left;
                                Console.CursorVisible = false;
                            }
                        }
                        finally
                        {
                            PkgChecker.Sync.Release();
                        }
                    }
                }
                catch (TaskCanceledException)
                {
                }
            });
            t.Start();
            await PkgChecker.CheckAsync(pkgList, longestFilename, sigWidth, csumWidth, csumsWidth-2, cts.Token).ConfigureAwait(false);
            cts.Cancel(false);
            t.Join();
        }
        finally
        {
            Console.Title = Title;
            Console.WriteLine("Press any key to exit");
            Console.ReadKey();
            Console.WriteLine();
            Console.CursorVisible = true;
        }
    }

    private static IEnumerable<string> GetFilePaths(string rootPath, string patternMatch, SearchOption searchOption)
    {
        var foundFiles = Enumerable.Empty<string>();
        try
        {
            foundFiles = foundFiles.Concat(Directory.EnumerateFiles(rootPath, patternMatch));
        }
        catch (Exception e) when (e is UnauthorizedAccessException || e is PathTooLongException)
        {
            Console.WriteLine($"{rootPath}: {e.Message}");
        }

        if (searchOption == SearchOption.AllDirectories)
        {
            try
            {
                var subDirs = Directory.EnumerateDirectories(rootPath);
                foreach (var dir in subDirs)
                {
                    try
                    {
                        var newFiles = GetFilePaths(dir, patternMatch, searchOption);
                        foundFiles = foundFiles.Concat(newFiles);
                    }
                    catch (Exception e) when (e is UnauthorizedAccessException || e is PathTooLongException)
                    {
                        Console.WriteLine($"{dir}: {e.Message}");
                    }
                }
            }
            catch (Exception e) when (e is UnauthorizedAccessException || e is PathTooLongException)
            {
                Console.WriteLine($"{rootPath}: {e.Message}");
            }
        }
        return foundFiles;
    }
}