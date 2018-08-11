using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PsnPkgCheck
{
    internal static class Program
    {
        private const string Title = "PSN PKG Validator";
        private const string HeaderPkgName = "Package name";
        private const string HeaderSginature = "Header";
        private const string HeaderChecksum = "Checksum";

        internal static async Task Main(string[] args)
        {
            try
            {
                if (args.Length == 0)
                {
                    Console.WriteLine("Drag .pkg files and/or folders onto this .exe to verify the packages.");
                    return;
                }

                Console.Title = Title;
                Console.CursorVisible = false;
                Console.WriteLine("Scanning for pkgs...");
                var pkgList = new List<FileInfo>();
                Console.ForegroundColor = ConsoleColor.Yellow;
                foreach (var item in args)
                {
                    var path = item.Trim('"');
                    if (File.Exists(path))
                        pkgList.Add(new FileInfo(path));
                    else if (Directory.Exists(path))
                        pkgList.AddRange(GetFilepaths(path, "*.pkg", SearchOption.AllDirectories).Select(p => new FileInfo(p)));
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
                var sigWidth = Math.Max(HeaderSginature.Length, 5);
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
                    if (idealWidth > Console.WindowWidth)
                    {
                        Console.BufferWidth = Math.Max(Console.BufferWidth, idealWidth);
                        Console.WindowWidth = idealWidth;
                    }
                    Console.BufferHeight = Math.Max(Console.BufferHeight, Math.Min(9999, pkgList.Count + 10));
                }
                catch (PlatformNotSupportedException) { }
                Console.WriteLine($"{HeaderPkgName.Trim(longestFilename).PadRight(longestFilename)} {HeaderSginature.PadLeft(sigWidth)} {HeaderChecksum.PadLeft(csumWidth)}");
                var cts = new CancellationTokenSource();
                Console.CancelKeyPress += (sender, eventArgs) => { cts.Cancel(); };
                var t = new Thread(() =>
                                   {
                                       try
                                       {
                                           var indicator = new[] {".", "..", "..."};
                                           var indicatorIdx = 0;
                                           while (!cts.Token.IsCancellationRequested)
                                           {
                                               Task.Delay(1000, cts.Token).ConfigureAwait(false).GetAwaiter().GetResult();
                                               if (cts.Token.IsCancellationRequested)
                                                   return;

                                               PkgChecker.Sync.Wait(cts.Token);
                                               try
                                               {
                                                   var frame = indicator[(indicatorIdx++) % indicator.Length];
                                                   var currentProgress = PkgChecker.CurrentFileProcessedBytes;
                                                   Console.Title = $"{Title} [{(double)(PkgChecker.ProcessedBytes + currentProgress) / PkgChecker.TotalFileSize * 100:0.00}% done{frame}]";
                                                   if (PkgChecker.CurrentPadding > 0)
                                                   {
                                                       Console.CursorVisible = false;
                                                       var oldPos = (top: Console.CursorTop, left: Console.CursorLeft);
                                                       Console.Write($"{(double)currentProgress / PkgChecker.CurrentFileSize * 100:0}%".PadLeft(PkgChecker.CurrentPadding));
                                                       Console.CursorTop = oldPos.top;
                                                       Console.CursorLeft = oldPos.left;
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

        private static IEnumerable<string> GetFilepaths(string rootPath, string patternMatch, SearchOption searchOption)
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
                            var newFiles = GetFilepaths(dir, patternMatch, searchOption);
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
}
