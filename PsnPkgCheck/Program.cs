using System;
using System.Threading.Tasks;

namespace PsnPkgCheck
{
    internal static class Program
    {
        internal static async Task Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Drag .pkg files or a folder onto this .exe to verify the packages.");
                return;
            }


        }
    }
}
