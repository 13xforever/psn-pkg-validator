using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PsnPkgCheck
{
    internal static class PkgChecker
    {
        internal static long TotalFileSize { get; private set; }
        internal static long ProcessedBytes { get; private set; }
        internal static long CurrentFileSize { get; private set; }
        internal static long CurrentFileProcessedBytes { get; private set; }
        internal static int CurrentPadding { get; private set; }
        internal static readonly SemaphoreSlim Sync = new SemaphoreSlim(1, 1);

        internal static async Task CheckAsync(List<FileInfo> pkgList, int fnameWidth, int sigWidth, int csumWidth, int allCsumsWidth, CancellationToken cancellationToken)
        {
            TotalFileSize = pkgList.Sum(i => i.Length);

            foreach (var item in pkgList)
            {
                Write($"{item.Name.Trim(fnameWidth).PadRight(fnameWidth)} ");
                try
                {
                    CurrentPadding = sigWidth;
                    CurrentFileSize = item.Length;
                    if (item.Length < 0xC0 + 0x20) // header + csum at the end
                    {
                        Write("invalid pkg".PadLeft(allCsumsWidth) + Environment.NewLine, ConsoleColor.Red);
                        continue;
                    }

                    var buf = new byte[1024 * 1024]; // 1 MB
                    using (var file = File.Open(item.FullName, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        var header = new byte[0xc0];
                        file.ReadExact(header);
                       if (!ValidateCmac(header))
                            Write("cmac".PadLeft(sigWidth) + " ", ConsoleColor.Red);
                        else if (!ValidateSig(header))
                            Write("ecdsa".PadLeft(sigWidth) + " ", ConsoleColor.Red);
                        else if (!ValidateHash(header))
                            Write("sha1".PadLeft(sigWidth) + " ", ConsoleColor.Yellow);
                        else
                            Write("ok".PadLeft(sigWidth) + " ", ConsoleColor.Green);

                        CurrentPadding = csumWidth;
                        file.Seek(0, SeekOrigin.Begin);
                        byte[] hash;
                        using (var sha1 = SHA1.Create())
                        {
                            var dataLengthToHash = CurrentFileSize - 0x20;
                            int read;
                            do
                            {
                                read = await file.ReadAsync(buf, 0, (int)Math.Min(buf.Length, dataLengthToHash - CurrentFileProcessedBytes), cancellationToken).ConfigureAwait(false);
                                CurrentFileProcessedBytes += read;
                                sha1.TransformBlock(buf, 0, read, null, 0);
                            } while (read > 0 && CurrentFileProcessedBytes < dataLengthToHash && !cancellationToken.IsCancellationRequested);
                            sha1.TransformFinalBlock(buf, 0, 0);
                            hash = sha1.Hash;
                        }
                        if (cancellationToken.IsCancellationRequested)
                            return;

                        var expectedHash = new byte[0x14];
                        file.ReadExact(expectedHash);
                        CurrentFileProcessedBytes += 0x20;
                        if (!expectedHash.SequenceEqual(hash))
                            Write("fail".PadLeft(csumWidth) + Environment.NewLine, ConsoleColor.Red);
                        else
                            Write("ok".PadLeft(csumWidth) + Environment.NewLine, ConsoleColor.Green);
                    }
                }
                catch (Exception e)
                {
                    Write("Error" + Environment.NewLine + e.Message + Environment.NewLine, ConsoleColor.Red);
                }
                finally
                {
                    ProcessedBytes += CurrentFileSize;
                    CurrentFileProcessedBytes = 0;
                    CurrentPadding = 0;
                }
                if (cancellationToken.IsCancellationRequested)
                    return;
            }
        }

        private static void ReadExact(this Stream stream, byte[] buf)
        {
            var read = 0;
            var total = 0;
            do
            {
                read = stream.Read(buf, read, buf.Length - read);
                total += read;
            } while (read > 0 && total < buf.Length);
            if (total < buf.Length)
                throw new InvalidOperationException($"Expected to read {buf.Length} bytes, but could only read {total} bytes");
        }

        private static void Write(string str, ConsoleColor? color = null)
        {
            Sync.Wait();
            try
            {
                if (color is ConsoleColor c)
                    Console.ForegroundColor = c;
                Console.Write(str);
                if (color.HasValue)
                    Console.ResetColor();
            }
            finally
            {
                Sync.Release();
            }
        }

        internal static string Trim(this string str, int maxLength)
        {
            if (string.IsNullOrEmpty(str))
                return str;

            const string suffix = "…";
            if (str.Length > maxLength)
            {
                if (maxLength > suffix.Length)
                    return str.Substring(0, maxLength - suffix.Length) + suffix;

                return str.Substring(0, maxLength);
            }

            return str;
        }

        private static bool ValidateCmac(Span<byte> header)
        {
            var actualCmac = GetCmac(header.Slice(0, 0x80));
            var expectedCmac = header.Slice(0x80, 0x10);
            return expectedCmac.SequenceEqual(actualCmac);
        }

        private static byte[] GetCmac(Span<byte> data)
        {
            byte[] AESEncrypt(byte[] key, byte[] iv, Span<byte> dataToEncrypt)
            {
                using (var result = new MemoryStream())
                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.None;
                    using (var cs = new CryptoStream(result, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write))
                    {
                        cs.Write(dataToEncrypt);
                        cs.FlushFinalBlock();
                        return result.ToArray();
                    }
                }
            }

            byte[] Rol(byte[] b)
            {
                var r = new byte[b.Length];
                byte carry = 0;
                for (var i = b.Length - 1; i >= 0; i--)
                {
                    ushort u = (ushort)(b[i] << 1);
                    r[i] = (byte)((u & 0xff) + carry);
                    carry = (byte)((u & 0xff00) >> 8);
                }
                return r;
            }

            // SubKey generation
            // step 1, AES-128 with key K is applied to an all-zero input block.
            var omacKey = VshCrypto.Ps3GpkgKey;
            byte[] derivedKey = AESEncrypt(omacKey, new byte[16], new byte[16]);

            // step 2, K1 is derived through the following operation:
            byte[] subKey1 = Rol(derivedKey); //If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
            if ((derivedKey[0] & 0x80) == 0x80)
                subKey1[15] ^= 0x87; // Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.

            // step 3, K2 is derived through the following operation:
            byte[] subKey2 = Rol(subKey1); // If the most significant bit of K1 is equal to 0, K2 is the left-shift of K1 by 1 bit.
            if ((subKey1[0] & 0x80) == 0x80)
                subKey2[15] ^= 0x87; // Otherwise, K2 is the exclusive-OR of const_Rb and the left-shift of K1 by 1 bit.

            // MAC computing
            byte[] buf;
            if ((data.Length != 0) && (data.Length % 16 == 0))
            {
                // If the size of the input message block is equal to a positive multiple of the block size (namely, 128 bits),
                // the last block shall be exclusive-OR'ed with K1 before processing
                buf = new byte[data.Length];
                Buffer.BlockCopy(data.ToArray(), 0, buf, 0, data.Length-16);
                for (var j = 0; j < subKey1.Length; j++)
                {
                    var idx = data.Length - 16 + j;
                    buf[idx] = (byte)(data[idx] ^ subKey1[j]);
                }
            }
            else
            {
                // Otherwise, the last block shall be padded with 10^i
                var paddingLength = 16 - data.Length % 16;
                buf = new byte[data.Length + paddingLength];
                Buffer.BlockCopy(data.ToArray(), 0, buf, 0, data.Length);
                buf[data.Length] = 0x80;
                // and exclusive-OR'ed with K2
                for (int j = 0; j < subKey2.Length; j++)
                    buf[buf.Length - 16 + j] ^= subKey2[j];
            }

            // The result of the previous process will be the input of the last encryption.
            byte[] encResult = AESEncrypt(omacKey, new byte[16], buf);
            return encResult.AsSpan(encResult.Length - 16, 16).ToArray();
        }

        private static byte[] GetPs3Hmac(Span<byte> data)
        {
            byte[] sha;
            using (var sha1 = SHA1.Create())
                sha = sha1.ComputeHash(data.ToArray());
            var buf = new byte[0x40];
            Buffer.BlockCopy(sha, 4, buf, 0, 8);
            Buffer.BlockCopy(sha, 4, buf, 8, 8);
            Buffer.BlockCopy(sha, 12, buf, 16, 4);
            buf[20] = sha[16];
            buf[21] = sha[1];
            buf[22] = sha[2];
            buf[23] = sha[3];
            Buffer.BlockCopy(buf, 16, buf, 24, 8);
            using (var sha1 = SHA1.Create())
                sha = sha1.ComputeHash(buf);
            return sha.AsSpan(0, 0x10).ToArray();
        }

        private static bool ValidateSig(byte[] header)
        {
            return true;
            //todo
            var sig = header.AsSpan(0x90, 0x28).ToArray();
            using (var ecdsa = ECDsa.Create(VshCrypto.Npdrm2ECparameters))
                if (ecdsa.VerifyData(header, 0, 0x80, sig, HashAlgorithmName.SHA1))
                    return true;

            using (var ecdsa = ECDsa.Create(VshCrypto.Npdrm1ECParameters))
                if (ecdsa.VerifyData(header, 0, 0x80, sig, HashAlgorithmName.SHA1))
                    return true;

            return false;
        }

        private static bool ValidateHash(byte[] header)
        {
            using (var sha1 = SHA1.Create())
            {
                var hash = sha1.ComputeHash(header, 0, 0x80).AsSpan(0x14 - 8, 8);
                var expectedHash = header.AsSpan(0xb8, 8);
                return expectedHash.SequenceEqual(hash);
            }
        }

        private static string AsHexString(this byte[] bytes)
        {
            var result = new StringBuilder();
            foreach (var b in bytes)
                result.Append(b.ToString("x2"));
            return result.ToString();
        }
    }
}
