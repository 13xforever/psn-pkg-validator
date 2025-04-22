using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Aes = System.Security.Cryptography.Aes;

namespace PsnPkgCheck;

public static class PkgChecker
{
    internal static long TotalFileSize { get; private set; }
    internal static long ProcessedBytes { get; private set; }
    internal static long CurrentFileSize { get; private set; }
    internal static long CurrentFileProcessedBytes { get; private set; }
    internal static int CurrentPadding { get; private set; }
    internal static readonly SemaphoreSlim Sync = new(1, 1);

    internal static async Task CheckAsync(
        List<FileInfo> pkgList,
        int fnameWidth,
        int headerSigWidth,
        int metaSigWidth,
        int dataSigWidth,
        int csumWidth,
        int allCsumsWidth,
        CancellationToken cancellationToken
    )
    {
        TotalFileSize = pkgList.Sum(i => i.Length);

        var buf = new byte[1024 * 1024]; // 1 MB
        foreach (var item in pkgList)
        {
            Write($"{item.Name.Trim(fnameWidth).PadRight(fnameWidth)} ");
            try
            {
                CurrentPadding = headerSigWidth;
                CurrentFileSize = item.Length;
                if (item.Length < 0xC0 + 0x20) // header + csum at the end
                {
                    Write("invalid pkg".PadLeft(allCsumsWidth) + Environment.NewLine, ConsoleColor.Red);
                    continue;
                }

                // header
                await using var file = File.Open(item.FullName, FileMode.Open, FileAccess.Read, FileShare.Read);
                var headerBuf = ArrayPool<byte>.Shared.Rent(0xc0);
                await file.ReadExactlyAsync(headerBuf.AsMemory()[..0xc0], cancellationToken).ConfigureAwait(false);
                var header = headerBuf.AsSpan()[..0xc0];
                ValidateSection(header[..^0x40], header[^0x40..], headerSigWidth);

                var metaOffset = BinaryPrimitives.ReadInt32BigEndian(header[0x08..0x0c]);
                var metaSize = BinaryPrimitives.ReadInt32BigEndian(header[0x10..0x14]);
                var totalSize = BinaryPrimitives.ReadInt64BigEndian(header[0x18..0x20]);
                var dataOffset = BinaryPrimitives.ReadInt64BigEndian(header[0x20..0x28]);
                var dataSize = BinaryPrimitives.ReadInt64BigEndian(header[0x28..0x30]);
                ArrayPool<byte>.Shared.Return(headerBuf);

                if (file.Length < totalSize)
                {
                    Write("size".PadLeft(metaSigWidth + 1 +csumWidth) + Environment.NewLine, ConsoleColor.Red);
                    continue;
                }

                // metadata
                var metaBuf = ArrayPool<byte>.Shared.Rent(metaSize);
                file.Seek(metaOffset, SeekOrigin.Begin);
                await file.ReadExactlyAsync(metaBuf.AsMemory()[..metaSize], cancellationToken).ConfigureAwait(false);
                var meta = metaBuf.AsSpan()[..metaSize];
                ValidateSection(meta[..^0x40], meta[^0x40..], metaSigWidth);
                ArrayPool<byte>.Shared.Return(metaBuf);

                // content (needs decryption)
                /*
                if (dataSize <= int.MaxValue)
                {
                    var dataBuf = ArrayPool<byte>.Shared.Rent((int)dataSize);
                    var dataDigestBuf = ArrayPool<byte>.Shared.Rent(0x40);
                    file.Seek(dataOffset, SeekOrigin.Begin);
                    await file.ReadExactlyAsync(dataBuf.AsMemory()[..(int)dataSize], cancellationToken).ConfigureAwait(false);
                    await file.ReadExactlyAsync(dataDigestBuf.AsMemory()[..0x40], cancellationToken).ConfigureAwait(false);
                    var data = dataBuf.AsSpan()[..(int)dataSize];
                    var digest = dataDigestBuf.AsSpan()[..0x40];
                    ValidateSection(data, digest, dataSigWidth);
                    ArrayPool<byte>.Shared.Return(dataBuf);
                    ArrayPool<byte>.Shared.Return(dataDigestBuf);
                }
                else
                {
                    Write("skipped".PadLeft(dataSigWidth)+" ", ConsoleColor.Yellow);
                }
                */

                // pkg checksum
                CurrentPadding = csumWidth;
                file.Seek(0, SeekOrigin.Begin);
                byte[] hash;
                using (var sha1 = SHA1.Create())
                {
                    var dataLengthToHash = CurrentFileSize - 0x20;
                    int read;
                    do
                    {
                        var memBuf = buf.AsMemory(0, (int)Math.Min(buf.Length, dataLengthToHash - CurrentFileProcessedBytes));
                        read = await file.ReadAsync(memBuf, cancellationToken).ConfigureAwait(false);
                        CurrentFileProcessedBytes += read;
                        sha1.TransformBlock(buf, 0, read, null, 0);
                    } while (read > 0 && CurrentFileProcessedBytes < dataLengthToHash && !cancellationToken.IsCancellationRequested);
                    sha1.TransformFinalBlock(buf, 0, 0);
                    hash = sha1.Hash!;
                }
                if (cancellationToken.IsCancellationRequested)
                    return;

                var expectedHash = new byte[0x14];
                await file.ReadExactlyAsync(expectedHash.AsMemory(), cancellationToken).ConfigureAwait(false);
                CurrentFileProcessedBytes += 0x20;
                if (!expectedHash.SequenceEqual(hash))
                    Write("csum".PadLeft(csumWidth) + Environment.NewLine, ConsoleColor.Red);
                else
                    Write("ok".PadLeft(csumWidth) + Environment.NewLine, ConsoleColor.Green);
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

    private static void ValidateSection(in ReadOnlySpan<byte> data, in ReadOnlySpan<byte> pkgDigest, int headerSigWidth)
    {
        var sha1Sum = SHA1.HashData(data);
        if (!ValidateCmac(data, pkgDigest))
            Write("cmac".PadLeft(headerSigWidth) + " ", ConsoleColor.Red);
        else if (!ValidateHash(pkgDigest, sha1Sum))
            Write("sha1".PadLeft(headerSigWidth) + " ", ConsoleColor.Yellow);
        else if (!ValidateSigNew(pkgDigest, sha1Sum))
        {
            if (!ValidateSigOld(pkgDigest, sha1Sum))
                Write("ecdsa".PadLeft(headerSigWidth) + " ", ConsoleColor.Red);
            else
                Write("ok (old)".PadLeft(headerSigWidth) + " ", ConsoleColor.Yellow);
        }
        else
            Write("ok".PadLeft(headerSigWidth) + " ", ConsoleColor.Green);
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
        if (str is not {Length: >0})
            return str;

        const string suffix = "…";
        if (str.Length <= maxLength)
            return str;
        
        if (maxLength > suffix.Length)
            return str[..(maxLength - suffix.Length)] + suffix;
        return str[..maxLength];
    }

    private static bool ValidateCmac(in ReadOnlySpan<byte> data, in ReadOnlySpan<byte> pkgDigest)
    {
        var actualCmac = GetCmac(data, VshCrypto.Ps3GpkgKey);
        return pkgDigest[..0x10].SequenceEqual(actualCmac);
    }

    private static byte[] GetCmac(in ReadOnlySpan<byte> data, in byte[] omacKey, bool truncate = true)
    {
        if (omacKey is not {Length: 0x10})
            throw new ArgumentException(nameof(omacKey));

        static byte[] AESEncrypt(byte[] key, byte[] iv, Span<byte> dataToEncrypt)
        {
            using var result = new MemoryStream();
            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            using var cs = new CryptoStream(result, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write);
            cs.Write(dataToEncrypt);
            cs.FlushFinalBlock();
            return result.ToArray();
        }

        static byte[] Rol(byte[] b)
        {
            var r = new byte[b.Length];
            byte carry = 0;
            for (var i = b.Length - 1; i >= 0; i--)
            {
                var u = (ushort)(b[i] << 1);
                r[i] = (byte)((u & 0xff) + carry);
                carry = (byte)((u & 0xff00) >> 8);
            }
            return r;
        }

        // SubKey generation
        // step 1, AES-128 with key K is applied to an all-zero input block.
        var derivedKey = AESEncrypt(omacKey, new byte[16], new byte[16]);

        // step 2, K1 is derived through the following operation:
        var subKey1 = Rol(derivedKey); //If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
        if ((derivedKey[0] & 0x80) == 0x80)
            subKey1[15] ^= 0x87; // Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.

        // step 3, K2 is derived through the following operation:
        var subKey2 = Rol(subKey1); // If the most significant bit of K1 is equal to 0, K2 is the left-shift of K1 by 1 bit.
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
            for (var j = 0; j < subKey2.Length; j++)
                buf[buf.Length - 16 + j] ^= subKey2[j];
        }

        // The result of the previous process will be the input of the last encryption.
        var encResult = AESEncrypt(omacKey, new byte[16], buf);
        if (truncate)
            return encResult.AsSpan(encResult.Length - 16, 16).ToArray();
        else
            return encResult.AsSpan(encResult.Length - 0x14, 0x14).ToArray();
    }

    private static bool ValidateSigNew(in ReadOnlySpan<byte> pkgDigest, in ReadOnlySpan<byte> hash)
    {
        var rs = VshCrypto.CreateReadOnlyPointRef(pkgDigest[0x10..0x38]);
        return VshCrypto.VshInvCurve2.Verify(VshCrypto.NpdrmQ, rs, hash);
    }

    private static bool ValidateSigOld(in ReadOnlySpan<byte> pkgDigest, in ReadOnlySpan<byte> hash)
    {
        var rs = VshCrypto.CreateReadOnlyPointRef(pkgDigest[0x10..0x38]);
        return VshCrypto.VshInvCurve2.Verify(VshCrypto.NpdrmQOld, rs, hash);
    }

    private static bool ValidateHash(in ReadOnlySpan<byte> pkgDigest, in ReadOnlySpan<byte> sha1)
        => pkgDigest[0x38..0x40].SequenceEqual(sha1[0x0c..0x14]);
}