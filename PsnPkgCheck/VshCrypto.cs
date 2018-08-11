using System;
using System.Globalization;
using System.Security.Cryptography;

namespace PsnPkgCheck
{
    internal static class VshCrypto
    {
        internal static readonly byte[] NpdrmPubKey1 = ("E6792E446CEBA27BCADF374B99504FD8E80ADFEB" +
                                                        "3E66DE73FFE58D3291221C65018C038D3822C3C9").AsBytes();
        internal static readonly byte[] NpdrmPubKey2 = ("D9AAEB6054307FC0FB488B15AE11B558C75FC8A3" +
                                                        "EC4907E129C5B5CD386D94D82318B9D558777C5A").AsBytes();
        internal static readonly ECParameters Npdrm1ECParameters;
        internal static readonly ECParameters Npdrm2ECparameters;
        internal static readonly byte[] Ps3GpkgKey = "2E7B71D7C9C9A14EA3221F188828B8F8".AsBytes();
        internal static readonly byte[] VshPubKey = ("6227B00A02856FB04108876719E0A0183291EEB9" +
                                                     "6E736ABF81F70EE9161B0DDEB026761AFF7BC85B").AsBytes();
        internal static readonly ECCurve VshCurve1;
        internal static readonly ECCurve VshCurve2;
        internal static readonly ECCurve VshInvCurve1;
        internal static readonly ECCurve VshInvCurve2;

        private static readonly byte[] VshCurve1Data = ("0000000000000000FFFFFFFE0000000000000000" +
                                                        "0000000000000000FFFFFFFE0000000000000003" +
                                                        "9A2EB773FCA61DCB5236A42C6F7FEB426E5ADA06" +
                                                        "0000000000000000FFFE4A39E80D6F151E245270" +
                                                        "DDA65311EAB7634F69577D0F51E30602711A0705" +
                                                        "9FBCA7BA92F5E34D6F7216F0D828A37D413EF73F").AsBytes();
        private static readonly byte[] VshCurve2Data = ("0000000000000000FFFFFFFE0000000000000000" +
                                                        "0000000000000000FFFFFFFE0000000000000003" +
                                                        "5974123CCBE7FD63E2C31CC465CDE0334461F0F4" +
                                                        "000000000000000100004A51C3ADC19C6BB0DED8" +
                                                        "ED713BDA9B780270209B1DBC843F5E092A5021D3" +
                                                        "A6A7AA814E24FFED9FBDAADB243C862A53A0B520").AsBytes();
        private static readonly byte[] VshInvCurve1Data =("FFFFFFFFFFFFFFFF00000001FFFFFFFFFFFFFFFF" +
                                                          "FFFFFFFFFFFFFFFF00000001FFFFFFFFFFFFFFFC" +
                                                          "65D1488C0359E234ADC95BD3908014BD91A525F9" +
                                                          "FFFFFFFFFFFFFFFF0001B5C617F290EAE1DBAD8F" +
                                                          "2259ACEE15489CB096A882F0AE1CF9FD8EE5F8FA" +
                                                          "604358456D0A1CB2908DE90F27D75C82BEC108C0").AsBytes();
        private static readonly byte[] VshInvCurve2Data =("FFFFFFFFFFFFFFFF00000001FFFFFFFFFFFFFFFF" +
                                                          "FFFFFFFFFFFFFFFF00000001FFFFFFFFFFFFFFFC" +
                                                          "A68BEDC33418029C1D3CE33B9A321FCCBB9E0F0B" +
                                                          "FFFFFFFFFFFFFFFEFFFFB5AE3C523E63944F2127" +
                                                          "128EC4256487FD8FDF64E2437BC0A1F6D5AFDE2C" +
                                                          "5958557EB1DB001260425524DBC379D5AC5F4ADF").AsBytes();


        static VshCrypto()
        {
            //VshCurve1 = CreateCurve(VshCurve1Data);
            //VshCurve2 = CreateCurve(VshCurve2Data);
            //VshInvCurve1 = CreateCurve(VshInvCurve1Data);
            //VshInvCurve2 = CreateCurve(VshInvCurve2Data);

            Npdrm1ECParameters = new ECParameters
            {
                Curve = VshInvCurve2,
                Q = CreatePoint(NpdrmPubKey1),
            };
            Npdrm2ECparameters = new ECParameters
            {
                Curve = VshInvCurve2,
                Q = CreatePoint(NpdrmPubKey2),
            };
        }

        private static ECCurve CreateCurve(Span<byte> curveData)
        {
            var result = new ECCurve
            {
                CurveType = ECCurve.ECCurveType.PrimeTwistedEdwards,
                Prime = curveData.Slice(0, 0x14).ToArray(),
                A = curveData.Slice(0x14, 0x14).ToArray(),
                B = curveData.Slice(0x28, 0x14).ToArray(),
                Order = curveData.Slice(0x3c, 0x14).ToArray(),
                G = CreatePoint(curveData.Slice(0x40, 0x28)),
            };
            try
            {
                result.Validate();
                return result;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e);
                throw e;
            }
        }

        private static ECPoint CreatePoint(Span<byte> pointData)
        {
            return new ECPoint
            {
                X = pointData.Slice(0, 0x14).ToArray(),
                Y = pointData.Slice(0x14, 0x14).ToArray(),
            };
        }

        private static byte[] AsBytes(this string hexString)
        {
            if (hexString == null)
                return null;

            if (hexString.Length == 0)
                return new byte[0];

            if (hexString.Length%2 == 1)
                throw new ArgumentException("Hex string cannot have an odd number of characters");

            var result = new byte[hexString.Length / 2];
            for (int ri = 0, si = 0; ri < result.Length; ri++, si += 2)
                result[ri] = byte.Parse(hexString.Substring(si, 2), NumberStyles.HexNumber);
            return result;
        }
    }
}
