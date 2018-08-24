using System;
using System.Globalization;
using System.Security.Cryptography;

namespace PsnPkgCheck
{
    public static class VshCrypto
    {
        public static readonly byte[] NpdrmPubKey = ("E6792E446CEBA27BCADF374B99504FD8E80ADFEB" +
                                                     "3E66DE73FFE58D3291221C65018C038D3822C3C9").AsBytes();

        public static readonly byte[] NpdrmPubKeyOld = ("D9AAEB6054307FC0FB488B15AE11B558C75FC8A3" +
                                                        "EC4907E129C5B5CD386D94D82318B9D558777C5A").AsBytes();

        public static readonly byte[] VshPubKey = ("6227B00A02856FB04108876719E0A0183291EEB9" +
                                                   "6E736ABF81F70EE9161B0DDEB026761AFF7BC85B").AsBytes();
        public static ECPoint NpdrmQ => CreatePoint(NpdrmPubKey);
        public static ECPoint NpdrmQOld => CreatePoint(NpdrmPubKeyOld);
        public static ECPoint VshPubQ => CreatePoint(VshPubKey);
        public static readonly byte[] Ps3GpkgKey = "2E7B71D7C9C9A14EA3221F188828B8F8".AsBytes();
        public static Ecdsa VshCurve1 => CreateCurve(VshCurve1Data);
        public static Ecdsa VshCurve2 => CreateCurve(VshCurve2Data);
        public static Ecdsa VshInvCurve1 => CreateCurve(VshInvCurve1Data);
        public static Ecdsa VshInvCurve2 => CreateCurve(VshInvCurve2Data);

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
        private static readonly byte[] VshInvCurve2Data =("FFFFFFFFFFFFFFFF00000001FFFFFFFFFFFFFFFF" + // p
                                                          "FFFFFFFFFFFFFFFF00000001FFFFFFFFFFFFFFFC" + // a
                                                          "A68BEDC33418029C1D3CE33B9A321FCCBB9E0F0B" + // b
                                                          "FFFFFFFFFFFFFFFEFFFFB5AE3C523E63944F2127" + // n
                                                          "128EC4256487FD8FDF64E2437BC0A1F6D5AFDE2C" + // gx
                                                          "5958557EB1DB001260425524DBC379D5AC5F4ADF").AsBytes(); // gy
        public static readonly string[] NpdrmPublicKeys =
        {
            "B05F9DA5F9121EE4031467E74C505C29A8E29D1022379EDFF0500B9AE480B5DAB4578A4C61C5D6BF",
            "05BF09CB6FD78050C78DE69CC316FF27C9F1ED66A45BFCE0A1E5A6749B19BD546BBB4602CF373440",
            "3F51E59FC74D6618D34431FA67987FA11ABBFACC7111811473CD9988FE91C43FC74605E7B8CB732D",
            "9C327471BAFF1F877AE4FE29F4501AF5AD6A2C459F8622697F583EFCA2CA30ABB5CD45D1131CAB30",
            "2A5D6C6908CA98FC4740D834C6400E6D6AD74CF0A712CF1E7DAE806E98605CC308F6A03658F2970E",
            "A13AFE8B63F897DA2D3DC3987B39389DC10BAD99DFB703838C4A0BC4E8BB44659C726CFD0CE60D0E",
            "A1FE61035DBBEA5A94D120D03C000D3B2F084B9F4AFA99A2D4A588DF92B8F36327CE9E47889A45D0",
            "3995C390C9F7FBBAB124A1C14E70F9741A5E6BDF17A605D88239652C8EA7D5FC9F24B30546C1E44B",
            "00DCF5391618604AB42C8CFF3DC304DF45341EBA4551293E9E2B68FFE2DF527FFA3BE8329E015E57",
            "9BFF1CC7118D2393DE50D5CF44909860683411A532767BFDAC78622DB9E5456753FE422CBAFA1DA1",
            "BBD7CCCB556C2EF0F908DC7810FAFC37F2E56B3DAA5F7FAF53A4944AA9B841F76AB091E16B231433",
            "64A5C60BC2AD18B8A237E4AA690647E12BF7A081523FAD4F29BE89ACAC72F7AB43C74EC9AFFDA213",
            "9D8DB5A880608DC69717991AFC3AD5C0215A5EE413328C2ABC8F35589E04432373DB2E2339EEF7C8",
            "62DFE488E410B1B6B2F559E4CB932BCB78845AB623CC59FDF65168400FD76FA82ED1DC60E091D1D1",
            "637EAD34E7B85C723C627E68ABDD0419914EBED4008311731DD87FDDA2DAF71F856A70E14DA17B42",
            "503172C9551308A87621ECEE90362D14889BFED2CF32B0B3E32A4F9FE527A41464B735E1ADBC6762",
            "9BFF1CC7118D2393DE50D5CF44909860683411A532767BFDAC78622DB9E5456753FE422CBAFA1DA1",
        };

        public static readonly string[] NpdrmOmacKeys =
        {
            "72F990788F9CFF745725F08E4C128387",
            "6BA52976EFDA16EF3C339FB2971E256B",
            "9B515FEACF75064981AA604D91A54E97",
        };

        private static Ecdsa CreateCurve(Span<byte> curveData)
        {
            return new Ecdsa(
                curveData.Slice(0x00, 0x14),
                curveData.Slice(0x14, 0x14),
                curveData.Slice(0x28, 0x14),
                curveData.Slice(0x3c, 0x14),
                CreatePoint(curveData.Slice(0x50, 0x28))
            );
        }

        public static ECPoint CreatePoint(Span<byte> pointData)
        {
            return new ECPoint
            {
                X = pointData.Slice(0x00, 0x14).ToArray(),
                Y = pointData.Slice(0x14, 0x14).ToArray(),
            };
        }

        public static byte[] AsBytes(this string hexString)
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
