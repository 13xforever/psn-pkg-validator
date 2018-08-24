using System;
using System.Security.Cryptography;

namespace PsnPkgCheck
{
    public sealed class Ecdsa
    {
        private static readonly byte[] inv256 =
        {
            0x01, 0xab, 0xcd, 0xb7, 0x39, 0xa3, 0xc5, 0xef,
            0xf1, 0x1b, 0x3d, 0xa7, 0x29, 0x13, 0x35, 0xdf,
            0xe1, 0x8b, 0xad, 0x97, 0x19, 0x83, 0xa5, 0xcf,
            0xd1, 0xfb, 0x1d, 0x87, 0x09, 0xf3, 0x15, 0xbf,
            0xc1, 0x6b, 0x8d, 0x77, 0xf9, 0x63, 0x85, 0xaf,
            0xb1, 0xdb, 0xfd, 0x67, 0xe9, 0xd3, 0xf5, 0x9f,
            0xa1, 0x4b, 0x6d, 0x57, 0xd9, 0x43, 0x65, 0x8f,
            0x91, 0xbb, 0xdd, 0x47, 0xc9, 0xb3, 0xd5, 0x7f,
            0x81, 0x2b, 0x4d, 0x37, 0xb9, 0x23, 0x45, 0x6f,
            0x71, 0x9b, 0xbd, 0x27, 0xa9, 0x93, 0xb5, 0x5f,
            0x61, 0x0b, 0x2d, 0x17, 0x99, 0x03, 0x25, 0x4f,
            0x51, 0x7b, 0x9d, 0x07, 0x89, 0x73, 0x95, 0x3f,
            0x41, 0xeb, 0x0d, 0xf7, 0x79, 0xe3, 0x05, 0x2f,
            0x31, 0x5b, 0x7d, 0xe7, 0x69, 0x53, 0x75, 0x1f,
            0x21, 0xcb, 0xed, 0xd7, 0x59, 0xc3, 0xe5, 0x0f,
            0x11, 0x3b, 0x5d, 0xc7, 0x49, 0x33, 0x55, 0xff,
        };

        private readonly byte[] ecP;
        private readonly byte[] ecA;
        private readonly byte[] ecB;
        private readonly byte[] ecN;
        private readonly ECPoint ecG;

        public Ecdsa(Span<byte> p, Span<byte> a, Span<byte> b, Span<byte> n, ECPoint g)
        {
            try
            {
                ecP = p.ToArray();
                ecA = a.ToArray();
                ecB = b.ToArray();
                ecN = CloneAndExpand(n);
                ecG = Clone(g);

                bn_to_mon(ecA, ecP, 20);
                bn_to_mon(ecB, ecP, 20);
                point_to_mon(ecG);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw e;
            }
        }

        public bool Verify(in ECPoint q, Span<byte> r, Span<byte> s, Span<byte> hash)
        {
            try
            {
                var qCopy = Clone(q);
                var rCopy = CloneAndExpand(r);
                var sCopy = CloneAndExpand(s);
                var eCopy = CloneAndExpand(hash);

                point_to_mon(qCopy);

                bn_reduce(eCopy, ecN, 21);

                bn_to_mon(rCopy, ecN, 21);
                bn_to_mon(sCopy, ecN, 21);
                bn_to_mon(eCopy, ecN, 21);

                var sInv = new byte[21];
                bn_mon_inv(sInv, sCopy, ecN, 21);

                var w1 = new byte[21];
                var w2 = new byte[21];
                bn_mon_mul(w1, eCopy, sInv, ecN, 21);
                bn_mon_mul(w2, rCopy, sInv, ecN, 21);

                bn_from_mon(w1, ecN, 21);
                bn_from_mon(w2, ecN, 21);

                var r1 = new ECPoint { X = new byte[20], Y = new byte[20] };
                var r2 = new ECPoint { X = new byte[20], Y = new byte[20] };
                point_mul(r1, w1, ecG);
                point_mul(r2, w2, qCopy);

                point_add(r1, r1, r2);

                point_from_mon(r1);

                var rr = CloneAndExpand(r1.X);
                bn_reduce(rr, ecN, 21);

                bn_from_mon(rCopy, ecN, 21);
                bn_from_mon(sCopy, ecN, 21);

                return bn_compare(rr, rCopy, 21) == 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                throw ex;
            }
        }

        private static void bn_reduce(byte[] d, Span<byte> N, int n)
        {
            if (bn_compare(d, N, n) >= 0)
                bn_sub_1(d, d, N, n);
        }

        private static int bn_compare(Span<byte> a, Span<byte> b, int n)
        {
            for (var i = 0; i < n; i++)
            {
                if (a[i] < b[i])
                    return -1;

                if (a[i] > b[i])
                    return 1;
            }
            return 0;
        }

        private static bool bn_add_1(byte[] d, Span<byte> a, Span<byte> b, int n)
        {
            byte c = 0;
            for (var i = n - 1; i >= 0; i--)
            {
                var dig = a[i] + b[i] + c;
                d[i] = (byte)dig;
                c = (byte)(dig >> 8);
            }
            return c != 0;
        }

        private static bool bn_sub_1(byte[] d, Span<byte> a, Span<byte> b, int n)
        {
            byte c = 1;
            for (var i = n - 1; i >= 0; i--)
            {
                var dig = a[i] + 255 - b[i] + c;
                d[i] = (byte)dig;
                c = (byte)(dig >> 8);
            }
            return c == 0;
        }

        private static void bn_to_mon(byte[] d, Span<byte> N, int n)
        {
            for (var i = 0; i < n * 8; i++)
                bn_add(d, d, d, N, n);
        }

        private static void bn_add(byte[] d, Span<byte> a, Span<byte> b, Span<byte> N, int n)
        {
            if (bn_add_1(d, a, b, n))
                bn_sub_1(d, d, N, n);
            bn_reduce(d, N, n);
        }

        private static void bn_mon_inv(byte[] d, Span<byte> a, Span<byte> N, int n)
        {
            var t = new byte[512];
            var s = new byte[512];
            s[n - 1] = 2;
            bn_sub_1(t, N, s, n);
            bn_mon_exp(d, a, N, n, t, n);
        }

        private static void bn_zero(byte[] d, int n)
        {
            Array.Clear(d, 0, n);
        }

        private static void bn_copy(byte[] d, Span<byte> a, int n)
        {
            Buffer.BlockCopy(a.ToArray(), 0, d, 0, n);
        }

        private static void bn_mon_exp(byte[] d, Span<byte> a, Span<byte> N, int n, Span<byte> e, int en)
        {
            var t = new byte[512];
            bn_zero(d, n);
            d[n - 1] = 1;
            bn_to_mon(d, N, n);
            for (var i = 0; i < en; i++)
            for (byte mask = 0x80; mask != 0; mask >>= 1)
            {
                bn_mon_mul(t, d, d, N, n);
                if ((e[i] & mask) != 0)
                    bn_mon_mul(d, t, a, N, n);
                else
                    bn_copy(d, t, n);
            }
        }

        private static void bn_mon_mul(byte[] d, Span<byte> a, Span<byte> b, Span<byte> N, int n)
        {
            var t = new byte[512];
            for (var i = n - 1; i >= 0; i--)
                bn_mon_muladd_dig(t, a, b[i], N, n);
            bn_copy(d, t, n);
        }

        private static void bn_mon_muladd_dig(byte[] d, Span<byte> a, byte b, Span<byte> N, int n)
        {
            var z = (byte)(-(d[n - 1] + a[n - 1] * b) * inv256[N[n - 1] / 2]);

            var dig = d[n - 1] + a[n - 1] * b + N[n - 1] * z;
            dig >>= 8;

            for (var i = n - 2; i >= 0; i--)
            {
                dig += d[i] + a[i] * b + N[i] * z;
                d[i + 1] = (byte)dig;
                dig >>= 8;
            }

            d[0] = (byte)dig;
            dig >>= 8;

            if (dig != 0)
                bn_sub_1(d, d, N, n);

            bn_reduce(d, N, n);
        }

        private static void bn_from_mon(byte[] d, Span<byte> N, int n)
        {
            var t = new byte[512];
            t[n - 1] = 1;
            bn_mon_mul(d, d, t, N, n);
        }

        private void point_mul(ECPoint d, Span<byte> a, in ECPoint b)
        {
            point_zero(d);
            for (var i = 0; i < 21; i++)
            for (byte mask = 0x80; mask != 0; mask >>= 1)
            {
                point_double(d, d);
                if ((a[i] & mask) != 0)
                    point_add(d, d, b);
            }
        }

        private static void point_zero(ECPoint d)
        {
            Array.Clear(d.X, 0, d.X.Length);
            Array.Clear(d.Y, 0, d.Y.Length);
        }

        private void point_double(ECPoint r, in ECPoint p)
        {
            var s = new byte[20];
            var t = new byte[20];

            if (elt_is_zero(p.Y))
            {
                point_zero(r);
                return;
            }

            var pp = Clone(p);

            elt_square(t, pp.X); // t = px*px
            elt_add(s, t, t); // s = 2*px*px
            elt_add(s, s, t); // s = 3*px*px
            elt_add(s, s, ecA); // s = 3*px*px + a

            elt_add(t, pp.Y, pp.Y); // t = 2*py
            elt_inv(t, t); // t = 1/(2*py)
            elt_mul(s, s, t); // s = (3*px*px+a)/(2*py)

            elt_square(r.X, s); // rx = s*s
            elt_add(t, pp.X, pp.X); // t = 2*px
            elt_sub(r.X, r.X, t); // rx = s*s - 2*px

            elt_sub(t, pp.X, r.X); // t = -(rx-px)
            elt_mul(r.Y, s, t); // ry = -s*(rx-px)
            elt_sub(r.Y, r.Y, pp.Y); // ry = -s*(rx-px) - py
        }

        private void elt_square(byte[] d, Span<byte> a)
        {
            elt_mul(d, a, a);
        }

        private void elt_mul(byte[] d, Span<byte> a, Span<byte> b)
        {
            bn_mon_mul(d, a, b, ecP, 20);
        }

        private void elt_add(byte[] d, Span<byte> a, Span<byte> b)
        {
            bn_add(d, a, b, ecP, 20);
        }

        private void elt_inv(byte[] d, Span<byte> a)
        {
            var s = new byte[20];
            elt_copy(s, a);
            bn_mon_inv(d, s, ecP, 20);
        }

        private static void elt_copy(byte[] d, Span<byte> a)
        {
            Buffer.BlockCopy(a.ToArray(), 0, d, 0, 20);
        }

        private static bool elt_is_zero(Span<byte> d)
        {
            for (var i = 0; i < 20; i++)
                if (d[i] != 0)
                    return false;
            return true;
        }

        private void elt_sub(byte[] d, Span<byte> a, Span<byte> b)
        {
            bn_sub(d, a, b, ecP, 20);
        }

        private static void bn_sub(byte[] d, Span<byte> a, Span<byte> b, Span<byte> N, int n)
        {
            if (bn_sub_1(d, a, b, n))
                bn_add_1(d, d, N, n);
        }

        private void point_add(ECPoint r, in ECPoint p, in ECPoint q)
        {
            if (point_is_zero(p))
            {
                elt_copy(r.X, q.X);
                elt_copy(r.Y, q.Y);
                return;
            }

            if (point_is_zero(q))
            {
                elt_copy(r.X, p.X);
                elt_copy(r.Y, p.Y);
                return;
            }

            var u = new byte[20];
            var pp = Clone(p);
            var qq = Clone(q);
            elt_sub(u, qq.X, pp.X);

            if (elt_is_zero(u))
            {
                elt_sub(u, qq.Y, pp.Y);
                if (elt_is_zero(u))
                    point_double(r, pp);
                else
                    point_zero(r);
                return;
            }

            var t = new byte[20];
            elt_inv(t, u); // t = 1/(qx-px)
            elt_sub(u, qq.Y, pp.Y); // u = qy-py
            var s = new byte[20];
            elt_mul(s, t, u); // s = (qy-py)/(qx-px)
            elt_square(r.X, s); // rx = s*s
            elt_add(t, pp.X, qq.X); // t = px+qx
            elt_sub(r.X, r.X, t); // rx = s*s - (px+qx)

            elt_sub(t, pp.X, r.X); // t = -(rx-px)
            elt_mul(r.Y, s, t); // ry = -s*(rx-px)
            elt_sub(r.Y, r.Y, pp.Y); // ry = -s*(rx-px) - py
        }

        private static bool point_is_zero(in ECPoint p)
        {
            return elt_is_zero(p.X) && elt_is_zero(p.Y);
        }

        private void point_from_mon(ECPoint p)
        {
            bn_from_mon(p.X, ecP, 20);
            bn_from_mon(p.Y, ecP, 20);
        }

        private void point_to_mon(ECPoint p)
        {
            bn_to_mon(p.X, ecP, 20);
            bn_to_mon(p.Y, ecP, 20);
        }

        private static ECPoint Clone(ECPoint p)
        {
            var result = new ECPoint
            {
                X = new byte[20],
                Y = new byte[20],
            };
            Buffer.BlockCopy(p.X, 0, result.X, 0 , 20);
            Buffer.BlockCopy(p.Y, 0, result.Y, 0 , 20);
            return result;
        }

        private static byte[] CloneAndExpand(Span<byte> a)
        {
            var result = new byte[21];
            Buffer.BlockCopy(a.ToArray(), 0, result, 1, 20);
            return result;
        }
    }
}