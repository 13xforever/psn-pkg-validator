using System;
using System.Security.Cryptography;

namespace PsnPkgCheck;

public ref struct ECPointRef(Span<byte> x, Span<byte> y)
{
    public Span<byte> X = x;
    public Span<byte> Y = y;

    public static implicit operator ECPointRef(ECPoint p) => new(p.X, p.Y);

    public void CopyFrom(in ECPoint p)
    {
        p.X.CopyTo(X);
        p.Y.CopyTo(Y);
    }

    public void CopyFrom(in ReadOnlyECPointRef p)
    {
        p.X.CopyTo(X);
        p.Y.CopyTo(Y);
    }
}

public readonly ref struct ReadOnlyECPointRef(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
{
    public readonly ReadOnlySpan<byte> X = x;
    public readonly ReadOnlySpan<byte> Y = y;

    public static implicit operator ReadOnlyECPointRef(ECPoint p) => new(p.X, p.Y);
    public static implicit operator ReadOnlyECPointRef(ECPointRef p) => new(p.X, p.Y);
}
