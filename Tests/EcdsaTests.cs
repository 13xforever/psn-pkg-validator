using NUnit.Framework;
using PsnPkgCheck;

namespace Tests;

[TestFixture]
public class EcdsaTests
{
    [Test]
    public void EcdsaVerificationTest()
    {
        var hash = "ab59624d92c9c3c8d82dffca9abde44ae98e5853".AsBytes();
        var rs = VshCrypto.CreateReadOnlyPointRef("9445F62151BA0F0AAF47D1483B0D0FC6F75C3388779450C9CDE48116C966D99AA8F893A140540AFE".AsBytes());
        var result = VshCrypto.VshInvCurve2.Verify(VshCrypto.VshPubQ, rs, hash);
        Assert.That(result, Is.True);
    }
}