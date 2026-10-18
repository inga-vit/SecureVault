using SecureVault.Pages.Services;
using Xunit;

namespace SecureVault.Tests;

public sealed class PasswordServiceTests
{
    [Fact]
    public void Hash_ProducesDifferentHashesForSamePassword()
    {
        const string password = "Strong-password-123!";

        var firstHash = PasswordService.Hash(password);
        var secondHash = PasswordService.Hash(password);

        Assert.NotEqual(firstHash, secondHash);
        Assert.StartsWith("$argon2id$v=19$m=65536,t=3,p=1$", firstHash);
    }

    [Fact]
    public void Verify_ReturnsTrueForMatchingPassword()
    {
        const string password = "Strong-password-123!";
        var hash = PasswordService.Hash(password);

        Assert.True(PasswordService.Verify(password, hash));
    }

    [Fact]
    public void Verify_ReturnsFalseForDifferentPassword()
    {
        var hash = PasswordService.Hash("Strong-password-123!");

        Assert.False(PasswordService.Verify("Different-password-456!", hash));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-an-argon2-hash")]
    [InlineData("$argon2id$v=19$m=65536,t=3,p=1$bad$hash")]
    [InlineData("$argon2id$v=19$m=999999999,t=3,p=1$bad$hash")]
    public void Verify_ReturnsFalseForInvalidEncodedHash(string? hash)
    {
        Assert.False(PasswordService.Verify("Strong-password-123!", hash));
    }

    [Fact]
    public void Verify_ReturnsFalseForNullPassword()
    {
        var hash = PasswordService.Hash("Strong-password-123!");

        Assert.False(PasswordService.Verify(null, hash));
    }
}
