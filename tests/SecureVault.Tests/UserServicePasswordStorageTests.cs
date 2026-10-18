using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SecureVault.Data;
using SecureVault.Models;
using SecureVault.Pages.Services;
using Xunit;

namespace SecureVault.Tests;

public sealed class UserServicePasswordStorageTests
{
    [Fact]
    public async Task RegisterAsync_PersistsArgon2idHashContainingSalt()
    {
        const string password = "Strong-password-123!";
        var options = new DbContextOptionsBuilder<SecureVaultDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        await using var dbContext = new SecureVaultDbContext(options);
        var service = new UserService(dbContext, NullLogger<UserService>.Instance);

        var result = await service.RegisterAsync("safe-user", "safe@example.com", password);
        var savedUser = await dbContext.Users.SingleAsync();

        Assert.Equal(RegistrationResult.Registered, result);
        Assert.Equal(UserRole.User, savedUser.Role);
        Assert.StartsWith("$argon2id$v=19$m=65536,t=3,p=1$", savedUser.PasswordHash);
        Assert.True(PasswordService.Verify(password, savedUser.PasswordHash));
        Assert.DoesNotContain(password, savedUser.PasswordHash, StringComparison.Ordinal);
    }
}
