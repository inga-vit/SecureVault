using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SecureVault.Data;
using SecureVault.Pages.Services;
using Xunit;

namespace SecureVault.Tests;

public sealed class UserServiceInjectionTests
{
    [Theory]
    [InlineData("<script>alert(1)</script>")]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("admin' OR '1'='1")]
    [InlineData("admin; DROP TABLE Users;--")]
    public async Task RegisterAsync_RejectsUnsafeUsernamesWithoutPersisting(string username)
    {
        await using var dbContext = CreateDbContext();
        var service = CreateService(dbContext);

        var result = await service.RegisterAsync(username, "safe@example.com", "Strong-password-123!");

        Assert.Equal(RegistrationResult.InvalidUsername, result);
        Assert.Empty(await dbContext.Users.ToListAsync());
    }

    [Theory]
    [InlineData("<script>alert(1)</script>@example.com")]
    [InlineData("user@example.com' OR '1'='1")]
    [InlineData("user@example.com; DROP TABLE Users;--")]
    public async Task RegisterAsync_RejectsUnsafeEmailsWithoutPersisting(string email)
    {
        await using var dbContext = CreateDbContext();
        var service = CreateService(dbContext);

        var result = await service.RegisterAsync("safe-user", email, "Strong-password-123!");

        Assert.Equal(RegistrationResult.InvalidEmail, result);
        Assert.Empty(await dbContext.Users.ToListAsync());
    }

    private static SecureVaultDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<SecureVaultDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        return new SecureVaultDbContext(options);
    }

    private static UserService CreateService(SecureVaultDbContext dbContext) =>
        new(dbContext, NullLogger<UserService>.Instance);
}
