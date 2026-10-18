using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SecureVault.Data;
using SecureVault.Models;
using SecureVault.Pages.Services;
using Microsoft.AspNetCore.Authorization;
using Xunit;

namespace SecureVault.Tests;

public sealed class LoginServiceTests
{
    [Fact]
    public async Task AuthenticateAsync_ReturnsUserForValidCredentials()
    {
        const string password = "Strong-password-123!";
        await using var dbContext = CreateDbContext();
        dbContext.Users.Add(new User
        {
            Username = "safe-user",
            Email = "safe@example.com",
            PasswordHash = PasswordService.Hash(password)
        });
        await dbContext.SaveChangesAsync();
        var service = CreateService(dbContext);

        var authenticatedUser = await service.AuthenticateAsync("safe-user", password);

        Assert.NotNull(authenticatedUser);
        Assert.Equal("safe-user", authenticatedUser.Username);
        Assert.Equal(1, authenticatedUser.Id);
        Assert.Equal(UserRole.User, authenticatedUser.Role);
    }

    [Theory]
    [InlineData("safe-user", "incorrect-password")]
    [InlineData("missing-user", "Strong-password-123!")]
    [InlineData("missing-user", "incorrect-password")]
    public async Task AuthenticateAsync_ReturnsNullForInvalidCredentials(string username, string password)
    {
        await using var dbContext = CreateDbContext();
        dbContext.Users.Add(new User
        {
            Username = "safe-user",
            Email = "safe@example.com",
            PasswordHash = PasswordService.Hash("Strong-password-123!")
        });
        await dbContext.SaveChangesAsync();
        var service = CreateService(dbContext);

        var result = await service.AuthenticateAsync(username, password);

        Assert.Null(result);
    }

    [Fact]
    public async Task AuthenticateAsync_DoesNotTrimPassword()
    {
        const string password = " password with spaces ";
        await using var dbContext = CreateDbContext();
        dbContext.Users.Add(new User
        {
            Username = "safe-user",
            Email = "safe@example.com",
            PasswordHash = PasswordService.Hash(password)
        });
        await dbContext.SaveChangesAsync();
        var service = CreateService(dbContext);

        var result = await service.AuthenticateAsync("safe-user", password);

        Assert.NotNull(result);
    }

    [Fact]
    public async Task AuthenticateAsync_ReturnsAdminRoleForAdminAccount()
    {
        const string password = "Strong-password-123!";
        await using var dbContext = CreateDbContext();
        dbContext.Users.Add(new User
        {
            Username = "vault-admin",
            Email = "admin@example.com",
            PasswordHash = PasswordService.Hash(password),
            Role = UserRole.Admin
        });
        await dbContext.SaveChangesAsync();
        var service = CreateService(dbContext);

        var authenticatedUser = await service.AuthenticateAsync("vault-admin", password);

        Assert.NotNull(authenticatedUser);
        Assert.Equal(UserRole.Admin, authenticatedUser.Role);
    }

    [Fact]
    public void AdminDashboard_RequiresAdminRole()
    {
        var authorization = typeof(SecureVault.Pages.AdminDashboardModel)
            .GetCustomAttributes(typeof(AuthorizeAttribute), inherit: true)
            .Cast<AuthorizeAttribute>()
            .Single();

        Assert.Equal(nameof(UserRole.Admin), authorization.Roles);
    }

    [Fact]
    public void UserDashboard_AllowsAnyAuthenticatedRole()
    {
        var authorization = typeof(SecureVault.Pages.UserDashboardModel)
            .GetCustomAttributes(typeof(AuthorizeAttribute), inherit: true)
            .Cast<AuthorizeAttribute>()
            .Single();

        Assert.Null(authorization.Roles);
    }

    private static SecureVaultDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<SecureVaultDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new SecureVaultDbContext(options);
    }

    private static LoginService CreateService(SecureVaultDbContext dbContext) =>
        new(dbContext, NullLogger<LoginService>.Instance);
}
