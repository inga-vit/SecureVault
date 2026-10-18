using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureVault.Data;
using SecureVault.Models;
using SecureVault.Pages.Services;
using SecureVault.Services;
using Xunit;

namespace SecureVault.Tests;

public sealed class ApiTokenServiceTests
{
    [Fact]
    public async Task IssueAsync_CreatesShortLivedJwtAndStoresOnlyRefreshTokenHash()
    {
        const string username = "vault-admin";
        await using var dbContext = CreateDbContext();
        var user = new User
        {
            Username = username,
            Email = "admin@example.com",
            PasswordHash = PasswordService.Hash("Strong-password-123!"),
            Role = UserRole.Admin
        };
        dbContext.Users.Add(user);
        await dbContext.SaveChangesAsync();
        var service = CreateService(dbContext);

        var pair = await service.IssueAsync(new AuthenticatedUser(user.Id, username, user.Role));
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(pair.AccessToken);
        var storedRefreshToken = await dbContext.RefreshTokens.SingleAsync();

        Assert.Equal("Bearer", pair.TokenType);
        Assert.Equal(300, pair.ExpiresIn);
        Assert.Equal(username, jwt.Claims.Single(claim => claim.Type == "name").Value);
        Assert.Equal(nameof(UserRole.Admin), jwt.Claims.Single(claim => claim.Type == "role").Value);
        Assert.Equal(64, storedRefreshToken.TokenHash.Length);
        Assert.NotEqual(pair.RefreshToken, storedRefreshToken.TokenHash);
        Assert.Equal(TimeSpan.FromDays(7), pair.RefreshTokenExpiresAt - storedRefreshToken.CreatedAt);
        var familyLifetime = storedRefreshToken.FamilyExpiresAt - storedRefreshToken.CreatedAt;
        Assert.InRange(familyLifetime, TimeSpan.FromDays(30) - TimeSpan.FromSeconds(1), TimeSpan.FromDays(30));
    }

    [Fact]
    public async Task RotateAsync_RevokesOldTokenAndIssuesReplacement()
    {
        var (service, dbContext, user) = await CreateSeededServiceAsync();

        var original = await service.IssueAsync(new AuthenticatedUser(user.Id, user.Username, user.Role));
        var rotated = await service.RotateAsync(original.RefreshToken);

        Assert.NotNull(rotated);
        Assert.NotEqual(original.RefreshToken, rotated.RefreshToken);
        var records = await dbContext.RefreshTokens.OrderBy(token => token.CreatedAt).ToListAsync();
        Assert.Equal(2, records.Count);
        Assert.NotNull(records[0].RevokedAt);
        Assert.Equal(records[1].TokenHash, records[0].ReplacedByTokenHash);
        Assert.Null(records[1].RevokedAt);
    }

    [Fact]
    public async Task RotateAsync_ReuseOfRevokedTokenRevokesTheWholeTokenFamily()
    {
        var (service, dbContext, user) = await CreateSeededServiceAsync();
        var original = await service.IssueAsync(new AuthenticatedUser(user.Id, user.Username, user.Role));
        var rotated = await service.RotateAsync(original.RefreshToken);
        Assert.NotNull(rotated);

        var replayResult = await service.RotateAsync(original.RefreshToken);
        var replacementResult = await service.RotateAsync(rotated.RefreshToken);

        Assert.Null(replayResult);
        Assert.Null(replacementResult);
        Assert.All(
            await dbContext.RefreshTokens.ToListAsync(),
            token => Assert.NotNull(token.RevokedAt));
    }

    [Fact]
    public async Task RevokeAsync_RevokesAllTokensInFamily()
    {
        var (service, dbContext, user) = await CreateSeededServiceAsync();
        var original = await service.IssueAsync(new AuthenticatedUser(user.Id, user.Username, user.Role));
        var rotated = await service.RotateAsync(original.RefreshToken);
        Assert.NotNull(rotated);

        await service.RevokeAsync(rotated.RefreshToken);

        Assert.All(
            await dbContext.RefreshTokens.ToListAsync(),
            token => Assert.NotNull(token.RevokedAt));
    }

    [Fact]
    public async Task RotateAsync_RejectsMalformedAndUnknownTokens()
    {
        var (service, _, _) = await CreateSeededServiceAsync();

        Assert.Null(await service.RotateAsync("not-a-refresh-token"));
        Assert.Null(await service.RotateAsync(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32))));
    }

    private static SecureVaultDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<SecureVaultDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new SecureVaultDbContext(options);
    }

    private static ApiTokenService CreateService(SecureVaultDbContext dbContext)
    {
        var jwtOptions = Options.Create(new JwtOptions
        {
            Issuer = "SecureVault.Tests",
            Audience = "SecureVault.Tests.Api",
            SigningKey = RandomNumberGenerator.GetBytes(32)
        });
        return new ApiTokenService(
            dbContext,
            jwtOptions,
            TimeProvider.System,
            NullLogger<ApiTokenService>.Instance);
    }

    private static async Task<(ApiTokenService Service, SecureVaultDbContext DbContext, User User)>
        CreateSeededServiceAsync()
    {
        var dbContext = CreateDbContext();
        var user = new User
        {
            Username = "test-user",
            Email = "test@example.com",
            PasswordHash = PasswordService.Hash("Strong-password-123!")
        };
        dbContext.Users.Add(user);
        await dbContext.SaveChangesAsync();
        return (CreateService(dbContext), dbContext, user);
    }
}
