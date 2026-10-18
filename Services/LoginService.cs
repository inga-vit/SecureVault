using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureVault.Data;
using SecureVault.Helpers;
using SecureVault.Models;

namespace SecureVault.Pages.Services;

public sealed record AuthenticatedUser(int Id, string Username, UserRole Role);

public sealed class LoginService(
    SecureVaultDbContext dbContext,
    ILogger<LoginService> logger)
{
    private const string UsernameAllowedCharacters = "._-";
    private const int MaximumPasswordLength = 1024;
    private static readonly string DummyPasswordHash = PasswordService.Hash(
        Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));

    public async Task<AuthenticatedUser?> AuthenticateAsync(
        string? username,
        string? password,
        CancellationToken cancellationToken = default)
    {
        username = username?.Trim();

        if (username is null
            || username.Length is < 3 or > 32
            || !ValidationHelper.IsValidInput(username, UsernameAllowedCharacters))
        {
            VerifyAgainstDummyHash(password);
            logger.LogInformation("Authentication failed.");
            return null;
        }

        var user = await dbContext.Users
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Username == username, cancellationToken);

        if (user is null)
        {
            VerifyAgainstDummyHash(password);
            logger.LogInformation("Authentication failed.");
            return null;
        }

        if (password is null || password.Length > MaximumPasswordLength
            || !PasswordService.Verify(password, user.PasswordHash))
        {
            logger.LogInformation("Authentication failed.");
            return null;
        }

        logger.LogInformation("Authentication succeeded. UserId: {UserId}", user.Id);
        return new AuthenticatedUser(user.Id, user.Username, user.Role);
    }

    private static void VerifyAgainstDummyHash(string? password)
    {
        if (password is not null && password.Length <= MaximumPasswordLength)
        {
            PasswordService.Verify(password, DummyPasswordHash);
        }
    }
}