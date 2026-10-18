using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecureVault.Data;
using SecureVault.Models;
using SecureVault.Pages.Services;

namespace SecureVault.Services;

public sealed record TokenPair(
    string AccessToken,
    string TokenType,
    int ExpiresIn,
    string RefreshToken,
    DateTimeOffset RefreshTokenExpiresAt);

public sealed class ApiTokenService(
    SecureVaultDbContext dbContext,
    IOptions<JwtOptions> jwtOptions,
    TimeProvider timeProvider,
    ILogger<ApiTokenService> logger)
{
    private const int RefreshTokenBytes = 32;
    private static readonly TimeSpan RefreshTokenLifetime = TimeSpan.FromDays(7);
    private static readonly TimeSpan RefreshTokenFamilyLifetime = TimeSpan.FromDays(30);
    private JwtOptions Options => jwtOptions.Value;

    public async Task<TokenPair> IssueAsync(
        AuthenticatedUser user,
        CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();
        return await CreatePairAsync(
            user.Id,
            user.Username,
            user.Role,
            Guid.NewGuid(),
            now.Add(RefreshTokenFamilyLifetime),
            now,
            cancellationToken);
    }

    public async Task<TokenPair?> RotateAsync(
        string? presentedToken,
        CancellationToken cancellationToken = default)
    {
        if (!TryHashRefreshToken(presentedToken, out var tokenHash))
        {
            return null;
        }

        var storedToken = await dbContext.RefreshTokens
            .SingleOrDefaultAsync(token => token.TokenHash == tokenHash, cancellationToken);
        if (storedToken is null)
        {
            return null;
        }

        var now = timeProvider.GetUtcNow();
        if (storedToken.RevokedAt is not null)
        {
            await RevokeFamilyAsync(storedToken.FamilyId, now, cancellationToken);
            logger.LogWarning("Refresh token reuse detected for user {UserId}.", storedToken.UserId);
            return null;
        }

        if (storedToken.ExpiresAt <= now || storedToken.FamilyExpiresAt <= now)
        {
            await RevokeFamilyAsync(storedToken.FamilyId, now, cancellationToken);
            return null;
        }

        var user = await dbContext.Users
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == storedToken.UserId, cancellationToken);
        if (user is null)
        {
            await RevokeFamilyAsync(storedToken.FamilyId, now, cancellationToken);
            return null;
        }

        var (pair, replacement) = CreatePair(
            user.Id,
            user.Username,
            user.Role,
            storedToken.FamilyId,
            storedToken.FamilyExpiresAt,
            now);
        storedToken.RevokedAt = now;
        storedToken.ReplacedByTokenHash = replacement.TokenHash;
        storedToken.ConcurrencyStamp = Guid.NewGuid();
        dbContext.RefreshTokens.Add(replacement);

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            return pair;
        }
        catch (DbUpdateConcurrencyException)
        {
            dbContext.ChangeTracker.Clear();
            await RevokeFamilyAsync(storedToken.FamilyId, now, cancellationToken);
            logger.LogWarning("Concurrent refresh token use detected for user {UserId}.", user.Id);
            return null;
        }
    }

    public async Task RevokeAsync(
        string? presentedToken,
        CancellationToken cancellationToken = default)
    {
        if (!TryHashRefreshToken(presentedToken, out var tokenHash))
        {
            return;
        }

        var token = await dbContext.RefreshTokens
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.TokenHash == tokenHash, cancellationToken);
        if (token is not null)
        {
            await RevokeFamilyAsync(token.FamilyId, timeProvider.GetUtcNow(), cancellationToken);
        }
    }

    private async Task<TokenPair> CreatePairAsync(
        int userId,
        string username,
        UserRole role,
        Guid familyId,
        DateTimeOffset familyExpiresAt,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var (pair, refreshToken) = CreatePair(
            userId,
            username,
            role,
            familyId,
            familyExpiresAt,
            now);
        dbContext.RefreshTokens.Add(refreshToken);
        await dbContext.SaveChangesAsync(cancellationToken);
        return pair;
    }

    private (TokenPair Pair, RefreshToken RefreshToken) CreatePair(
        int userId,
        string username,
        UserRole role,
        Guid familyId,
        DateTimeOffset familyExpiresAt,
        DateTimeOffset now)
    {
        var expiresAt = now.Add(Options.AccessTokenLifetime);
        var refreshExpiresAt = Min(now.Add(Options.RefreshTokenLifetime), familyExpiresAt);
        var refreshToken = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(
            RandomNumberGenerator.GetBytes(RefreshTokenBytes));
        var refreshTokenHash = HashToken(refreshToken);
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new Claim("name", username),
            new Claim("role", role.ToString())
        };
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(Options.SigningKey),
            SecurityAlgorithms.HmacSha256);
        var jwt = new JwtSecurityToken(
            issuer: Options.Issuer,
            audience: Options.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expiresAt.UtcDateTime,
            signingCredentials: credentials);
        var accessToken = new JwtSecurityTokenHandler().WriteToken(jwt);

        return (
            new TokenPair(
                accessToken,
                "Bearer",
                (int)Options.AccessTokenLifetime.TotalSeconds,
                refreshToken,
                refreshExpiresAt),
            new RefreshToken
            {
                TokenHash = refreshTokenHash,
                UserId = userId,
                FamilyId = familyId,
                CreatedAt = now,
                ExpiresAt = refreshExpiresAt,
                FamilyExpiresAt = familyExpiresAt,
                ConcurrencyStamp = Guid.NewGuid()
            });
    }

    private static DateTimeOffset Min(DateTimeOffset first, DateTimeOffset second) =>
        first <= second ? first : second;

    private async Task RevokeFamilyAsync(
        Guid familyId,
        DateTimeOffset revokedAt,
        CancellationToken cancellationToken)
    {
        var activeTokens = dbContext.RefreshTokens.Where(token =>
            token.FamilyId == familyId && token.RevokedAt == null);

        if (dbContext.Database.IsRelational())
        {
            await activeTokens.ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(token => token.RevokedAt, revokedAt)
                    .SetProperty(token => token.ConcurrencyStamp, Guid.NewGuid()),
                cancellationToken);
            return;
        }

        var tokens = await activeTokens.ToListAsync(cancellationToken);
        foreach (var token in tokens)
        {
            token.RevokedAt = revokedAt;
            token.ConcurrencyStamp = Guid.NewGuid();
        }

        if (tokens.Count > 0)
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
    }

    private static bool TryHashRefreshToken(string? token, out string tokenHash)
    {
        tokenHash = string.Empty;
        if (token is null
            || token.Length != 43
            || token.Any(character =>
                !(character is >= 'A' and <= 'Z'
                    or >= 'a' and <= 'z'
                    or >= '0' and <= '9'
                    or '-' or '_')))
        {
            return false;
        }

        tokenHash = HashToken(token);
        return true;
    }

    private static string HashToken(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(token)));
}
