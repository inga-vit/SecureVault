namespace SecureVault.Services;

public sealed class JwtOptions
{
    public required string Issuer { get; init; }

    public required string Audience { get; init; }

    public required byte[] SigningKey { get; init; }

    public TimeSpan AccessTokenLifetime { get; init; } = TimeSpan.FromMinutes(5);

    public TimeSpan RefreshTokenLifetime { get; init; } = TimeSpan.FromDays(7);
}
