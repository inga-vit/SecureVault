namespace SecureVault.Models;

public sealed class RefreshToken
{
    public required string TokenHash { get; set; }

    public int UserId { get; set; }

    public Guid FamilyId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset FamilyExpiresAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public string? ReplacedByTokenHash { get; set; }

    public Guid ConcurrencyStamp { get; set; }

    public User User { get; set; } = null!;
}
