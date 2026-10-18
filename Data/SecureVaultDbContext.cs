using Microsoft.EntityFrameworkCore;
using SecureVault.Models;

namespace SecureVault.Data;

public sealed class SecureVaultDbContext(DbContextOptions<SecureVaultDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var user = modelBuilder.Entity<User>();

        user.ToTable("Users");
        user.HasKey(user => user.Id);
        user.Property(user => user.Username)
            .HasMaxLength(32)
            .IsRequired();
        user.Property(user => user.Email)
            .HasMaxLength(254)
            .IsRequired();
        user.Property(user => user.PasswordHash)
            .HasMaxLength(256)
            .IsRequired();
        user.Property(user => user.Role)
            .HasConversion<string>()
            .HasMaxLength(16)
            .HasDefaultValue(UserRole.User)
            .IsRequired();
        user.HasIndex(user => user.Username)
            .IsUnique();
        user.HasIndex(user => user.Email)
            .IsUnique();

        var refreshToken = modelBuilder.Entity<RefreshToken>();
        refreshToken.ToTable("RefreshTokens");
        refreshToken.HasKey(token => token.TokenHash);
        refreshToken.Property(token => token.TokenHash)
            .HasMaxLength(64)
            .IsRequired();
        refreshToken.Property(token => token.ReplacedByTokenHash)
            .HasMaxLength(64);
        refreshToken.Property(token => token.FamilyId)
            .IsRequired();
        refreshToken.Property(token => token.ConcurrencyStamp)
            .IsConcurrencyToken();
        refreshToken.HasIndex(token => new { token.FamilyId, token.RevokedAt });
        refreshToken.HasOne(token => token.User)
            .WithMany()
            .HasForeignKey(token => token.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
