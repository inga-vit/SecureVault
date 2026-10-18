namespace SecureVault.Models;

public enum UserRole
{
    User,
    Admin
}

public sealed class User
{
    public int Id { get; set; }

    public required string Username { get; set; }

    public required string Email { get; set; }
    public required string PasswordHash { get; set; }

    public UserRole Role { get; set; } = UserRole.User;
}
