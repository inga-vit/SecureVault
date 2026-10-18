using System.ComponentModel.DataAnnotations;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureVault.Data;
using SecureVault.Helpers;
using SecureVault.Models;

namespace SecureVault.Pages.Services;

public enum RegistrationResult
{
    Registered,
    InvalidUsername,
    InvalidEmail,
    InvalidPassword,
    UsernameAlreadyExists,
    EmailAlreadyExists
}

//Using EF Core converts all queries into parameterized queries, so there is no risk of SQL injection here.
public sealed class UserService(SecureVaultDbContext dbContext, ILogger<UserService> logger)
{
    private const string UsernameAllowedCharacters = "._-";
    private const string EmailAllowedCharacters = "@._+-";
    private const int MaximumPasswordLength = 1024;


    public async Task<RegistrationResult> RegisterAsync(
        string? username,
        string? email,
        string? password,
        CancellationToken cancellationToken = default)
    {
        username = username?.Trim();
        email = email?.Trim();

        if (username is null
            || username.Length is < 3 or > 32
            || !ValidationHelper.IsValidInput(username, UsernameAllowedCharacters))
        {
            return RegistrationResult.InvalidUsername;
        }

        if (email is null
            || email.Length > 254
            || !ValidationHelper.IsValidInput(email, EmailAllowedCharacters)
            || !new EmailAddressAttribute().IsValid(email))
        {
            return RegistrationResult.InvalidEmail;
        }

        if (password is null
            || password.Length < 8
            || password.Length > MaximumPasswordLength)
        {
            return RegistrationResult.InvalidPassword;
        }

        if (await dbContext.Users.AnyAsync(user => user.Username == username, cancellationToken))
        {
            return RegistrationResult.UsernameAlreadyExists;
        }

        if (await dbContext.Users.AnyAsync(user => user.Email == email, cancellationToken))
        {
            return RegistrationResult.EmailAlreadyExists;
        }

        var user = new User
        {
            Username = username,
            Email = email,
            PasswordHash = PasswordService.Hash(password),
            Role = UserRole.User
        };
        dbContext.Users.Add(user);

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException exception) when (IsUniqueConstraintViolation(exception))
        {
            if (await dbContext.Users.AnyAsync(user => user.Username == username, cancellationToken))
            {
                return RegistrationResult.UsernameAlreadyExists;
            }

            if (await dbContext.Users.AnyAsync(user => user.Email == email, cancellationToken))
            {
                return RegistrationResult.EmailAlreadyExists;
            }

            throw;
        }

        logger.LogInformation(
            "User registration succeeded. UserId: {UserId}",
            user.Id);

        return RegistrationResult.Registered;
    }

    private static bool IsUniqueConstraintViolation(DbUpdateException exception) =>
        exception.InnerException is SqlException { Number: 2601 or 2627 };
}