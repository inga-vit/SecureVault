using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace SecureVault.Pages.Services;

public static class PasswordService
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int MemorySizeKiB = 65_536;
    private const int Iterations = 3;
    private const int DegreeOfParallelism = 1;
    private const string EncodedParameters = "m=65536,t=3,p=1";

    public static string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = DeriveHash(password, salt);

        return $"$argon2id$v=19${EncodedParameters}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string? password, string? encodedHash)
    {
        if (password is null || !TryParseHash(encodedHash, out var salt, out var expectedHash))
        {
            return false;
        }

        var actualHash = DeriveHash(password, salt);
        try
        {
            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualHash);
            CryptographicOperations.ZeroMemory(expectedHash);
        }
    }

    private static byte[] DeriveHash(string password, byte[] salt)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                MemorySize = MemorySizeKiB,
                Iterations = Iterations,
                DegreeOfParallelism = DegreeOfParallelism
            };

            return argon2.GetBytes(HashSize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static bool TryParseHash(string? encodedHash, out byte[] salt, out byte[] expectedHash)
    {
        salt = [];
        expectedHash = [];

        if (encodedHash is null || encodedHash.Length > 256)
        {
            return false;
        }

        var parts = encodedHash.Split('$');
        if (parts.Length != 6
            || parts[0].Length != 0
            || parts[1] != "argon2id"
            || parts[2] != "v=19"
            || parts[3] != EncodedParameters)
        {
            return false;
        }

        try
        {
            salt = Convert.FromBase64String(parts[4]);
            expectedHash = Convert.FromBase64String(parts[5]);
        }
        catch (FormatException)
        {
            return false;
        }

        if (salt.Length != SaltSize
            || expectedHash.Length != HashSize
            || Convert.ToBase64String(salt) != parts[4]
            || Convert.ToBase64String(expectedHash) != parts[5])
        {
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(expectedHash);
            salt = [];
            expectedHash = [];
            return false;
        }

        return true;
    }
}