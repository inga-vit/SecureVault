namespace SecureVault.Helpers;

public static class ValidationHelper
{
    /// <summary>
    /// Checks that input contains only Unicode letters, digits, and explicitly allowed characters.
    /// This validation does not replace context-appropriate output encoding or parameterized SQL.
    /// </summary>
    /// <param name="input">The value to validate.</param>
    /// <param name="allowedCharacters">Additional characters permitted in the value.</param>
    /// <returns><see langword="true"/> if the non-empty value contains only permitted characters.</returns>
    public static bool IsValidInput(string? input, string allowedCharacters = "")
    {
        if (string.IsNullOrEmpty(input))
        {
            return false;
        }

        if (!input.All(c => 
        char.IsLetterOrDigit(c) || allowedCharacters.Contains(c)))
        {
            return false;
        }

        return true;
    }
}
