using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureVault.Pages.Services;

namespace SecureVault.Pages;

public sealed class IndexModel(UserService userService) : PageModel
{
    [BindProperty]
    public string? Username { get; set; }

    [BindProperty]
    public string? Email { get; set; }

    [BindProperty]
    public string? Password { get; set; }

    public string? StatusMessage { get; private set; }

    public async Task OnPostAsync(CancellationToken cancellationToken)
    {
        var result = await userService.RegisterAsync(Username, Email, Password, cancellationToken);

        switch (result)
        {
            case RegistrationResult.Registered:
                StatusMessage = "Registration successful.";
                Username = null;
                Email = null;
                Password = null;
                break;
            case RegistrationResult.InvalidUsername:
                ModelState.AddModelError(nameof(Username), "Use 3 to 32 letters or digits; periods, underscores, and hyphens are also allowed.");
                break;
            case RegistrationResult.InvalidEmail:
                ModelState.AddModelError(nameof(Email), "Enter a valid email address.");
                break;
            case RegistrationResult.UsernameAlreadyExists:
                ModelState.AddModelError(nameof(Username), "That username is already registered.");
                break;
            case RegistrationResult.EmailAlreadyExists:
                ModelState.AddModelError(nameof(Email), "That email address is already registered.");
                break;
        }
    }
}
