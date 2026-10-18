using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SecureVault.Pages;

[Authorize]
public sealed class UserDashboardModel : PageModel
{
    public string Username => User.Identity?.Name ?? string.Empty;
}
