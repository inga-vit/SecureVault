using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureVault.Data;
using SecureVault.Models;

namespace SecureVault.Pages;

[Authorize(Roles = nameof(UserRole.Admin))]
public sealed class AdminDashboardModel(SecureVaultDbContext dbContext) : PageModel
{
    public int UserCount { get; private set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        UserCount = await dbContext.Users.CountAsync(cancellationToken);
    }
}
