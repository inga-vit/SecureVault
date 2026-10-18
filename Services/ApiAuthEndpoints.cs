using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using SecureVault.Pages.Services;

namespace SecureVault.Services;

public sealed record ApiLoginRequest(string? Username, string? Password);

public sealed record ApiRefreshRequest(string? RefreshToken);

public static class ApiAuthEndpoints
{
    public static IEndpointRouteBuilder MapApiAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/auth");

        group.MapPost("/login", async (
            ApiLoginRequest request,
            HttpContext context,
            LoginService loginService,
            ApiTokenService tokenService,
            CancellationToken cancellationToken) =>
        {
            SetNoStoreHeaders(context);
            var user = await loginService.AuthenticateAsync(
                request.Username,
                request.Password,
                cancellationToken);
            if (user is null)
            {
                return Results.Unauthorized();
            }

            var tokens = await tokenService.IssueAsync(user, cancellationToken);
            return Results.Ok(tokens);
        })
        .AllowAnonymous()
        .RequireRateLimiting("api-auth");

        group.MapPost("/refresh", async (
            ApiRefreshRequest request,
            HttpContext context,
            ApiTokenService tokenService,
            CancellationToken cancellationToken) =>
        {
            SetNoStoreHeaders(context);
            var tokens = await tokenService.RotateAsync(request.RefreshToken, cancellationToken);
            return tokens is null ? Results.Unauthorized() : Results.Ok(tokens);
        })
        .AllowAnonymous()
        .RequireRateLimiting("api-refresh");

        group.MapPost("/revoke", async (
            ApiRefreshRequest request,
            HttpContext context,
            ApiTokenService tokenService,
            CancellationToken cancellationToken) =>
        {
            SetNoStoreHeaders(context);
            await tokenService.RevokeAsync(request.RefreshToken, cancellationToken);
            return Results.NoContent();
        })
        .AllowAnonymous()
        .RequireRateLimiting("api-refresh");

        group.MapGet("/me", (ClaimsPrincipal user) =>
                Results.Ok(new
                {
                    Subject = user.FindFirstValue("sub"),
                    Username = user.FindFirstValue("name"),
                    Role = user.FindFirstValue("role")
                }))
            .RequireAuthorization(new AuthorizeAttribute
            {
                AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme
            });

        return endpoints;
    }

    private static void SetNoStoreHeaders(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
    }
}
