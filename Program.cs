using System.Threading.RateLimiting;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SecureVault.Data;
using SecureVault.Models;
using SecureVault.Pages.Services;
using SecureVault.Services;

var builder = WebApplication.CreateBuilder(args);

#region JWT 
    var signingKey = builder.Configuration["Jwt:SigningKey"];
if (string.IsNullOrWhiteSpace(signingKey) || Encoding.UTF8.GetByteCount(signingKey) < 32)
{
    throw new InvalidOperationException(
        "Configure Jwt:SigningKey with a cryptographically random secret of at least 32 bytes.");
}

var issuer = builder.Configuration["Jwt:Issuer"];
if (string.IsNullOrWhiteSpace(issuer)) throw new InvalidOperationException("Jwt:Issuer not found");

var audience = builder.Configuration["Jwt:Audience"];
if (string.IsNullOrWhiteSpace(audience)) throw new InvalidOperationException("Jwt:Audience not found");

var jwtOptions = new JwtOptions
{
    Issuer = issuer,
    Audience = audience,
    SigningKey = Encoding.UTF8.GetBytes(signingKey)
};
#endregion JWT


// Add services to the container.
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AddPageApplicationModelConvention("/Login", model =>
        model.EndpointMetadata.Add(new EnableRateLimitingAttribute("login")));
});
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "__Host-SecureVault.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.Path = "/";
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = false;
        options.LoginPath = "/Login";
    })
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtOptions.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(jwtOptions.SigningKey),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            NameClaimType = "name",
            RoleClaimType = "role"
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("login", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 5,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(1)
            }));
    options.AddPolicy("api-auth", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 5,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(1)
            }));
    options.AddPolicy("api-refresh", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 20,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(1)
            }));
});

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("The DefaultConnection SQL Server connection string is not configured.");

builder.Services.AddDbContext<SecureVaultDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<LoginService>();
builder.Services.AddScoped<ApiTokenService>();
builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);
builder.Services.AddSingleton<Microsoft.Extensions.Options.IOptions<JwtOptions>>(
    Microsoft.Extensions.Options.Options.Create(jwtOptions));

var app = builder.Build();

await using (var scope = app.Services.CreateAsyncScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<SecureVaultDbContext>();
    await dbContext.Database.EnsureCreatedAsync();
    await dbContext.Database.ExecuteSqlRawAsync(
        """
        IF OBJECT_ID(N'dbo.Users', N'U') IS NULL
        BEGIN
            CREATE TABLE dbo.Users
            (
                Id           int IDENTITY(1,1) NOT NULL,
                Username     nvarchar(32)      NOT NULL,
                Email        nvarchar(254)     NOT NULL,
                PasswordHash nvarchar(256)     NOT NULL,
                Role         nvarchar(16)      NOT NULL
                    CONSTRAINT DF_Users_Role DEFAULT N'User',

                CONSTRAINT PK_Users PRIMARY KEY (Id),
                CONSTRAINT CK_Users_Role CHECK (Role IN (N'User', N'Admin'))
            );

            CREATE UNIQUE INDEX UX_Users_Username ON dbo.Users (Username);
            CREATE UNIQUE INDEX UX_Users_Email ON dbo.Users (Email);
        END;
        """);
    await dbContext.Database.ExecuteSqlRawAsync(
        """
        IF OBJECT_ID(N'dbo.RefreshTokens', N'U') IS NULL
        BEGIN
            CREATE TABLE [dbo].[RefreshTokens]
            (
                [TokenHash] nvarchar(64) NOT NULL CONSTRAINT [PK_RefreshTokens] PRIMARY KEY,
                [UserId] int NOT NULL,
                [FamilyId] uniqueidentifier NOT NULL,
                [CreatedAt] datetimeoffset NOT NULL,
                [ExpiresAt] datetimeoffset NOT NULL,
                [FamilyExpiresAt] datetimeoffset NOT NULL,
                [RevokedAt] datetimeoffset NULL,
                [ReplacedByTokenHash] nvarchar(64) NULL,
                [ConcurrencyStamp] uniqueidentifier NOT NULL,
                CONSTRAINT [FK_RefreshTokens_Users_UserId]
                    FOREIGN KEY ([UserId]) REFERENCES [dbo].[Users] ([Id]) ON DELETE CASCADE
            );
            CREATE INDEX [IX_RefreshTokens_FamilyId_RevokedAt]
                ON [dbo].[RefreshTokens] ([FamilyId], [RevokedAt]);
        END
        """);
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();
app.MapApiAuthEndpoints();

app.Run();
