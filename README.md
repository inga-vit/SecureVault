# SecureVault

SecureVault is a learning application developed for the [Security and Authentication course](https://www.coursera.org/learn/security-and-authentication?specialization=microsoft-full-stack-developer) in the Microsoft Full-Stack Developer Specialization.

The project uses the SafeVault scenario: build a web application that protects user credentials and sensitive information through secure coding practices. The current implementation focuses on account registration, authentication, authorization, and security testing.

## Learning objectives

- Validate user input and test responses to XSS- and SQL-injection-shaped input.
- Use Entity Framework Core queries and database constraints for safer persistence.
- Authenticate users and authorize access according to their roles.
- Use GitHub Copilot to assist with secure implementation, test generation, and debugging.

## Features

- Razor Pages registration and browser login.
- Argon2id password hashing with a cryptographically generated salt. The encoded password hash contains the salt and algorithm parameters.
- Generic login failures, dummy-hash verification for unknown users, and rate limiting.
- Cookie authentication for browser sessions, with `HttpOnly`, `Secure`, and `SameSite=Lax` cookie settings.
- User and Admin roles. New registrations receive the User role. Admins can access both dashboards; regular users cannot access the admin dashboard.
- An API token flow for non-browser clients:
  - Five-minute JWT bearer access tokens.
  - Random refresh tokens, persisted as SHA-256 hashes.
  - Refresh-token rotation, family revocation, and reuse detection.
- SQL Server persistence for users and refresh tokens.
- Unit tests using xUnit and EF Core's in-memory provider.

## Requirements

- .NET 10 SDK.
- SQL Server or SQL Server LocalDB.
- A JWT signing secret supplied through secure configuration.

## Configuration

The connection string is read from `ConnectionStrings:DefaultConnection`. Set this value in `appsettings.json` to the SQL Server instance and database appropriate to your environment.

The application requires these JWT settings at startup:

| Setting          | Description                            |
| ---------------- | -------------------------------------- |
| `Jwt:SigningKey` | Cryptographically random secret with at least 32 bytes. Do not store it in source control. |
| `Jwt:Issuer`     | Expected issuer for JWTs.              |
| `Jwt:Audience`   | Expected audience for JWTs.            |

Supply settings through a secret manager or environment variables. For a local PowerShell session:

```powershell
$env:Jwt__SigningKey = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$env:Jwt__Issuer = "SecureVault"
$env:Jwt__Audience = "SecureVault.Api"
```

Keep the generated signing key stable across application restarts, and share it securely across application instances. The example above generates a temporary key for a local run; changing it invalidates tokens signed with the previous key.

## Run the application

From the repository root:

```powershell
dotnet restore
dotnet run --project SecureVault.csproj
```

Open the local HTTPS URL printed by `dotnet run`. On startup, the app creates the `Users` and `RefreshTokens` tables if they do not already exist. The database account needs permission to create tables and indexes.

Register through the home page, then use the **Log in** link. New accounts are assigned the User role and redirected to the user dashboard after login.

### Granting an administrator role

There is no public role-assignment endpoint. A trusted database operator may promote an account explicitly:

```sql
UPDATE dbo.Users
SET Role = N'Admin'
WHERE Username = N'<trusted-admin-username>';
```

The account must log in again to receive a cookie or access token containing the updated role claim. Restrict direct database access and treat role changes as privileged administrative operations.

## API authentication

The following endpoints are available to API clients:

| Method and route          | Purpose                                               |
| ------------------------- | ----------------------------------------------------- |
| `POST /api/auth/login`    | Exchange a username and password for an access token and refresh token.  |
| `POST /api/auth/refresh`  | Rotate a refresh token and obtain a new token pair.   |
| `POST /api/auth/revoke`   | Revoke the refresh-token family.                      |
| `GET /api/auth/me`        | Example endpoint requiring a JWT bearer access token. |

Example login request:

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "example-user",
  "password": "replace-with-your-password"
}
```

Send the access token to protected endpoints using:

```http
Authorization: Bearer <access-token>
```

Refresh and revoke requests use a JSON body such as:

```json
{
  "refreshToken": "<refresh-token>"
}
```

Treat both tokens as secrets. Do not put them in URLs, logs, or browser local storage. Use HTTPS for all API traffic. A revoked refresh token does not immediately invalidate existing access tokens; they can remain valid for up to five minutes.

## Run tests

```powershell
dotnet test tests\SecureVault.Tests\SecureVault.Tests.csproj
```

Tests cover password hashing and verification, registration input handling, login behavior, role authorization metadata, and API refresh-token issuance, rotation, revocation, and reuse detection. The test database is in-memory; these tests do not replace SQL Server integration tests or end-to-end security testing.

## Security notes and limitations

- Razor Pages output is encoded by default by Razor. Continue to avoid rendering untrusted data as raw HTML.
- Input validation is defense in depth; it does not replace parameterized database access or context-appropriate output encoding.
- The login and API rate limits are in-process and keyed by client IP. Production multi-instance deployments should use a shared rate-limiting mechanism and correctly configured trusted-proxy handling.
- JWT signing secrets must be stored and rotated securely. Restrict access to production secrets and database credentials.
- Configure database backups, access controls, monitoring, and schema migrations appropriate to the deployment. The current startup table creation is intended for this learning application, not a substitute for a production migration strategy.
- This application is an educational example, not a security certification or substitute for a threat model and independent penetration testing.
