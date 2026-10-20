# SafeVault — Full-Stack Application Security Capstone

An ASP.NET Core MVC + SQLite demonstration for the three SafeVault activities.

## Requirements
- .NET 10 SDK
- VS Code / GitHub Copilot (for the assignment's Copilot-assisted review requirement)

## Run locally
```bash
dotnet restore SafeVault.sln
dotnet build SafeVault.sln
dotnet test SafeVault.sln
dotnet run --project SafeVault --launch-profile https
```
Open the HTTPS URL printed by `dotnet run`. If a development HTTPS certificate is not trusted, run `dotnet dev-certs https --trust` first.

## Included features
- Server-side username/email validation; safe Razor HTML encoding.
- SQLite prepared/parameterized commands (no concatenated user SQL).
- PasswordHasher<TUser> password hashing and verification.
- Secure cookie sign-in and logout; antiforgery validation for POST forms.
- `AdminOnly` role authorization policy on `/Admin`, with the current database role checked when an authentication cookie is validated.
- NUnit tests for SQL injection, XSS-related validation/encoding, password hashing and login, and role authorization/revocation.

## Admin setup
Self-registration creates **User** accounts only. No web endpoint can grant Admin privileges. For a **local demo**, register a user, stop the app, then promote that user using a SQLite tool:
```sql
UPDATE Users SET Role = 'Admin' WHERE Username = 'your_registered_username';
```
Restart the app and sign in again. Never expose a public admin-promotion endpoint. The database file is created in the application output directory by default.

## Security limitations
This is a **course demonstration, not a production-ready financial vault**. The current-role check reads SQLite during cookie validation; production deployments should evaluate the performance and availability implications, and use an appropriate revocation strategy such as a security stamp or versioned session. Production deployment additionally needs login rate limiting/lockouts, email verification, MFA, audited account provisioning, data protection key persistence, secure database backups, secret management, centralized monitoring, and integration tests for HTTP authorization/antiforgery flows. Use HTTPS. Never upload real user credentials or the `.db` file.

## Copilot evidence
The code is a starter implementation provided for review. **Do not claim Copilot generated it unless you actually use Copilot**. Open the solution in VS Code, ask Copilot to review and improve it using `docs/COPILOT_PROMPTS.md`, apply and test suggestions, and document the actual prompts, changes, and test results in your submission.

## Submission
Publish the repository publicly (without database/secrets), paste its GitHub URL into Coursera, and include a factual summary of security fixes and how you used Copilot.
