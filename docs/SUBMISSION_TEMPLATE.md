# Coursera submission (fill in after verification)

**Project title:** SafeVault — Secure ASP.NET Core Application with Authentication, RBAC and Security Tests

**GitHub URL:** [PASTE YOUR ACTUAL PUBLIC REPOSITORY URL]

**Security summary:**
SafeVault uses parameterized SQLite commands, server-side input validation, and Razor's default HTML encoding for user-provided values. Authentication uses ASP.NET Core `PasswordHasher<TUser>` and secure cookie settings; `/Admin` requires the `AdminOnly` role policy. A security review found that role claims could remain stale in an active cookie after a database role change. I added cookie-principal role revalidation against the current database record and reject/sign out cookies whose account or role no longer matches. I also added regression tests for role revocation and the Admin controller's policy metadata, and removed stray text that prevented the project file from building. I ran `dotnet test SafeVault.Tests/SafeVault.Tests.csproj --no-restore`: **Passed — 14 tests, 0 failures**.

**Copilot contribution record:**
- **Date:** 2026-10-21
- **Prompt used:** "Review my SafeVault ASP.NET Core application for SQL injection, XSS, authentication, and authorization vulnerabilities. Check whether database queries are parameterized, passwords are securely hashed, and role-based access controls are correctly implemented. Suggest improvements following OWASP recommendations and help me add security tests. Review its recommendations and apply appropriate changes. Record the changes you actually make so your submission accurately describes Copilot’s contribution."
- **Finding applied:** Revalidate the current user role during cookie authentication so role revocation takes effect for existing sessions.
- **Changes made:** Added a parameterized lookup by user ID; added cookie validation that rejects and signs out deleted-user or stale-role sessions; added tests for role revocation and the Admin-only controller policy; corrected the malformed project-file closing line.
- **Tests run:** `dotnet test SafeVault.Tests/SafeVault.Tests.csproj --no-restore`
- **Actual result:** Passed — 14 tests, 0 failures.
- **Remaining production risks:** Login rate limiting/lockouts, MFA, email verification, durable Data Protection keys, audited Admin provisioning, secure backups, secrets management, centralized monitoring, and full HTTP-level authorization/antiforgery integration tests remain out of scope. Per-request role lookup also adds a database read and depends on database availability.

**Do not submit placeholders or claim tests/Copilot usage you have not performed.**
