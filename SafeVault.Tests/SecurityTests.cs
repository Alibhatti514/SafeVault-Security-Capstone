using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.Controllers;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;
namespace SafeVault.Tests;
[TestFixture]
public sealed class SecurityTests
{
    private string _path = null!;
    private UserRepository _repo = null!;
    private AccountService _accounts = null!;
    [SetUp] public void Setup()
    {
        _path = Path.Combine(Path.GetTempPath(), "safevault-test-" + Guid.NewGuid() + ".db");
        _repo = new UserRepository(_path); _repo.Initialize();
        _accounts = new AccountService(_repo, new PasswordHasher<UserRecord>());
    }
    [TearDown] public void Cleanup() { SqliteCleanup(); }
    private void SqliteCleanup() { if (File.Exists(_path)) File.Delete(_path); }
    [TestCase("admin' OR 1=1 --")]
    [TestCase("' UNION SELECT * FROM Users --")]
    [TestCase("'; DROP TABLE Users; --")]
    public void ParameterizedLookup_DoesNotExecuteInjectedSql(string attack)
    {
        Assert.That(_repo.Find(attack), Is.Null);
        Assert.That(_repo.Add("real_user", "real@example.com", "test-hash"), Is.True);
        Assert.That(_repo.Find("real_user"), Is.Not.Null);
    }
    [TestCase("<script>alert(1)</script>")]
    [TestCase("<img src=x onerror=alert(1)>")]
    public void UsernameValidation_RejectsHtml(string attack) => Assert.That(InputRules.ValidUsername(attack), Is.False);
    [Test] public void HtmlEncoding_EscapesUntrustedMarkup()
    {
        var encoded = WebUtility.HtmlEncode("<script>alert('x')</script>");
        Assert.That(encoded, Does.Not.Contain("<script>"));
        Assert.That(encoded, Does.Contain("&lt;script&gt;"));
    }
    [Test] public void Registration_StoresHash_NotPlaintext()
    {
        Assert.That(_accounts.Register(new RegisterForm { Username="sample_user", Email="sample@example.com", Password="VeryStrongPass123!" }), Is.True);
        var user = _repo.Find("sample_user")!;
        Assert.That(user.PasswordHash, Is.Not.EqualTo("VeryStrongPass123!"));
        Assert.That(_accounts.Authenticate("sample_user", "VeryStrongPass123!"), Is.Not.Null);
    }
    [Test] public void IncorrectPassword_IsRejected()
    {
        _accounts.Register(new RegisterForm { Username="sample_user", Email="sample@example.com", Password="VeryStrongPass123!" });
        Assert.That(_accounts.Authenticate("sample_user", "wrong-password"), Is.Null);
    }
    [Test] public void UnknownUser_IsRejected() => Assert.That(_accounts.Authenticate("missing", "anything"), Is.Null);
    [Test] public void NewRegistrations_CannotChooseAdminRole()
    {
        _accounts.Register(new RegisterForm { Username="sample_user", Email="sample@example.com", Password="VeryStrongPass123!" });
        Assert.That(_repo.Find("sample_user")!.Role, Is.EqualTo("User"));
    }
    [Test] public void AdminPolicy_RequiresAdminRole()
    {
        var policy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder().RequireRole("Admin").Build();
        var requirement = policy.Requirements.OfType<Microsoft.AspNetCore.Authorization.Infrastructure.RolesAuthorizationRequirement>().Single();
        Assert.That(requirement.AllowedRoles, Does.Contain("Admin"));
        Assert.That(requirement.AllowedRoles, Does.Not.Contain("User"));
    }
    [Test] public void AdminController_RequiresAdminOnlyPolicy()
    {
        var attribute = typeof(AdminController).GetCustomAttributes(typeof(AuthorizeAttribute), inherit: true)
            .Cast<AuthorizeAttribute>()
            .Single();

        Assert.That(attribute.Policy, Is.EqualTo("AdminOnly"));
    }
    [Test] public async Task CookieIsRejectedWhenDatabaseRoleChanges()
    {
        Assert.That(_accounts.Register(new RegisterForm { Username = "sample_user", Email = "sample@example.com", Password = "VeryStrongPass123!" }), Is.True);
        var user = _repo.Find("sample_user")!;
        Assert.That(_repo.PromoteToAdmin(user.Username), Is.True);
        user = _repo.FindById(user.Id)!;

        using (var db = new SqliteConnection($"Data Source={_path}"))
        {
            db.Open();
            using var command = db.CreateCommand();
            command.CommandText = "UPDATE Users SET Role = 'User' WHERE Id = $id";
            command.Parameters.AddWithValue("$id", user.Id);
            Assert.That(command.ExecuteNonQuery(), Is.EqualTo(1));
        }

        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, "Admin")
            },
            CookieAuthenticationDefaults.AuthenticationScheme));
        var scheme = new AuthenticationScheme(
            CookieAuthenticationDefaults.AuthenticationScheme,
            CookieAuthenticationDefaults.AuthenticationScheme,
            typeof(CookieAuthenticationHandler));
        var httpContext = new DefaultHttpContext();
        var authenticationService = new RecordingAuthenticationService();
        httpContext.RequestServices = new ServiceCollection()
            .AddSingleton<IAuthenticationService>(authenticationService)
            .BuildServiceProvider();
        var context = new CookieValidatePrincipalContext(
            httpContext,
            scheme,
            new CookieAuthenticationOptions(),
            new AuthenticationTicket(principal, scheme.Name));

        await new RoleRevalidationCookieEvents(_repo).ValidatePrincipal(context);

        Assert.That(context.Principal, Is.Null);
        Assert.That(authenticationService.SignedOutScheme, Is.EqualTo(scheme.Name));
    }

    private sealed class RecordingAuthenticationService : IAuthenticationService
    {
        public string? SignedOutScheme { get; private set; }

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) =>
            Task.FromResult(AuthenticateResult.NoResult());

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
            Task.CompletedTask;

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
            Task.CompletedTask;

        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) =>
            Task.CompletedTask;

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            SignedOutScheme = scheme;
            return Task.CompletedTask;
        }
    }
    [Test] public void SQLInjectionInput_IsRejectedAtRegistration()
    {
        Assert.That(_accounts.Register(new RegisterForm { Username="admin' OR 1=1 --", Email="x@example.com", Password="VeryStrongPass123!" }), Is.False);
    }
}
