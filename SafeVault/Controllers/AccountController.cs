using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Services;
namespace SafeVault.Controllers;
public sealed class AccountController : Controller
{
    private readonly AccountService _accounts;
    private readonly ILogger<AccountController> _logger;
    public AccountController(AccountService accounts, ILogger<AccountController> logger) { _accounts = accounts; _logger = logger; }
    [HttpGet] public IActionResult Register() => View(new RegisterForm());
    [HttpPost, ValidateAntiForgeryToken]
    public IActionResult Register(RegisterForm form)
    {
        if (!ModelState.IsValid) return View(form);
        if (!_accounts.Register(form)) { ModelState.AddModelError("", "Registration failed. Check the fields or choose a different username/email."); return View(form); }
        return RedirectToAction(nameof(Login));
    }
    [HttpGet] public IActionResult Login() => View(new LoginForm());
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginForm form)
    {
        if (!ModelState.IsValid) return View(form);
        var user = _accounts.Authenticate(form.Username, form.Password);
        if (user is null) { _logger.LogWarning("Failed login attempt"); ModelState.AddModelError("", "Invalid credentials."); return View(form); }
        var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()), new Claim(ClaimTypes.Name, user.Username), new Claim(ClaimTypes.Role, user.Role) }, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
        _logger.LogInformation("Successful login for user ID {Id}", user.Id);
        return RedirectToAction("Index", "Home");
    }
    [Authorize, HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout() { await HttpContext.SignOutAsync(); return RedirectToAction("Index", "Home"); }
    public IActionResult Denied() => Content("Access denied.");
}
