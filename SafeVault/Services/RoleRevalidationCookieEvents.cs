using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SafeVault.Data;

namespace SafeVault.Services;

public sealed class RoleRevalidationCookieEvents : CookieAuthenticationEvents
{
    private readonly UserRepository _users;

    public RoleRevalidationCookieEvents(UserRepository users) => _users = users;

    public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
    {
        var userId = context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
        var role = context.Principal?.FindFirstValue(ClaimTypes.Role);
        var user = long.TryParse(userId, out var id) ? _users.FindById(id) : null;

        if (user is not null && string.Equals(user.Role, role, StringComparison.Ordinal))
        {
            return;
        }

        context.RejectPrincipal();
        await context.HttpContext.SignOutAsync(context.Scheme.Name);
    }
}
