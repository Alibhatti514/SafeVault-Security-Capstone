using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
namespace SafeVault.Controllers;
[Authorize(Policy = "AdminOnly")]
public sealed class AdminController : Controller
{
    public IActionResult Index() => View();
}
