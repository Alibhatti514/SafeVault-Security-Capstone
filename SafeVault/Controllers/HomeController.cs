using Microsoft.AspNetCore.Mvc;
namespace SafeVault.Controllers;
public sealed class HomeController : Controller
{
    public IActionResult Index() => View();
    public IActionResult Error() => Content("An unexpected error occurred.");
}
