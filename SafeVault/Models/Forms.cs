using System.ComponentModel.DataAnnotations;
namespace SafeVault.Models;
public sealed class RegisterForm
{
    [Required, RegularExpression(@"^[A-Za-z0-9_]{3,30}$", ErrorMessage = "Username must be 3–30 letters, digits or underscores.")]
    public string Username { get; set; } = "";
    [Required, EmailAddress, StringLength(100)] public string Email { get; set; } = "";
    [Required, MinLength(12), MaxLength(128), DataType(DataType.Password)] public string Password { get; set; } = "";
}
public sealed class LoginForm
{
    [Required] public string Username { get; set; } = "";
    [Required, DataType(DataType.Password)] public string Password { get; set; } = "";
}
