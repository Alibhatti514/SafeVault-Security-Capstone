using Microsoft.AspNetCore.Identity;
using SafeVault.Data;
using SafeVault.Models;
namespace SafeVault.Services;
public sealed class AccountService
{
    private readonly UserRepository _users;
    private readonly PasswordHasher<UserRecord> _hasher;
    public AccountService(UserRepository users, PasswordHasher<UserRecord> hasher) { _users = users; _hasher = hasher; }
    public bool Register(RegisterForm form)
    {
        if (!InputRules.ValidUsername(form.Username) || !InputRules.ValidEmail(form.Email) || form.Password is null || form.Password.Length < 12 || form.Password.Length > 128) return false;
        var placeholder = new UserRecord(0, form.Username, form.Email, "", "User");
        var hash = _hasher.HashPassword(placeholder, form.Password);
        return _users.Add(form.Username, form.Email, hash);
    }
    public UserRecord? Authenticate(string username, string password)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password)) return null;
        var user = _users.Find(username);
        if (user is null) return null;
        var result = _hasher.VerifyHashedPassword(user, user.PasswordHash, password);
        return result == PasswordVerificationResult.Failed ? null : user;
    }
}
