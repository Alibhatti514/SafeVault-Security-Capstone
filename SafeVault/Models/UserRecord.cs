namespace SafeVault.Models;
public sealed record UserRecord(long Id, string Username, string Email, string PasswordHash, string Role);
