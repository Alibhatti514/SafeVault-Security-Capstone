using System.Text.RegularExpressions;
namespace SafeVault.Services;
public static class InputRules
{
    public static bool ValidUsername(string? value) => value is not null && Regex.IsMatch(value, @"\A[A-Za-z0-9_]{3,30}\z", RegexOptions.CultureInvariant);
    public static bool ValidEmail(string? value) => value is not null && value.Length <= 100 && new System.ComponentModel.DataAnnotations.EmailAddressAttribute().IsValid(value);
}
