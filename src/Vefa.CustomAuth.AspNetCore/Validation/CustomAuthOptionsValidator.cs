using Microsoft.Extensions.Options;
using Vefa.CustomAuth.Core.Options;

namespace Vefa.CustomAuth.AspNetCore.Validation;

/// <summary>
/// Validates <see cref="CustomAuthOptions"/> at startup to ensure all configuration values are valid.
/// </summary>
public sealed class CustomAuthOptionsValidator : IValidateOptions<CustomAuthOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, CustomAuthOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            failures.Add($"{nameof(options.Issuer)} must be specified.");
        }
        else if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuerUri))
        {
            failures.Add($"{nameof(options.Issuer)} must be a valid absolute URI (e.g., 'https://auth.example.com').");
        }
        else
        {
            if (options.RequireHttps && !string.Equals(issuerUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                failures.Add($"{nameof(options.Issuer)} must use HTTPS when {nameof(options.RequireHttps)} is true.");
            }
        }

        if (options.AuthorizationCodeLifetime <= TimeSpan.Zero)
        {
            failures.Add($"{nameof(options.AuthorizationCodeLifetime)} must be greater than zero.");
        }

        if (options.AccessTokenLifetime <= TimeSpan.Zero)
        {
            failures.Add($"{nameof(options.AccessTokenLifetime)} must be greater than zero.");
        }

        if (options.IdTokenLifetime <= TimeSpan.Zero)
        {
            failures.Add($"{nameof(options.IdTokenLifetime)} must be greater than zero.");
        }

        if (options.RefreshTokenLifetime <= TimeSpan.Zero)
        {
            failures.Add($"{nameof(options.RefreshTokenLifetime)} must be greater than zero.");
        }

        if (options.RefreshTokenAbsoluteLifetime <= TimeSpan.Zero)
        {
            failures.Add($"{nameof(options.RefreshTokenAbsoluteLifetime)} must be greater than zero.");
        }

        if (options.RefreshTokenAbsoluteLifetime < options.RefreshTokenLifetime)
        {
            failures.Add($"{nameof(options.RefreshTokenAbsoluteLifetime)} must be greater than or equal to {nameof(options.RefreshTokenLifetime)}.");
        }

        if (string.IsNullOrWhiteSpace(options.LoginPath))
        {
            failures.Add($"{nameof(options.LoginPath)} must not be empty.");
        }
        else if (!options.LoginPath.StartsWith('/'))
        {
            failures.Add($"{nameof(options.LoginPath)} must start with '/'.");
        }

        if (string.IsNullOrWhiteSpace(options.CookieName))
        {
            failures.Add($"{nameof(options.CookieName)} must not be empty.");
        }

        if (failures.Count > 0)
        {
            return ValidateOptionsResult.Fail(failures);
        }

        return ValidateOptionsResult.Success;
    }
}
