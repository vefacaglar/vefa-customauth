using Vefa.CustomAuth.Core.Managers;

namespace Vefa.CustomAuth.AspNetCore.Services;

/// <summary>
/// Resolves the audiences (resource identifiers) an access token should carry from the granted
/// scopes, and validates RFC 8707 <c>resource</c> parameters against them. Each granted scope may
/// map to an API audience via <see cref="Core.Models.CustomAuthScope.Audience"/>; when none does,
/// token issuance falls back to <c>aud = client_id</c>.
/// </summary>
internal sealed class TokenAudienceResolver
{
    private readonly ICustomAuthScopeManager _scopeManager;

    public TokenAudienceResolver(ICustomAuthScopeManager scopeManager)
    {
        _scopeManager = scopeManager ?? throw new ArgumentNullException(nameof(scopeManager));
    }

    /// <summary>
    /// Returns the distinct audiences mapped by the granted scopes, in first-seen order.
    /// Scope names without a configured scope entity (or without an audience) contribute nothing.
    /// </summary>
    public async Task<IReadOnlyList<string>> ResolveAudiencesAsync(string scope, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            return Array.Empty<string>();
        }

        var scopeNames = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var audiences = new List<string>();
        foreach (var scopeName in scopeNames)
        {
            var configuredScope = await _scopeManager.FindByNameAsync(scopeName, cancellationToken).ConfigureAwait(false);
            if (configuredScope?.Audience is { Length: > 0 } audience
                && !audiences.Contains(audience, StringComparer.Ordinal))
            {
                audiences.Add(audience);
            }
        }

        return audiences;
    }

    /// <summary>
    /// Checks the RFC 8707 §2 format requirements for a <c>resource</c> value: an absolute URI
    /// without a fragment component.
    /// </summary>
    public static bool HasValidResourceFormat(string resource)
        => Uri.TryCreate(resource, UriKind.Absolute, out var uri)
            && string.IsNullOrEmpty(uri.Fragment);

    /// <summary>
    /// Splits a stored space-delimited resource list back into individual values.
    /// </summary>
    public static string[] SplitResources(string? resources)
        => string.IsNullOrWhiteSpace(resources)
            ? Array.Empty<string>()
            : resources.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
