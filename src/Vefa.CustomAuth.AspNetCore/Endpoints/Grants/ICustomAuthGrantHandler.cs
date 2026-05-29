using Microsoft.AspNetCore.Http;

namespace Vefa.CustomAuth.AspNetCore.Endpoints.Grants;

/// <summary>
/// Handles a single OAuth2 token-endpoint grant type. The token endpoint dispatches each request
/// to the handler whose <see cref="GrantType"/> matches the request's <c>grant_type</c>.
/// Register additional implementations in the service collection to support custom grants;
/// a registration whose <see cref="GrantType"/> matches a built-in grant overrides it.
/// </summary>
public interface ICustomAuthGrantHandler
{
    /// <summary>
    /// Gets the <c>grant_type</c> value this handler serves (for example, <c>client_credentials</c>).
    /// </summary>
    string GrantType { get; }

    /// <summary>
    /// Processes a token request for <see cref="GrantType"/> and produces the token endpoint response.
    /// </summary>
    /// <param name="form">The parsed <c>application/x-www-form-urlencoded</c> request body.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The result to return to the caller (a token response or an OAuth error).</returns>
    Task<IResult> HandleAsync(IFormCollection form, CancellationToken cancellationToken = default);
}
