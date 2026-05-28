using System;
using System.Collections.Generic;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Services;

/// <summary>
/// Contains the context for a profile data request.
/// </summary>
public sealed class CustomAuthProfileContext
{
    /// <summary>
    /// Gets the subject identifier (user ID).
    /// </summary>
    public string UserId { get; }

    /// <summary>
    /// Gets the client making the request.
    /// </summary>
    public CustomAuthClient Client { get; }

    /// <summary>
    /// Gets the requested scopes.
    /// </summary>
    public string Scope { get; }

    /// <summary>
    /// Gets the dictionary of claims that will be added to the issued tokens and userinfo endpoint.
    /// </summary>
    public Dictionary<string, object> Claims { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Initializes a new instance of the <see cref="CustomAuthProfileContext"/> class.
    /// </summary>
    /// <param name="userId">The subject identifier.</param>
    /// <param name="client">The client.</param>
    /// <param name="scope">The requested scopes.</param>
    public CustomAuthProfileContext(string userId, CustomAuthClient client, string scope)
    {
        UserId = userId ?? throw new ArgumentNullException(nameof(userId));
        Client = client ?? throw new ArgumentNullException(nameof(client));
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
    }
}
