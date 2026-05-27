using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Managers;

/// <summary>
/// Defines business operations for managing OAuth2/OIDC clients.
/// </summary>
public interface ICustomAuthClientManager
{
    /// <summary>
    /// Finds a client by its unique client ID.
    /// </summary>
    /// <param name="clientId">The unique client ID.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The client if found, otherwise null.</returns>
    Task<CustomAuthClient?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a paginated list of clients.
    /// </summary>
    /// <param name="request">The paginated request parameters.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A paginated result containing clients.</returns>
    Task<CustomAuthPagedResult<CustomAuthClient>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates and registers a new client.
    /// </summary>
    /// <param name="client">The client to register.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task CreateAsync(CustomAuthClient client, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates and updates an existing client configuration.
    /// </summary>
    /// <param name="client">The updated client model.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task UpdateAsync(CustomAuthClient client, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a client by its unique client ID.
    /// </summary>
    /// <param name="clientId">The client ID to delete.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task DeleteAsync(string clientId, CancellationToken cancellationToken = default);
}
