using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Managers;

/// <summary>
/// Defines business operations for managing OAuth2/OIDC scopes.
/// </summary>
public interface ICustomAuthScopeManager
{
    /// <summary>
    /// Finds a scope by its unique name.
    /// </summary>
    /// <param name="name">The unique scope name.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The scope if found, otherwise null.</returns>
    Task<CustomAuthScope?> FindByNameAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all configured scopes.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A read-only list of all scopes.</returns>
    Task<IReadOnlyList<CustomAuthScope>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates and persists a new scope.
    /// </summary>
    /// <param name="scope">The scope to create.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task CreateAsync(CustomAuthScope scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates and updates an existing scope configuration.
    /// </summary>
    /// <param name="scope">The scope to update.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task UpdateAsync(CustomAuthScope scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a scope by its unique name.
    /// </summary>
    /// <param name="name">The name of the scope to delete.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task DeleteAsync(string name, CancellationToken cancellationToken = default);
}
