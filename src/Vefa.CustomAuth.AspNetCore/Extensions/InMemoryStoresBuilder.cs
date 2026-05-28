using Vefa.CustomAuth.AspNetCore.Stores.InMemory;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.AspNetCore.Extensions;

/// <summary>
/// Builder for configuring seed data for in-memory stores.
/// </summary>
public sealed class InMemoryStoresBuilder
{
    /// <summary>
    /// Gets the list of clients to seed.
    /// </summary>
    public List<CustomAuthClient> Clients { get; } = new();

    /// <summary>
    /// Gets the list of users to seed.
    /// </summary>
    public List<InMemoryUserStore.SeedUser> Users { get; } = new();
}
