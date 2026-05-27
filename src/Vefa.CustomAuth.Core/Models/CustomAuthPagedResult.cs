using System.Collections.Generic;

namespace Vefa.CustomAuth.Core.Models;

/// <summary>
/// Represents a paginated query result.
/// </summary>
/// <typeparam name="T">The type of the item inside the paged result.</typeparam>
public sealed class CustomAuthPagedResult<T>
{
    /// <summary>
    /// Gets or sets the items on the current page.
    /// </summary>
    public IReadOnlyList<T> Items { get; init; } = [];

    /// <summary>
    /// Gets or sets the total number of records matching the query.
    /// </summary>
    public int TotalCount { get; init; }
}
