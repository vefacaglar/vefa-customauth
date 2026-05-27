namespace Vefa.CustomAuth.Core.Models;

/// <summary>
/// Represents a paginated request model.
/// </summary>
public sealed class CustomAuthPagedRequest
{
    /// <summary>
    /// Gets or sets the 1-based page number. Defaults to 1.
    /// </summary>
    public int Page { get; init; } = 1;

    /// <summary>
    /// Gets or sets the page size. Defaults to 10.
    /// </summary>
    public int PageSize { get; init; } = 10;

    /// <summary>
    /// Gets or sets an optional search query.
    /// </summary>
    public string? Search { get; init; }
}
