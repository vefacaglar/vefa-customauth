using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.EntityFrameworkCore.Stores;

/// <summary>
/// EF Core implementation of <see cref="ICustomAuthClientStore"/>.
/// </summary>
/// <typeparam name="TContext">The DbContext type.</typeparam>
public sealed class EfCustomAuthClientStore<TContext> : ICustomAuthClientStore
    where TContext : DbContext
{
    private readonly TContext _context;

    /// <summary>
    /// Creates a new client store.
    /// </summary>
    /// <param name="context">The DbContext instance.</param>
    public EfCustomAuthClientStore(TContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc />
    public async Task<CustomAuthClient?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);

        var client = await QueryClients()
            .AsNoTracking()
            .SingleOrDefaultAsync(client => client.ClientId == clientId, cancellationToken)
            .ConfigureAwait(false);

        PopulateClientLists(client);
        return client;
    }

    /// <inheritdoc />
    public async Task<CustomAuthPagedResult<CustomAuthClient>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var query = QueryClients()
            .AsNoTracking()
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(request.Search))
        {
            var search = request.Search;
            query = query.Where(c => c.ClientId.Contains(search) || (c.DisplayName != null && c.DisplayName.Contains(search)));
        }

        query = query.OrderBy(c => c.ClientId);

        var totalCount = await query.CountAsync(cancellationToken).ConfigureAwait(false);

        var page = request.Page > 0 ? request.Page : 1;
        var pageSize = request.PageSize > 0 ? request.PageSize : 10;

        var items = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        foreach (var item in items)
        {
            PopulateClientLists(item);
        }

        return new CustomAuthPagedResult<CustomAuthClient>
        {
            Items = items,
            TotalCount = totalCount
        };
    }

    /// <inheritdoc />
    public async Task StoreAsync(CustomAuthClient client, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrEmpty(client.ClientId);

        var existing = await QueryClients()
            .SingleOrDefaultAsync(c => c.ClientId == client.ClientId, cancellationToken)
            .ConfigureAwait(false);

        SyncClientRelations(client);

        if (existing is not null)
        {
            _context.Entry(existing).CurrentValues.SetValues(client);
            ReplaceClientRelations(existing, client);
        }
        else
        {
            _context.Set<CustomAuthClient>().Add(client);
        }

        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task DeleteAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);

        var client = await _context.Set<CustomAuthClient>()
            .SingleOrDefaultAsync(c => c.ClientId == clientId, cancellationToken)
            .ConfigureAwait(false);

        if (client is not null)
        {
            _context.Set<CustomAuthClient>().Remove(client);
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private IQueryable<CustomAuthClient> QueryClients()
    {
        return _context.Set<CustomAuthClient>()
            .Include(client => client.RedirectUriEntries)
            .Include(client => client.PostLogoutRedirectUriEntries)
            .Include(client => client.AllowedScopeEntries);
    }

    private static void PopulateClientLists(CustomAuthClient? client)
    {
        if (client is null)
        {
            return;
        }

        client.RedirectUris = client.RedirectUriEntries
            .Select(entry => entry.Uri)
            .ToList();
        client.PostLogoutRedirectUris = client.PostLogoutRedirectUriEntries
            .Select(entry => entry.Uri)
            .ToList();
        client.AllowedScopes = client.AllowedScopeEntries
            .Select(entry => entry.Scope)
            .ToList();
    }

    private static void ReplaceClientRelations(CustomAuthClient target, CustomAuthClient source)
    {
        target.RedirectUris = source.RedirectUris.ToList();
        target.PostLogoutRedirectUris = source.PostLogoutRedirectUris.ToList();
        target.AllowedScopes = source.AllowedScopes.ToList();

        target.RedirectUriEntries.Clear();
        target.PostLogoutRedirectUriEntries.Clear();
        target.AllowedScopeEntries.Clear();

        foreach (var entry in source.RedirectUriEntries)
        {
            target.RedirectUriEntries.Add(new CustomAuthClientRedirectUri
            {
                ClientId = target.ClientId,
                Uri = entry.Uri
            });
        }

        foreach (var entry in source.PostLogoutRedirectUriEntries)
        {
            target.PostLogoutRedirectUriEntries.Add(new CustomAuthClientPostLogoutRedirectUri
            {
                ClientId = target.ClientId,
                Uri = entry.Uri
            });
        }

        foreach (var entry in source.AllowedScopeEntries)
        {
            target.AllowedScopeEntries.Add(new CustomAuthClientAllowedScope
            {
                ClientId = target.ClientId,
                Scope = entry.Scope
            });
        }
    }

    private static void SyncClientRelations(CustomAuthClient client)
    {
        client.RedirectUriEntries.Clear();
        client.PostLogoutRedirectUriEntries.Clear();
        client.AllowedScopeEntries.Clear();

        foreach (var redirectUri in NormalizeValues(client.RedirectUris))
        {
            client.RedirectUriEntries.Add(new CustomAuthClientRedirectUri
            {
                ClientId = client.ClientId,
                Uri = redirectUri
            });
        }

        foreach (var postLogoutRedirectUri in NormalizeValues(client.PostLogoutRedirectUris))
        {
            client.PostLogoutRedirectUriEntries.Add(new CustomAuthClientPostLogoutRedirectUri
            {
                ClientId = client.ClientId,
                Uri = postLogoutRedirectUri
            });
        }

        foreach (var allowedScope in NormalizeValues(client.AllowedScopes))
        {
            client.AllowedScopeEntries.Add(new CustomAuthClientAllowedScope
            {
                ClientId = client.ClientId,
                Scope = allowedScope
            });
        }
    }

    private static IEnumerable<string> NormalizeValues(IEnumerable<string>? values)
    {
        return (values ?? [])
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.Ordinal);
    }
}
