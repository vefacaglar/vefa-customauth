using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MongoDB.Driver;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.MongoDB.Options;
using Microsoft.Extensions.Options;

namespace Vefa.CustomAuth.MongoDB.Stores;

/// <summary>
/// MongoDB implementation of <see cref="ICustomAuthScopeStore"/>.
/// </summary>
public sealed class MongoCustomAuthScopeStore : ICustomAuthScopeStore
{
    private readonly IMongoCollection<CustomAuthScope> _collection;

    /// <summary>
    /// Initializes a new instance of the <see cref="MongoCustomAuthScopeStore"/> class.
    /// </summary>
    /// <param name="database">The MongoDB database.</param>
    /// <param name="options">The MongoDB options.</param>
    public MongoCustomAuthScopeStore(IMongoDatabase database, IOptions<CustomAuthMongoDbOptions> options)
    {
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(options);
        _collection = database.GetCollection<CustomAuthScope>(options.Value.ScopesCollectionName);
    }

    /// <inheritdoc/>
    public async Task<CustomAuthScope?> FindByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        var filter = Builders<CustomAuthScope>.Filter.Eq(s => s.Name, name);
        return await _collection.Find(filter).FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<IReadOnlyList<CustomAuthScope>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _collection.Find(Builders<CustomAuthScope>.Filter.Empty)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task StoreAsync(CustomAuthScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentException.ThrowIfNullOrEmpty(scope.Name);

        var filter = Builders<CustomAuthScope>.Filter.Eq(s => s.Name, scope.Name);
        await _collection.ReplaceOneAsync(filter, scope, new ReplaceOptions { IsUpsert = true }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task DeleteAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        var filter = Builders<CustomAuthScope>.Filter.Eq(s => s.Name, name);
        await _collection.DeleteOneAsync(filter, cancellationToken).ConfigureAwait(false);
    }
}
