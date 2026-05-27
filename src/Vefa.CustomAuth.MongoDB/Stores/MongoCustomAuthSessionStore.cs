using System;
using System.Threading;
using System.Threading.Tasks;
using MongoDB.Driver;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.MongoDB.Options;
using Microsoft.Extensions.Options;

namespace Vefa.CustomAuth.MongoDB.Stores;

/// <summary>
/// MongoDB implementation of <see cref="ICustomAuthSessionStore"/>.
/// </summary>
public sealed class MongoCustomAuthSessionStore : ICustomAuthSessionStore
{
    private readonly IMongoCollection<CustomAuthSession> _collection;

    /// <summary>
    /// Initializes a new instance of the <see cref="MongoCustomAuthSessionStore"/> class.
    /// </summary>
    /// <param name="database">The MongoDB database.</param>
    /// <param name="options">The MongoDB options.</param>
    public MongoCustomAuthSessionStore(IMongoDatabase database, IOptions<CustomAuthMongoDbOptions> options)
    {
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(options);
        _collection = database.GetCollection<CustomAuthSession>(options.Value.SessionsCollectionName);
    }

    /// <inheritdoc/>
    public async Task<CustomAuthSession?> FindAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        var filter = Builders<CustomAuthSession>.Filter.Eq(s => s.Id, sessionId);
        return await _collection.Find(filter).FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task StoreAsync(CustomAuthSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        await _collection.InsertOneAsync(session, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task RevokeAsync(Guid sessionId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        var filter = Builders<CustomAuthSession>.Filter.Eq(s => s.Id, sessionId);
        var update = Builders<CustomAuthSession>.Update.Set(s => s.RevokedAt, revokedAt);
        await _collection.UpdateOneAsync(filter, update, cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}
