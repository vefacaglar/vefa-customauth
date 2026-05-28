using System;
using System.Threading;
using System.Threading.Tasks;
using MongoDB.Driver;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Services;
using Vefa.CustomAuth.MongoDB.Options;
using Microsoft.Extensions.Options;

namespace Vefa.CustomAuth.MongoDB.Services;

/// <summary>
/// MongoDB implementation of <see cref="ICustomAuthCleanupService"/>.
/// </summary>
public sealed class MongoCustomAuthCleanupService : ICustomAuthCleanupService
{
    private readonly IMongoDatabase _database;
    private readonly CustomAuthMongoDbOptions _options;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="MongoCustomAuthCleanupService"/> class.
    /// </summary>
    /// <param name="database">The MongoDB database.</param>
    /// <param name="options">The MongoDB options.</param>
    /// <param name="timeProvider">The time provider.</param>
    public MongoCustomAuthCleanupService(
        IMongoDatabase database,
        IOptions<CustomAuthMongoDbOptions> options,
        TimeProvider timeProvider)
    {
        _database = database ?? throw new ArgumentNullException(nameof(database));
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <inheritdoc/>
    public async Task CleanupAsync(CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();

        var codesCollection = _database.GetCollection<CustomAuthAuthorizationCode>(_options.AuthorizationCodesCollectionName);
        var codesFilter = Builders<CustomAuthAuthorizationCode>.Filter.Lte(c => c.ExpiresAt, now)
            | Builders<CustomAuthAuthorizationCode>.Filter.Ne(c => c.ConsumedAt, null);
        await codesCollection.DeleteManyAsync(codesFilter, cancellationToken).ConfigureAwait(false);

        var tokensCollection = _database.GetCollection<CustomAuthRefreshToken>(_options.RefreshTokensCollectionName);
        var tokensFilter = Builders<CustomAuthRefreshToken>.Filter.Lte(t => t.ExpiresAt, now);
        await tokensCollection.DeleteManyAsync(tokensFilter, cancellationToken).ConfigureAwait(false);

        var sessionsCollection = _database.GetCollection<CustomAuthSession>(_options.SessionsCollectionName);
        var sessionsFilter = Builders<CustomAuthSession>.Filter.Lte(s => s.ExpiresAt, now)
            | Builders<CustomAuthSession>.Filter.Ne(s => s.RevokedAt, null);
        await sessionsCollection.DeleteManyAsync(sessionsFilter, cancellationToken).ConfigureAwait(false);
    }
}
