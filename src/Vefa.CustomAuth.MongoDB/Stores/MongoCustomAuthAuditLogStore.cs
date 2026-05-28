using System;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using global::MongoDB.Bson;
using MongoDB.Driver;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.MongoDB.Options;
using Microsoft.Extensions.Options;

namespace Vefa.CustomAuth.MongoDB.Stores;

/// <summary>
/// MongoDB implementation of <see cref="ICustomAuthAuditLogStore"/>.
/// </summary>
public sealed class MongoCustomAuthAuditLogStore : ICustomAuthAuditLogStore
{
    private readonly IMongoCollection<CustomAuthAuditLog> _collection;

    /// <summary>
    /// Initializes a new instance of the <see cref="MongoCustomAuthAuditLogStore"/> class.
    /// </summary>
    /// <param name="database">The MongoDB database.</param>
    /// <param name="options">The MongoDB options.</param>
    public MongoCustomAuthAuditLogStore(IMongoDatabase database, IOptions<CustomAuthMongoDbOptions> options)
    {
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(options);
        _collection = database.GetCollection<CustomAuthAuditLog>(options.Value.AuditLogsCollectionName);
    }

    /// <inheritdoc/>
    public async Task StoreAsync(CustomAuthAuditLog log, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(log);
        if (log.Id == Guid.Empty)
            throw new ArgumentException("Log ID cannot be empty.", nameof(log));

        await _collection.InsertOneAsync(log, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<CustomAuthPagedResult<CustomAuthAuditLog>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var filter = Builders<CustomAuthAuditLog>.Filter.Empty;
        if (!string.IsNullOrWhiteSpace(request.Search))
        {
            var regex = new BsonRegularExpression(Regex.Escape(request.Search), "i");
            filter = Builders<CustomAuthAuditLog>.Filter.Regex(l => l.Action, regex)
                | Builders<CustomAuthAuditLog>.Filter.Regex(l => l.TargetType, regex)
                | Builders<CustomAuthAuditLog>.Filter.Regex(l => l.TargetId, regex)
                | Builders<CustomAuthAuditLog>.Filter.Regex(l => l.ActorUserId, regex);
        }

        var page = request.Page > 0 ? request.Page : 1;
        var pageSize = request.PageSize > 0 ? request.PageSize : 10;

        var totalCount = (int)await _collection.CountDocumentsAsync(filter, cancellationToken: cancellationToken).ConfigureAwait(false);
        var items = await _collection.Find(filter)
            .SortByDescending(l => l.Timestamp)
            .Skip((page - 1) * pageSize)
            .Limit(pageSize)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return new CustomAuthPagedResult<CustomAuthAuditLog> { Items = items, TotalCount = totalCount };
    }
}
