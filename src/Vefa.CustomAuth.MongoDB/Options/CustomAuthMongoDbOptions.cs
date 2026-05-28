using System;

namespace Vefa.CustomAuth.MongoDB.Options;

/// <summary>
/// Configuration options for the MongoDB persistence provider.
/// </summary>
public sealed class CustomAuthMongoDbOptions
{
    /// <summary>
    /// Gets or sets the MongoDB connection string.
    /// </summary>
    public string ConnectionString { get; set; } = "mongodb://localhost:27017";

    /// <summary>
    /// Gets or sets the database name used for CustomAuth collections.
    /// </summary>
    public string DatabaseName { get; set; } = "customauth";

    /// <summary>
    /// Gets or sets the collection name for clients.
    /// </summary>
    public string ClientsCollectionName { get; set; } = "Clients";

    /// <summary>
    /// Gets or sets the collection name for authorization codes.
    /// </summary>
    public string AuthorizationCodesCollectionName { get; set; } = "AuthorizationCodes";

    /// <summary>
    /// Gets or sets the collection name for refresh tokens.
    /// </summary>
    public string RefreshTokensCollectionName { get; set; } = "RefreshTokens";

    /// <summary>
    /// Gets or sets the collection name for sessions.
    /// </summary>
    public string SessionsCollectionName { get; set; } = "Sessions";

    /// <summary>
    /// Gets or sets the collection name for signing keys.
    /// </summary>
    public string SigningKeysCollectionName { get; set; } = "SigningKeys";

    /// <summary>
    /// Gets or sets the collection name for scopes.
    /// </summary>
    public string ScopesCollectionName { get; set; } = "Scopes";

    /// <summary>
    /// Gets or sets the collection name for audit logs.
    /// </summary>
    public string AuditLogsCollectionName { get; set; } = "AuditLogs";
}
