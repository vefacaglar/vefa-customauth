using System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.MongoDB;

/// <summary>
/// Registers BSON class maps for CustomAuth domain models.
/// </summary>
internal static class MongoCustomAuthClassMap
{
    private static bool _registered;
    private static readonly object Lock = new();

    /// <summary>
    /// Registers all class maps if they have not been registered yet.
    /// </summary>
    public static void Register()
    {
        lock (Lock)
        {
            if (_registered)
                return;

            BsonClassMap.RegisterClassMap<CustomAuthClient>(map =>
            {
                map.AutoMap();
                map.MapIdMember(c => c.ClientId);
            });

            BsonClassMap.RegisterClassMap<CustomAuthAuthorizationCode>(map =>
            {
                map.AutoMap();
                map.MapIdMember(c => c.Id);
            });

            BsonClassMap.RegisterClassMap<CustomAuthRefreshToken>(map =>
            {
                map.AutoMap();
                map.MapIdMember(c => c.Id);
            });

            BsonClassMap.RegisterClassMap<CustomAuthSession>(map =>
            {
                map.AutoMap();
                map.MapIdMember(c => c.Id);
            });

            BsonClassMap.RegisterClassMap<CustomAuthSigningKey>(map =>
            {
                map.AutoMap();
                map.MapIdMember(c => c.KeyId);
            });

            BsonClassMap.RegisterClassMap<CustomAuthScope>(map =>
            {
                map.AutoMap();
                map.MapIdMember(c => c.Name);
            });

            BsonClassMap.RegisterClassMap<CustomAuthAuditLog>(map =>
            {
                map.AutoMap();
                map.MapIdMember(c => c.Id);
            });

            _registered = true;
        }
    }
}
