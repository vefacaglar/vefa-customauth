using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.EntityFrameworkCore.Configurations;

/// <summary>
/// Shared mapping for the free-form <c>Properties</c> extensibility bag exposed by several
/// CustomAuth models. The dictionary is persisted as a single JSON text column so that additive
/// features can store extra string properties without requiring a new relational column.
/// </summary>
internal static class CustomAuthPropertiesBagConfiguration
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    private static readonly ValueConverter<IDictionary<string, string>, string> Converter = new(
        value => Serialize(value),
        json => Deserialize(json));

    private static readonly ValueComparer<IDictionary<string, string>> Comparer = new(
        (left, right) => Serialize(left) == Serialize(right),
        value => Serialize(value).GetHashCode(StringComparison.Ordinal),
        value => Deserialize(Serialize(value)));

    /// <summary>
    /// Maps the supplied dictionary property to a JSON text column with change-tracking support.
    /// </summary>
    public static void Configure<TEntity>(
        EntityTypeBuilder<TEntity> builder,
        Expression<Func<TEntity, IDictionary<string, string>>> propertySelector)
        where TEntity : class
    {
        var property = builder.Property(propertySelector).HasConversion(Converter);
        property.Metadata.SetValueComparer(Comparer);
    }

    private static string Serialize(IDictionary<string, string>? value)
        => JsonSerializer.Serialize(value ?? new Dictionary<string, string>(), SerializerOptions);

    private static IDictionary<string, string> Deserialize(string? json)
        => string.IsNullOrEmpty(json)
            ? new Dictionary<string, string>()
            : JsonSerializer.Deserialize<Dictionary<string, string>>(json, SerializerOptions) ?? new Dictionary<string, string>();
}

internal sealed class CustomAuthClientConfiguration : IEntityTypeConfiguration<CustomAuthClient>
{
    public void Configure(EntityTypeBuilder<CustomAuthClient> builder)
    {
        builder.ToTable("CustomAuthClients");
        builder.HasKey(x => x.ClientId);
        builder.Property(x => x.ClientId).HasMaxLength(200);
        builder.Property(x => x.DisplayName).HasMaxLength(200);

        builder.Ignore(x => x.RedirectUris);
        builder.Ignore(x => x.PostLogoutRedirectUris);
        builder.Ignore(x => x.AllowedScopes);

        builder.HasMany(x => x.RedirectUriEntries)
            .WithOne()
            .HasForeignKey(x => x.ClientId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasMany(x => x.PostLogoutRedirectUriEntries)
            .WithOne()
            .HasForeignKey(x => x.ClientId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasMany(x => x.AllowedScopeEntries)
            .WithOne()
            .HasForeignKey(x => x.ClientId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.Property(x => x.TokenEndpointAuthMethod)
            .HasConversion<int>();

        builder.Property(x => x.JwksJson)
            .HasMaxLength(8000);

        CustomAuthPropertiesBagConfiguration.Configure(builder, x => x.Properties);
    }
}

internal sealed class CustomAuthClientRedirectUriConfiguration : IEntityTypeConfiguration<CustomAuthClientRedirectUri>
{
    public void Configure(EntityTypeBuilder<CustomAuthClientRedirectUri> builder)
    {
        builder.ToTable("CustomAuthClientRedirectUris");
        builder.HasKey(x => new { x.ClientId, x.Uri });
        builder.Property(x => x.ClientId).HasMaxLength(200);
        builder.Property(x => x.Uri).HasMaxLength(2000);
    }
}

internal sealed class CustomAuthClientPostLogoutRedirectUriConfiguration : IEntityTypeConfiguration<CustomAuthClientPostLogoutRedirectUri>
{
    public void Configure(EntityTypeBuilder<CustomAuthClientPostLogoutRedirectUri> builder)
    {
        builder.ToTable("CustomAuthClientPostLogoutRedirectUris");
        builder.HasKey(x => new { x.ClientId, x.Uri });
        builder.Property(x => x.ClientId).HasMaxLength(200);
        builder.Property(x => x.Uri).HasMaxLength(2000);
    }
}

internal sealed class CustomAuthClientAllowedScopeConfiguration : IEntityTypeConfiguration<CustomAuthClientAllowedScope>
{
    public void Configure(EntityTypeBuilder<CustomAuthClientAllowedScope> builder)
    {
        builder.ToTable("CustomAuthClientAllowedScopes");
        builder.HasKey(x => new { x.ClientId, x.Scope });
        builder.Property(x => x.ClientId).HasMaxLength(200);
        builder.Property(x => x.Scope).HasMaxLength(200);
    }
}

internal sealed class CustomAuthAuthorizationCodeConfiguration : IEntityTypeConfiguration<CustomAuthAuthorizationCode>
{
    public void Configure(EntityTypeBuilder<CustomAuthAuthorizationCode> builder)
    {
        builder.ToTable("CustomAuthAuthorizationCodes");
        builder.HasKey(x => x.Id);
        builder.HasIndex(x => x.CodeHash).IsUnique();
        builder.HasIndex(x => x.SessionId);
        builder.Property(x => x.CodeHash).HasMaxLength(200);
        builder.Property(x => x.ClientId).HasMaxLength(200);
        builder.Property(x => x.UserId).HasMaxLength(200);
        builder.Property(x => x.RedirectUri).HasMaxLength(2000);
        builder.Property(x => x.Scope).HasMaxLength(2000);
        builder.Property(x => x.Nonce).HasMaxLength(512);
    }
}

internal sealed class CustomAuthRefreshTokenConfiguration : IEntityTypeConfiguration<CustomAuthRefreshToken>
{
    public void Configure(EntityTypeBuilder<CustomAuthRefreshToken> builder)
    {
        builder.ToTable("CustomAuthRefreshTokens");
        builder.HasKey(x => x.Id);
        builder.HasIndex(x => x.TokenHash).IsUnique();
        builder.HasIndex(x => x.SessionId);
        builder.HasIndex(x => x.ParentTokenId);
        builder.HasIndex(x => x.AbsoluteExpiresAt);
        builder.Property(x => x.TokenHash).HasMaxLength(200);
        builder.Property(x => x.ClientId).HasMaxLength(200);
        builder.Property(x => x.UserId).HasMaxLength(200);
        builder.Property(x => x.Scope).HasMaxLength(2000);
    }
}

internal sealed class CustomAuthSessionConfiguration : IEntityTypeConfiguration<CustomAuthSession>
{
    public void Configure(EntityTypeBuilder<CustomAuthSession> builder)
    {
        builder.ToTable("CustomAuthSessions");
        builder.HasKey(x => x.Id);
        builder.Property(x => x.UserId).HasMaxLength(200);

        CustomAuthPropertiesBagConfiguration.Configure(builder, x => x.Properties);
    }
}

internal sealed class CustomAuthSigningKeyConfiguration : IEntityTypeConfiguration<CustomAuthSigningKey>
{
    public void Configure(EntityTypeBuilder<CustomAuthSigningKey> builder)
    {
        builder.ToTable("CustomAuthSigningKeys");
        builder.HasKey(x => x.KeyId);
        builder.Property(x => x.KeyId).HasMaxLength(200);
        builder.Property(x => x.Algorithm).HasMaxLength(50);
    }
}

internal sealed class CustomAuthScopeConfiguration : IEntityTypeConfiguration<CustomAuthScope>
{
    public void Configure(EntityTypeBuilder<CustomAuthScope> builder)
    {
        builder.ToTable("CustomAuthScopes");
        builder.HasKey(x => x.Name);
        builder.Property(x => x.Name).HasMaxLength(200);
        builder.Property(x => x.DisplayName).HasMaxLength(200);
        builder.Property(x => x.Description).HasMaxLength(1000);

        CustomAuthPropertiesBagConfiguration.Configure(builder, x => x.Properties);
    }
}

internal sealed class CustomAuthAuditLogConfiguration : IEntityTypeConfiguration<CustomAuthAuditLog>
{
    public void Configure(EntityTypeBuilder<CustomAuthAuditLog> builder)
    {
        builder.ToTable("CustomAuthAuditLogs");
        builder.HasKey(x => x.Id);
        builder.Property(x => x.Action).HasMaxLength(100);
        builder.Property(x => x.ActorUserId).HasMaxLength(200);
        builder.Property(x => x.TargetType).HasMaxLength(100);
        builder.Property(x => x.TargetId).HasMaxLength(200);
        builder.Property(x => x.IpAddress).HasMaxLength(50);
        builder.Property(x => x.UserAgent).HasMaxLength(1000);
        builder.Property(x => x.Metadata).HasMaxLength(4000);

        builder.HasIndex(x => x.Timestamp);
        builder.HasIndex(x => x.ActorUserId);
        builder.HasIndex(x => x.TargetType);
    }
}
