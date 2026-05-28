using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.EntityFrameworkCore.Configurations;

internal sealed class CustomAuthClientConfiguration : IEntityTypeConfiguration<CustomAuthClient>
{
    public void Configure(EntityTypeBuilder<CustomAuthClient> builder)
    {
        builder.ToTable("CustomAuthClients");
        builder.HasKey(x => x.ClientId);
        builder.Property(x => x.ClientId).HasMaxLength(200);
        builder.Property(x => x.DisplayName).HasMaxLength(200);

        var listComparer = new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<List<string>>(
            (a, b) => (a ?? new()).SequenceEqual(b ?? new()),
            v => v.Aggregate(0, (h, s) => HashCode.Combine(h, s.GetHashCode())),
            v => v.ToList());

        builder.Property(x => x.RedirectUris)
            .HasConversion(v => string.Join('\n', v), v => v.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList())
            .Metadata.SetValueComparer(listComparer);

        builder.Property(x => x.PostLogoutRedirectUris)
            .HasConversion(v => string.Join('\n', v), v => v.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList())
            .Metadata.SetValueComparer(listComparer);

        builder.Property(x => x.AllowedScopes)
            .HasConversion(v => string.Join(' ', v), v => v.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList())
            .Metadata.SetValueComparer(listComparer);
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
