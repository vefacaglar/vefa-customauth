using Microsoft.EntityFrameworkCore;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.EntityFrameworkCore;

namespace Vefa.CustomAuth.Sample.AuthServer.Data;

public sealed class SampleCustomAuthDbContext : CustomAuthDbContext
{
    public SampleCustomAuthDbContext(DbContextOptions<SampleCustomAuthDbContext> options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<CustomAuthClient>().ToTable("Clients");
        modelBuilder.Entity<CustomAuthClientRedirectUri>().ToTable("ClientRedirectUris");
        modelBuilder.Entity<CustomAuthClientPostLogoutRedirectUri>().ToTable("ClientPostLogoutRedirectUris");
        modelBuilder.Entity<CustomAuthClientAllowedScope>().ToTable("ClientAllowedScopes");
        modelBuilder.Entity<CustomAuthAuthorizationCode>().ToTable("AuthorizationCodes");
        modelBuilder.Entity<CustomAuthRefreshToken>().ToTable("RefreshTokens");
        modelBuilder.Entity<CustomAuthSession>().ToTable("Sessions");
        modelBuilder.Entity<CustomAuthSigningKey>().ToTable("SigningKeys");
        modelBuilder.Entity<CustomAuthScope>().ToTable("Scopes");
        modelBuilder.Entity<CustomAuthAuditLog>().ToTable("AuditLogs");
    }
}
