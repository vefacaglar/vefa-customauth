using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.EntityFrameworkCore;

public class CustomAuthDbContext : DbContext
{
    public CustomAuthDbContext(DbContextOptions<CustomAuthDbContext> options) : base(options)
    {
    }

    /// <summary>
    /// Initializes a derived custom auth DbContext with the supplied options.
    /// </summary>
    /// <param name="options">The context options.</param>
    protected CustomAuthDbContext(DbContextOptions options) : base(options)
    {
    }

    public DbSet<CustomAuthClient> Clients => Set<CustomAuthClient>();
    public DbSet<CustomAuthClientRedirectUri> ClientRedirectUris => Set<CustomAuthClientRedirectUri>();
    public DbSet<CustomAuthClientPostLogoutRedirectUri> ClientPostLogoutRedirectUris => Set<CustomAuthClientPostLogoutRedirectUri>();
    public DbSet<CustomAuthClientAllowedScope> ClientAllowedScopes => Set<CustomAuthClientAllowedScope>();
    public DbSet<CustomAuthAuthorizationCode> AuthorizationCodes => Set<CustomAuthAuthorizationCode>();
    public DbSet<CustomAuthRefreshToken> RefreshTokens => Set<CustomAuthRefreshToken>();
    public DbSet<CustomAuthSession> Sessions => Set<CustomAuthSession>();
    public DbSet<CustomAuthSigningKey> SigningKeys => Set<CustomAuthSigningKey>();
    public DbSet<CustomAuthScope> Scopes => Set<CustomAuthScope>();
    public DbSet<CustomAuthAuditLog> AuditLogs => Set<CustomAuthAuditLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(CustomAuthDbContext).Assembly);
    }

    public override int SaveChanges()
    {
        SyncClientRelations();
        return base.SaveChanges();
    }

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        SyncClientRelations();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        SyncClientRelations();
        return base.SaveChangesAsync(cancellationToken);
    }

    public override Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        SyncClientRelations();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    private void SyncClientRelations()
    {
        foreach (var entry in ChangeTracker.Entries<CustomAuthClient>())
        {
            if (entry.State is EntityState.Added or EntityState.Modified)
            {
                SyncClientRelations(entry.Entity);
            }
        }
    }

    private static void SyncClientRelations(CustomAuthClient client)
    {
        SyncRedirectUris(client, client.RedirectUris);
        SyncPostLogoutRedirectUris(client, client.PostLogoutRedirectUris);
        SyncAllowedScopes(client, client.AllowedScopes);
    }

    private static void SyncRedirectUris(CustomAuthClient client, IEnumerable<string> redirectUris)
    {
        client.RedirectUriEntries.Clear();

        foreach (var redirectUri in NormalizeValues(redirectUris))
        {
            client.RedirectUriEntries.Add(new CustomAuthClientRedirectUri
            {
                ClientId = client.ClientId,
                Uri = redirectUri
            });
        }
    }

    private static void SyncPostLogoutRedirectUris(CustomAuthClient client, IEnumerable<string> postLogoutRedirectUris)
    {
        client.PostLogoutRedirectUriEntries.Clear();

        foreach (var postLogoutRedirectUri in NormalizeValues(postLogoutRedirectUris))
        {
            client.PostLogoutRedirectUriEntries.Add(new CustomAuthClientPostLogoutRedirectUri
            {
                ClientId = client.ClientId,
                Uri = postLogoutRedirectUri
            });
        }
    }

    private static void SyncAllowedScopes(CustomAuthClient client, IEnumerable<string> allowedScopes)
    {
        client.AllowedScopeEntries.Clear();

        foreach (var allowedScope in NormalizeValues(allowedScopes))
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
