using Microsoft.EntityFrameworkCore;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.EntityFrameworkCore;

public class CustomAuthDbContext : DbContext
{
    public CustomAuthDbContext(DbContextOptions<CustomAuthDbContext> options) : base(options)
    {
    }

    public DbSet<CustomAuthClient> Clients => Set<CustomAuthClient>();
    public DbSet<CustomAuthAuthorizationCode> AuthorizationCodes => Set<CustomAuthAuthorizationCode>();
    public DbSet<CustomAuthRefreshToken> RefreshTokens => Set<CustomAuthRefreshToken>();
    public DbSet<CustomAuthSession> Sessions => Set<CustomAuthSession>();
    public DbSet<CustomAuthSigningKey> SigningKeys => Set<CustomAuthSigningKey>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(CustomAuthDbContext).Assembly);
    }
}
