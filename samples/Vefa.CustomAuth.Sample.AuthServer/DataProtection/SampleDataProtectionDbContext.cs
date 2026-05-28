using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Vefa.CustomAuth.Sample.AuthServer.DataProtection;

/// <summary>
/// EF Core context that stores the ASP.NET Core Data Protection key ring. Persisting the keys to a
/// shared database (instead of the per-machine default) lets every instance behind a load balancer
/// read cookies and antiforgery tokens created by any other instance. It implements
/// <see cref="IDataProtectionKeyContext"/> so Data Protection can use it via
/// <c>PersistKeysToDbContext</c>. It is intentionally separate from the protocol and identity
/// contexts.
/// </summary>
public sealed class SampleDataProtectionDbContext : DbContext, IDataProtectionKeyContext
{
    public SampleDataProtectionDbContext(DbContextOptions<SampleDataProtectionDbContext> options)
        : base(options)
    {
    }

    /// <summary>Gets the set of Data Protection keys.</summary>
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();
}
