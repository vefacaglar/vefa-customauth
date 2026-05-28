using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Vefa.CustomAuth.Sample.AuthServer.Identity;

/// <summary>
/// ASP.NET Core Identity database context for the sample. It is deliberately separate from
/// <c>CustomAuthDbContext</c>: the OAuth/OIDC protocol data (clients, codes, tokens, signing keys)
/// and the user identity data are owned by different stores and can live in different databases.
/// The library never references this context — it only talks to <c>ICustomAuthUserStore</c>.
/// </summary>
public sealed class SampleIdentityDbContext : IdentityDbContext<IdentityUser>
{
    public SampleIdentityDbContext(DbContextOptions<SampleIdentityDbContext> options)
        : base(options)
    {
    }
}
