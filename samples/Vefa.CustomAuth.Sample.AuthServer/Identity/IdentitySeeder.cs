using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Vefa.CustomAuth.Sample.AuthServer.Identity;

/// <summary>
/// Creates the Identity database and seeds the demo user (<c>demo</c> / <c>demo</c>) with the same
/// roles and custom claims the in-memory demo store exposes, so the dynamic profile service behaves
/// identically regardless of which user store backs the sample.
/// </summary>
public static class IdentitySeeder
{
    private static readonly string[] DemoRoles = { "admin", "superadmin" };

    public static async Task EnsureSeededAsync(IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();

        var context = scope.ServiceProvider.GetRequiredService<SampleIdentityDbContext>();
        await context.Database.EnsureCreatedAsync().ConfigureAwait(false);

        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        foreach (var role in DemoRoles)
        {
            if (!await roleManager.RoleExistsAsync(role).ConfigureAwait(false))
            {
                await roleManager.CreateAsync(new IdentityRole(role)).ConfigureAwait(false);
            }
        }

        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        if (await userManager.FindByNameAsync("demo").ConfigureAwait(false) is not null)
        {
            return;
        }

        var user = new IdentityUser
        {
            UserName = "demo",
            Email = "demo@example.com",
            EmailConfirmed = true,
        };

        var result = await userManager.CreateAsync(user, "demo").ConfigureAwait(false);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                "Failed to seed the demo Identity user: " +
                string.Join(", ", result.Errors.Select(error => error.Description)));
        }

        await userManager.AddToRolesAsync(user, DemoRoles).ConfigureAwait(false);
        await userManager.AddClaimsAsync(user, new[]
        {
            new Claim("department", "IT"),
            new Claim("tenant_id", "42"),
            new Claim("is_premium", "true"),
            new Claim("custom_permission", "write_access"),
        }).ConfigureAwait(false);
    }
}
