using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.EntityFrameworkCore;

namespace Vefa.CustomAuth.Sample.AuthServer.Data;

public static class DatabaseSeeder
{
    public static async Task EnsureDatabaseSeededAsync(IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<CustomAuthDbContext>();

        await context.Database.EnsureCreatedAsync();

        bool changed = false;

        if (!await context.Clients.AnyAsync(client => client.ClientId == "sample-webapp"))
        {
            context.Clients.Add(new CustomAuthClient
            {
                ClientId = "sample-webapp",
                DisplayName = "Sample Web App",
                RedirectUris = { "http://localhost:5043/signin-oidc" },
                PostLogoutRedirectUris = { "http://localhost:5043/signout-callback-oidc" },
                AllowedScopes = { "openid", "profile", "email", "offline_access", "sample-api" },
                AllowRefreshTokens = true,
            });
            changed = true;
        }

        if (!await context.Clients.AnyAsync(client => client.ClientId == "swagger-ui"))
        {
            context.Clients.Add(new CustomAuthClient
            {
                ClientId = "swagger-ui",
                DisplayName = "Sample Swagger UI",
                RedirectUris = { "http://localhost:5098/swagger/oauth2-redirect.html" },
                PostLogoutRedirectUris = { "http://localhost:5098/swagger/" },
                AllowedScopes = { "openid", "profile", "email", "offline_access", "sample-api" },
                AllowRefreshTokens = true,
            });
            changed = true;
        }

        if (changed)
        {
            await context.SaveChangesAsync();
        }
    }
}
