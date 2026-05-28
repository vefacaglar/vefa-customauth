using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.EntityFrameworkCore;

namespace Vefa.CustomAuth.Sample.AuthServer.Data;

public static class DatabaseSeeder
{
    public static async Task EnsureDatabaseSeededAsync(IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<CustomAuthDbContext>();
        var environment = scope.ServiceProvider.GetRequiredService<IHostEnvironment>();

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

        if (!await context.Clients.AnyAsync(client => client.ClientId == "service-client"))
        {
            // Confidential client that authenticates with private_key_jwt. Only the PUBLIC key is
            // loaded here from Keys/service-client.jwks.json; the matching private key lives with the
            // calling service and is never shipped. The service signs a short-lived JWT client
            // assertion that this server verifies with the public keys in that file.
            var jwksPath = Path.Combine(environment.ContentRootPath, "Keys", "service-client.jwks.json");
            var jwksJson = await File.ReadAllTextAsync(jwksPath);

            context.Clients.Add(new CustomAuthClient
            {
                ClientId = "service-client",
                DisplayName = "Sample Confidential Service Client",
                RedirectUris = { "http://localhost:5099/signin-oidc" },
                AllowedScopes = { "openid", "profile", "email", "offline_access", "sample-api" },
                AllowRefreshTokens = true,
                TokenEndpointAuthMethod = CustomAuthClientAuthenticationMethod.PrivateKeyJwt,
                JwksJson = jwksJson,
            });
            changed = true;
        }

        if (changed)
        {
            await context.SaveChangesAsync();
        }
    }
}
