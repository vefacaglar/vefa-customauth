using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Vefa.CustomAuth.Core.Stores;
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
        await EnsureClientRelationTablesAsync(context);

        var clientStore = scope.ServiceProvider.GetRequiredService<ICustomAuthClientStore>();

        if (!await context.Clients.AnyAsync(client => client.ClientId == "sample-webapp"))
        {
            await clientStore.StoreAsync(new CustomAuthClient
            {
                ClientId = "sample-webapp",
                DisplayName = "Sample Web App",
                RedirectUris = { "http://localhost:5043/signin-oidc" },
                PostLogoutRedirectUris = { "http://localhost:5043/signout-callback-oidc" },
                AllowedScopes = { "openid", "profile", "email", "offline_access", "sample-api" },
                AllowRefreshTokens = true,
            });
        }
        else if (!await context.ClientRedirectUris.AnyAsync(uri => uri.ClientId == "sample-webapp"))
        {
            await clientStore.StoreAsync(new CustomAuthClient
            {
                ClientId = "sample-webapp",
                DisplayName = "Sample Web App",
                RedirectUris = { "http://localhost:5043/signin-oidc" },
                PostLogoutRedirectUris = { "http://localhost:5043/signout-callback-oidc" },
                AllowedScopes = { "openid", "profile", "email", "offline_access", "sample-api" },
                AllowRefreshTokens = true,
            });
        }

        if (!await context.Clients.AnyAsync(client => client.ClientId == "swagger-ui"))
        {
            await clientStore.StoreAsync(new CustomAuthClient
            {
                ClientId = "swagger-ui",
                DisplayName = "Sample Swagger UI",
                RedirectUris = { "http://localhost:5098/swagger/oauth2-redirect.html" },
                PostLogoutRedirectUris = { "http://localhost:5098/swagger/" },
                AllowedScopes = { "openid", "profile", "email", "offline_access", "sample-api" },
                AllowRefreshTokens = true,
            });
        }
        else if (!await context.ClientRedirectUris.AnyAsync(uri => uri.ClientId == "swagger-ui"))
        {
            await clientStore.StoreAsync(new CustomAuthClient
            {
                ClientId = "swagger-ui",
                DisplayName = "Sample Swagger UI",
                RedirectUris = { "http://localhost:5098/swagger/oauth2-redirect.html" },
                PostLogoutRedirectUris = { "http://localhost:5098/swagger/" },
                AllowedScopes = { "openid", "profile", "email", "offline_access", "sample-api" },
                AllowRefreshTokens = true,
            });
        }

        if (!await context.Clients.AnyAsync(client => client.ClientId == "service-client"))
        {
            // Confidential client that authenticates with private_key_jwt. Only the PUBLIC key is
            // loaded here from Keys/service-client.jwks.json; the matching private key lives with the
            // calling service and is never shipped. The service signs a short-lived JWT client
            // assertion that this server verifies with the public keys in that file.
            var jwksPath = Path.Combine(environment.ContentRootPath, "Keys", "service-client.jwks.json");
            var jwksJson = await File.ReadAllTextAsync(jwksPath);

            await clientStore.StoreAsync(new CustomAuthClient
            {
                ClientId = "service-client",
                DisplayName = "Sample Confidential Service Client",
                RedirectUris = { "http://localhost:5099/signin-oidc" },
                AllowedScopes = { "openid", "profile", "email", "offline_access", "sample-api" },
                AllowRefreshTokens = true,
                TokenEndpointAuthMethod = CustomAuthClientAuthenticationMethod.PrivateKeyJwt,
                JwksJson = jwksJson,
            });
        }
        else if (!await context.ClientRedirectUris.AnyAsync(uri => uri.ClientId == "service-client"))
        {
            var jwksPath = Path.Combine(environment.ContentRootPath, "Keys", "service-client.jwks.json");
            var jwksJson = await File.ReadAllTextAsync(jwksPath);

            await clientStore.StoreAsync(new CustomAuthClient
            {
                ClientId = "service-client",
                DisplayName = "Sample Confidential Service Client",
                RedirectUris = { "http://localhost:5099/signin-oidc" },
                AllowedScopes = { "openid", "profile", "email", "offline_access", "sample-api" },
                AllowRefreshTokens = true,
                TokenEndpointAuthMethod = CustomAuthClientAuthenticationMethod.PrivateKeyJwt,
                JwksJson = jwksJson,
            });
        }
    }

    private static async Task EnsureClientRelationTablesAsync(CustomAuthDbContext context)
    {
        if (!context.Database.IsSqlite())
        {
            return;
        }

        await context.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "CustomAuthClientRedirectUris" (
                "ClientId" TEXT NOT NULL,
                "Uri" TEXT NOT NULL,
                CONSTRAINT "PK_CustomAuthClientRedirectUris" PRIMARY KEY ("ClientId", "Uri"),
                CONSTRAINT "FK_CustomAuthClientRedirectUris_CustomAuthClients_ClientId" FOREIGN KEY ("ClientId") REFERENCES "CustomAuthClients" ("ClientId") ON DELETE CASCADE
            );
            """);

        await context.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "CustomAuthClientPostLogoutRedirectUris" (
                "ClientId" TEXT NOT NULL,
                "Uri" TEXT NOT NULL,
                CONSTRAINT "PK_CustomAuthClientPostLogoutRedirectUris" PRIMARY KEY ("ClientId", "Uri"),
                CONSTRAINT "FK_CustomAuthClientPostLogoutRedirectUris_CustomAuthClients_ClientId" FOREIGN KEY ("ClientId") REFERENCES "CustomAuthClients" ("ClientId") ON DELETE CASCADE
            );
            """);

        await context.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS "CustomAuthClientAllowedScopes" (
                "ClientId" TEXT NOT NULL,
                "Scope" TEXT NOT NULL,
                CONSTRAINT "PK_CustomAuthClientAllowedScopes" PRIMARY KEY ("ClientId", "Scope"),
                CONSTRAINT "FK_CustomAuthClientAllowedScopes_CustomAuthClients_ClientId" FOREIGN KEY ("ClientId") REFERENCES "CustomAuthClients" ("ClientId") ON DELETE CASCADE
            );
            """);
    }
}
