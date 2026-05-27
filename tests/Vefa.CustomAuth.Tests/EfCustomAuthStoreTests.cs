using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.EntityFrameworkCore;
using Vefa.CustomAuth.EntityFrameworkCore.Extensions;
using Vefa.CustomAuth.Tokens;

namespace Vefa.CustomAuth.Tests;

public sealed class EfCustomAuthStoreTests
{
    [Fact]
    public async Task EntityFrameworkExtensionRegistersAllStores()
    {
        var services = new ServiceCollection();
        var databaseName = Guid.NewGuid().ToString("N");
        services.AddVefaCustomAuthEntityFrameworkCore(options => options.UseInMemoryDatabase(databaseName));

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ICustomAuthClientStore>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ICustomAuthAuthorizationCodeStore>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ICustomAuthRefreshTokenStore>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ICustomAuthSessionStore>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ICustomAuthSigningKeyStore>());
    }

    [Fact]
    public async Task ClientStoreFindsClientById()
    {
        await using var provider = CreateProvider();
        await SeedAsync(provider, context => context.Clients.Add(new CustomAuthClient
        {
            ClientId = "client-1",
            DisplayName = "Client 1",
            RedirectUris = { "https://client.example.com/callback" },
            AllowedScopes = { "openid" },
        }));

        await using var scope = provider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<ICustomAuthClientStore>();

        var client = await store.FindByClientIdAsync("client-1");

        Assert.NotNull(client);
        Assert.Equal("Client 1", client!.DisplayName);
    }

    [Fact]
    public async Task AuthorizationCodeStorePersistsFindsAndConsumesCode()
    {
        await using var provider = CreateProvider();
        var codeHash = TokenHasher.Hash(TokenHasher.CreateOpaqueToken());
        var codeId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero);

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthAuthorizationCodeStore>();
            await store.StoreAsync(new CustomAuthAuthorizationCode
            {
                Id = codeId,
                CodeHash = codeHash,
                ClientId = "client-1",
                UserId = "user-1",
                RedirectUri = "https://client.example.com/callback",
                CodeChallenge = "challenge",
                CodeChallengeMethod = "plain",
                Scope = "openid",
                CreatedAt = now,
                ExpiresAt = now.AddMinutes(2),
            });
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthAuthorizationCodeStore>();
            var storedCode = await store.FindByHashAsync(codeHash);
            Assert.NotNull(storedCode);
            Assert.Null(storedCode!.ConsumedAt);

            await store.MarkConsumedAsync(codeId, now.AddSeconds(10));
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthAuthorizationCodeStore>();
            var consumedCode = await store.FindByHashAsync(codeHash);
            Assert.Equal(now.AddSeconds(10), consumedCode!.ConsumedAt);
        }
    }

    [Fact]
    public async Task RefreshTokenStorePersistsConsumesAndRevokesToken()
    {
        await using var provider = CreateProvider();
        var tokenHash = TokenHasher.Hash(TokenHasher.CreateOpaqueToken());
        var tokenId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero);

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthRefreshTokenStore>();
            await store.StoreAsync(new CustomAuthRefreshToken
            {
                Id = tokenId,
                TokenHash = tokenHash,
                ClientId = "client-1",
                UserId = "user-1",
                Scope = "openid offline_access",
                CreatedAt = now,
                ExpiresAt = now.AddDays(30),
            });
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthRefreshTokenStore>();
            var storedToken = await store.FindByHashAsync(tokenHash);
            Assert.NotNull(storedToken);

            await store.MarkConsumedAsync(tokenId, now.AddSeconds(10));
            await store.RevokeAsync(tokenId, now.AddSeconds(20));
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthRefreshTokenStore>();
            var updatedToken = await store.FindByHashAsync(tokenHash);
            Assert.Equal(now.AddSeconds(10), updatedToken!.ConsumedAt);
            Assert.Equal(now.AddSeconds(20), updatedToken.RevokedAt);
        }
    }

    [Fact]
    public async Task SessionStorePersistsFindsAndRevokesSession()
    {
        await using var provider = CreateProvider();
        var sessionId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero);

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthSessionStore>();
            await store.StoreAsync(new CustomAuthSession
            {
                Id = sessionId,
                UserId = "user-1",
                CreatedAt = now,
                ExpiresAt = now.AddDays(30),
            });
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthSessionStore>();
            var session = await store.FindAsync(sessionId);
            Assert.NotNull(session);

            await store.RevokeAsync(sessionId, now.AddSeconds(10));
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthSessionStore>();
            var session = await store.FindAsync(sessionId);
            Assert.Equal(now.AddSeconds(10), session!.RevokedAt);
        }
    }

    [Fact]
    public async Task SigningKeyStorePersistsAndFindsActiveKey()
    {
        await using var provider = CreateProvider();
        var now = new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero);

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthSigningKeyStore>();
            await store.StoreAsync(new CustomAuthSigningKey
            {
                KeyId = "key-1",
                Algorithm = "RS256",
                PrivateKeyPem = "private",
                PublicKeyPem = "public",
                CreatedAt = now,
                IsActive = true,
            });
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthSigningKeyStore>();
            var activeKey = await store.GetActiveAsync();
            var keys = await store.GetAllAsync();

            Assert.NotNull(activeKey);
            Assert.Equal("key-1", activeKey!.KeyId);
            Assert.Single(keys);
        }
    }

    private static ServiceProvider CreateProvider()
    {
        var services = new ServiceCollection();
        var databaseName = Guid.NewGuid().ToString("N");
        services.AddVefaCustomAuthEntityFrameworkCore(options => options.UseInMemoryDatabase(databaseName));
        return services.BuildServiceProvider();
    }

    private static async Task SeedAsync(ServiceProvider provider, Action<CustomAuthDbContext> seed)
    {
        await using var scope = provider.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<CustomAuthDbContext>();
        seed(context);
        await context.SaveChangesAsync();
    }
}
