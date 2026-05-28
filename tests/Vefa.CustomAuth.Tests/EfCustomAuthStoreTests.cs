using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Services;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.EntityFrameworkCore;
using Vefa.CustomAuth.EntityFrameworkCore.Extensions;
using Vefa.CustomAuth.Tokens;
using Xunit;

namespace Vefa.CustomAuth.Tests;

public sealed class EfCustomAuthStoreTests
{
    [Fact]
    public async Task EntityFrameworkExtensionRegistersAllStores()
    {
        var services = new ServiceCollection();
        var databaseName = Guid.NewGuid().ToString("N");
        services.AddVefaCustomAuthEntityFrameworkCore(options => options.UseInMemoryDatabase(databaseName));
        services.AddSingleton(TimeProvider.System);

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ICustomAuthClientStore>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ICustomAuthAuthorizationCodeStore>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ICustomAuthRefreshTokenStore>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ICustomAuthSessionStore>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ICustomAuthSigningKeyStore>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ICustomAuthScopeStore>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ICustomAuthAuditLogStore>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ICustomAuthCleanupService>());
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
        await using var provider = CreateSqliteProvider();
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
    public async Task AuthorizationCodeStoreConsumesCodeOnlyOnce()
    {
        await using var provider = CreateSqliteProvider();
        var codeId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero);

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthAuthorizationCodeStore>();
            await store.StoreAsync(new CustomAuthAuthorizationCode
            {
                Id = codeId,
                CodeHash = TokenHasher.Hash(TokenHasher.CreateOpaqueToken()),
                ClientId = "client-1",
                UserId = "user-1",
                RedirectUri = "https://client.example.com/callback",
                CodeChallenge = "c",
                CodeChallengeMethod = "plain",
                Scope = "openid",
                CreatedAt = now,
                ExpiresAt = now.AddMinutes(2),
            });
        }

        await using var consumeScope = provider.CreateAsyncScope();
        var consumeStore = consumeScope.ServiceProvider.GetRequiredService<ICustomAuthAuthorizationCodeStore>();
        Assert.True(await consumeStore.MarkConsumedAsync(codeId, now.AddSeconds(10)));
        Assert.False(await consumeStore.MarkConsumedAsync(codeId, now.AddSeconds(20)));
    }

    [Fact]
    public async Task RefreshTokenStoreConsumesTokenOnlyOnce()
    {
        await using var provider = CreateSqliteProvider();
        var tokenId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero);

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthRefreshTokenStore>();
            await store.StoreAsync(new CustomAuthRefreshToken
            {
                Id = tokenId,
                TokenHash = TokenHasher.Hash(TokenHasher.CreateOpaqueToken()),
                ClientId = "client-1",
                UserId = "user-1",
                Scope = "openid offline_access",
                CreatedAt = now,
                ExpiresAt = now.AddDays(30),
                AbsoluteExpiresAt = now.AddDays(30),
            });
        }

        await using var consumeScope = provider.CreateAsyncScope();
        var consumeStore = consumeScope.ServiceProvider.GetRequiredService<ICustomAuthRefreshTokenStore>();
        Assert.True(await consumeStore.MarkConsumedAsync(tokenId, now.AddSeconds(10)));
        Assert.False(await consumeStore.MarkConsumedAsync(tokenId, now.AddSeconds(20)));
    }

    [Fact]
    public async Task RefreshTokenStorePersistsConsumesAndRevokesToken()
    {
        await using var provider = CreateSqliteProvider();
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

    [Fact]
    public async Task ScopeStorePersistsFindsAndDeletesScope()
    {
        await using var provider = CreateProvider();

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthScopeStore>();
            await store.StoreAsync(new CustomAuthScope
            {
                Name = "test-scope",
                DisplayName = "Test Scope",
                Description = "My test scope description",
                Required = true
            });
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthScopeStore>();
            var storedScope = await store.FindByNameAsync("test-scope");
            Assert.NotNull(storedScope);
            Assert.Equal("Test Scope", storedScope!.DisplayName);
            Assert.True(storedScope.Required);

            var all = await store.GetAllAsync();
            Assert.Contains(all, s => s.Name == "test-scope");

            await store.DeleteAsync("test-scope");
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthScopeStore>();
            var storedScope = await store.FindByNameAsync("test-scope");
            Assert.Null(storedScope);
        }
    }

    [Fact]
    public async Task AuditLogStorePersistsAndPagesLogs()
    {
        await using var provider = CreateProvider();
        var now = DateTimeOffset.UtcNow;

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthAuditLogStore>();
            for (int i = 1; i <= 15; i++)
            {
                await store.StoreAsync(new CustomAuthAuditLog
                {
                    Id = Guid.NewGuid(),
                    Action = $"Action-{i}",
                    ActorUserId = "admin",
                    TargetType = "Client",
                    TargetId = "client-1",
                    Timestamp = now.AddMinutes(i)
                });
            }
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthAuditLogStore>();
            
            // Fetch first page
            var result = await store.GetPagedAsync(new CustomAuthPagedRequest
            {
                Page = 1,
                PageSize = 10
            });

            Assert.Equal(15, result.TotalCount);
            Assert.Equal(10, result.Items.Count);
            // Verify ordering (newest first)
            Assert.Equal("Action-15", result.Items[0].Action);

            // Fetch with search
            var searchResult = await store.GetPagedAsync(new CustomAuthPagedRequest
            {
                Page = 1,
                PageSize = 5,
                Search = "Action-1" // matches Action-1, Action-10..15
            });

            Assert.True(searchResult.TotalCount >= 7);
        }
    }

    [Fact]
    public async Task CleanupServiceClearsExpiredRecords()
    {
        await using var provider = CreateSqliteProvider();
        var timeProvider = new FakeTimeProvider();
        var now = timeProvider.GetUtcNow();

        // Seed some expired and valid data
        await SeedAsync(provider, context =>
        {
            // Expired code
            context.AuthorizationCodes.Add(new CustomAuthAuthorizationCode
            {
                Id = Guid.NewGuid(),
                CodeHash = "expired-code-hash",
                ClientId = "client",
                UserId = "user",
                RedirectUri = "https://localhost",
                CodeChallenge = "challenge",
                CodeChallengeMethod = "plain",
                Scope = "openid",
                CreatedAt = now.AddMinutes(-5),
                ExpiresAt = now.AddMinutes(-3) // Expired
            });

            // Consumed code
            context.AuthorizationCodes.Add(new CustomAuthAuthorizationCode
            {
                Id = Guid.NewGuid(),
                CodeHash = "consumed-code-hash",
                ClientId = "client",
                UserId = "user",
                RedirectUri = "https://localhost",
                CodeChallenge = "challenge",
                CodeChallengeMethod = "plain",
                Scope = "openid",
                CreatedAt = now.AddMinutes(-5),
                ExpiresAt = now.AddMinutes(5),
                ConsumedAt = now.AddMinutes(-4) // Consumed
            });

            // Valid code
            context.AuthorizationCodes.Add(new CustomAuthAuthorizationCode
            {
                Id = Guid.NewGuid(),
                CodeHash = "valid-code-hash",
                ClientId = "client",
                UserId = "user",
                RedirectUri = "https://localhost",
                CodeChallenge = "challenge",
                CodeChallengeMethod = "plain",
                Scope = "openid",
                CreatedAt = now.AddMinutes(-1),
                ExpiresAt = now.AddMinutes(1) // Valid
            });

            // Expired refresh token
            context.RefreshTokens.Add(new CustomAuthRefreshToken
            {
                Id = Guid.NewGuid(),
                TokenHash = "expired-token-hash",
                ClientId = "client",
                UserId = "user",
                Scope = "openid",
                CreatedAt = now.AddDays(-40),
                ExpiresAt = now.AddDays(-10) // Expired
            });

            // Valid refresh token
            context.RefreshTokens.Add(new CustomAuthRefreshToken
            {
                Id = Guid.NewGuid(),
                TokenHash = "valid-token-hash",
                ClientId = "client",
                UserId = "user",
                Scope = "openid",
                CreatedAt = now.AddDays(-1),
                ExpiresAt = now.AddDays(29) // Valid
            });

            // Revoked session
            context.Sessions.Add(new CustomAuthSession
            {
                Id = Guid.NewGuid(),
                UserId = "user",
                CreatedAt = now.AddDays(-5),
                ExpiresAt = now.AddDays(5),
                RevokedAt = now.AddDays(-1) // Revoked
            });

            // Valid session
            context.Sessions.Add(new CustomAuthSession
            {
                Id = Guid.NewGuid(),
                UserId = "user",
                CreatedAt = now.AddDays(-1),
                ExpiresAt = now.AddDays(9) // Valid
            });
        });

        await using (var scope = provider.CreateAsyncScope())
        {
            var cleanupService = new EntityFrameworkCore.Services.EfCustomAuthCleanupService<CustomAuthDbContext>(
                scope.ServiceProvider.GetRequiredService<CustomAuthDbContext>(),
                timeProvider);

            await cleanupService.CleanupAsync();
        }

        // Verify databases cleared expired items
        await using (var scope = provider.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CustomAuthDbContext>();

            var codes = await db.AuthorizationCodes.ToListAsync();
            Assert.Single(codes);
            Assert.Equal("valid-code-hash", codes[0].CodeHash);

            var tokens = await db.RefreshTokens.ToListAsync();
            Assert.Single(tokens);
            Assert.Equal("valid-token-hash", tokens[0].TokenHash);

            var sessions = await db.Sessions.ToListAsync();
            Assert.Single(sessions);
            Assert.Null(sessions[0].RevokedAt);
        }
    }

    private static ServiceProvider CreateProvider()
    {
        var services = new ServiceCollection();
        var databaseName = Guid.NewGuid().ToString("N");
        services.AddVefaCustomAuthEntityFrameworkCore(options => options.UseInMemoryDatabase(databaseName));
        services.AddSingleton<TimeProvider>(TimeProvider.System);
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// SQLite-backed provider for tests that depend on relational features such as
    /// <c>ExecuteUpdateAsync</c> (used by atomic <c>MarkConsumedAsync</c>) which are
    /// unsupported by the EF Core InMemory provider.
    /// </summary>
    private static ServiceProvider CreateSqliteProvider()
    {
        var services = new ServiceCollection();
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        services.AddSingleton(connection);
        services.AddVefaCustomAuthEntityFrameworkCore(options => options.UseSqlite(connection));
        services.AddSingleton<TimeProvider>(TimeProvider.System);
        var provider = services.BuildServiceProvider();
        using (var scope = provider.CreateScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<CustomAuthDbContext>();
            ctx.Database.EnsureCreated();
        }
        return provider;
    }

    private static async Task SeedAsync(ServiceProvider provider, Action<CustomAuthDbContext> seed)
    {
        await using var scope = provider.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<CustomAuthDbContext>();
        seed(context);
        await context.SaveChangesAsync();
    }

    private sealed class FakeTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => _now;
    }
}
