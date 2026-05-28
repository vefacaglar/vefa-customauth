using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Driver;
using Testcontainers.MongoDb;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Services;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.MongoDB;
using Vefa.CustomAuth.MongoDB.Extensions;
using Vefa.CustomAuth.MongoDB.Options;
using Vefa.CustomAuth.Tokens;

namespace Vefa.CustomAuth.Tests;

public sealed class MongoCustomAuthStoreTests : IAsyncLifetime
{
    private readonly MongoDbContainer _container = new MongoDbBuilder()
        .WithImage("mongo:7.0")
        .Build();

    private ServiceProvider _provider = default!;

    public async Task InitializeAsync()
    {
        await _container.StartAsync();

        var services = new ServiceCollection();
        services.AddVefaCustomAuthMongoDbStores(options =>
        {
            options.ConnectionString = _container.GetConnectionString();
            options.DatabaseName = "customauth_test_" + Guid.NewGuid().ToString("N")[..8];
        });
        services.AddSingleton(TimeProvider.System);

        _provider = services.BuildServiceProvider();

        var database = _provider.GetRequiredService<IMongoDatabase>();
        var mongoOptions = _provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<CustomAuthMongoDbOptions>>().Value;
        await MongoCustomAuthIndexManager.EnsureIndexesAsync(database, mongoOptions);
    }

    public async Task DisposeAsync()
    {
        if (_provider is not null)
            await _provider.DisposeAsync();
        await _container.DisposeAsync();
    }

    [Fact]
    public async Task MongoDbExtensionRegistersAllStores()
    {
        await using var scope = _provider.CreateAsyncScope();

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
        await using var scope = _provider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<ICustomAuthClientStore>();

        await store.StoreAsync(new CustomAuthClient
        {
            ClientId = "client-1",
            DisplayName = "Client 1",
            RedirectUris = { "https://client.example.com/callback" },
            AllowedScopes = { "openid" },
        });

        var client = await store.FindByClientIdAsync("client-1");

        Assert.NotNull(client);
        Assert.Equal("Client 1", client!.DisplayName);
    }

    [Fact]
    public async Task ClientStoreUpdatesExistingClient()
    {
        await using var scope = _provider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<ICustomAuthClientStore>();

        await store.StoreAsync(new CustomAuthClient
        {
            ClientId = "client-update",
            DisplayName = "Original",
        });

        await store.StoreAsync(new CustomAuthClient
        {
            ClientId = "client-update",
            DisplayName = "Updated",
        });

        var client = await store.FindByClientIdAsync("client-update");
        Assert.NotNull(client);
        Assert.Equal("Updated", client!.DisplayName);
    }

    [Fact]
    public async Task ClientStoreDeletesClient()
    {
        await using var scope = _provider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<ICustomAuthClientStore>();

        await store.StoreAsync(new CustomAuthClient
        {
            ClientId = "client-delete",
            DisplayName = "To Delete",
        });

        await store.DeleteAsync("client-delete");

        var client = await store.FindByClientIdAsync("client-delete");
        Assert.Null(client);
    }

    [Fact]
    public async Task ClientStorePagesAndSearches()
    {
        await using var scope = _provider.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<ICustomAuthClientStore>();

        for (int i = 1; i <= 15; i++)
        {
            await store.StoreAsync(new CustomAuthClient
            {
                ClientId = $"paged-client-{i:D2}",
                DisplayName = $"Paged Client {i}",
            });
        }

        var result = await store.GetPagedAsync(new CustomAuthPagedRequest { Page = 1, PageSize = 10 });
        Assert.Equal(15, result.TotalCount);
        Assert.Equal(10, result.Items.Count);

        var searchResult = await store.GetPagedAsync(new CustomAuthPagedRequest { Page = 1, PageSize = 20, Search = "paged-client-0" });
        Assert.True(searchResult.TotalCount >= 6);
    }

    [Fact]
    public async Task AuthorizationCodeStorePersistsFindsAndConsumesCode()
    {
        var codeHash = TokenHasher.Hash(TokenHasher.CreateOpaqueToken());
        var codeId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero);

        await using (var scope = _provider.CreateAsyncScope())
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

        await using (var scope = _provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthAuthorizationCodeStore>();
            var storedCode = await store.FindByHashAsync(codeHash);
            Assert.NotNull(storedCode);
            Assert.Null(storedCode!.ConsumedAt);

            await store.MarkConsumedAsync(codeId, now.AddSeconds(10));
        }

        await using (var scope = _provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthAuthorizationCodeStore>();
            var consumedCode = await store.FindByHashAsync(codeHash);
            Assert.Equal(now.AddSeconds(10), consumedCode!.ConsumedAt);
        }
    }

    [Fact]
    public async Task RefreshTokenStorePersistsConsumesAndRevokesToken()
    {
        var tokenHash = TokenHasher.Hash(TokenHasher.CreateOpaqueToken());
        var tokenId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero);

        await using (var scope = _provider.CreateAsyncScope())
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

        await using (var scope = _provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthRefreshTokenStore>();
            var storedToken = await store.FindByHashAsync(tokenHash);
            Assert.NotNull(storedToken);

            await store.MarkConsumedAsync(tokenId, now.AddSeconds(10));
            await store.RevokeAsync(tokenId, now.AddSeconds(20));
        }

        await using (var scope = _provider.CreateAsyncScope())
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
        var sessionId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero);

        await using (var scope = _provider.CreateAsyncScope())
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

        await using (var scope = _provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthSessionStore>();
            var session = await store.FindAsync(sessionId);
            Assert.NotNull(session);

            await store.RevokeAsync(sessionId, now.AddSeconds(10));
        }

        await using (var scope = _provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthSessionStore>();
            var session = await store.FindAsync(sessionId);
            Assert.Equal(now.AddSeconds(10), session!.RevokedAt);
        }
    }

    [Fact]
    public async Task SigningKeyStorePersistsAndFindsActiveKey()
    {
        var now = new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero);

        await using (var scope = _provider.CreateAsyncScope())
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

        await using (var scope = _provider.CreateAsyncScope())
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
        await using (var scope = _provider.CreateAsyncScope())
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

        await using (var scope = _provider.CreateAsyncScope())
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

        await using (var scope = _provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthScopeStore>();
            var storedScope = await store.FindByNameAsync("test-scope");
            Assert.Null(storedScope);
        }
    }

    [Fact]
    public async Task AuditLogStorePersistsAndPagesLogs()
    {
        var now = DateTimeOffset.UtcNow;

        await using (var scope = _provider.CreateAsyncScope())
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

        await using (var scope = _provider.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICustomAuthAuditLogStore>();

            var result = await store.GetPagedAsync(new CustomAuthPagedRequest
            {
                Page = 1,
                PageSize = 10
            });

            Assert.Equal(15, result.TotalCount);
            Assert.Equal(10, result.Items.Count);
            Assert.Equal("Action-15", result.Items[0].Action);

            var searchResult = await store.GetPagedAsync(new CustomAuthPagedRequest
            {
                Page = 1,
                PageSize = 5,
                Search = "Action-1"
            });

            Assert.True(searchResult.TotalCount >= 7);
        }
    }

    [Fact]
    public async Task CleanupServiceClearsExpiredRecords()
    {
        var timeProvider = new FakeTimeProvider();
        var now = timeProvider.GetUtcNow();

        var database = _provider.GetRequiredService<IMongoDatabase>();
        var mongoOptions = _provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<CustomAuthMongoDbOptions>>().Value;

        var codesCollection = database.GetCollection<CustomAuthAuthorizationCode>(mongoOptions.AuthorizationCodesCollectionName);
        var tokensCollection = database.GetCollection<CustomAuthRefreshToken>(mongoOptions.RefreshTokensCollectionName);
        var sessionsCollection = database.GetCollection<CustomAuthSession>(mongoOptions.SessionsCollectionName);

        await codesCollection.InsertManyAsync(new[]
        {
            new CustomAuthAuthorizationCode
            {
                Id = Guid.NewGuid(), CodeHash = "expired-code-hash", ClientId = "client", UserId = "user",
                RedirectUri = "https://localhost", CodeChallenge = "challenge", CodeChallengeMethod = "plain",
                Scope = "openid", CreatedAt = now.AddMinutes(-5), ExpiresAt = now.AddMinutes(-3)
            },
            new CustomAuthAuthorizationCode
            {
                Id = Guid.NewGuid(), CodeHash = "consumed-code-hash", ClientId = "client", UserId = "user",
                RedirectUri = "https://localhost", CodeChallenge = "challenge", CodeChallengeMethod = "plain",
                Scope = "openid", CreatedAt = now.AddMinutes(-5), ExpiresAt = now.AddMinutes(5),
                ConsumedAt = now.AddMinutes(-4)
            },
            new CustomAuthAuthorizationCode
            {
                Id = Guid.NewGuid(), CodeHash = "valid-code-hash", ClientId = "client", UserId = "user",
                RedirectUri = "https://localhost", CodeChallenge = "challenge", CodeChallengeMethod = "plain",
                Scope = "openid", CreatedAt = now.AddMinutes(-1), ExpiresAt = now.AddMinutes(1)
            },
        });

        await tokensCollection.InsertManyAsync(new[]
        {
            new CustomAuthRefreshToken
            {
                Id = Guid.NewGuid(), TokenHash = "expired-token-hash", ClientId = "client", UserId = "user",
                Scope = "openid", CreatedAt = now.AddDays(-40), ExpiresAt = now.AddDays(-10)
            },
            new CustomAuthRefreshToken
            {
                Id = Guid.NewGuid(), TokenHash = "valid-token-hash", ClientId = "client", UserId = "user",
                Scope = "openid", CreatedAt = now.AddDays(-1), ExpiresAt = now.AddDays(29)
            },
        });

        await sessionsCollection.InsertManyAsync(new[]
        {
            new CustomAuthSession
            {
                Id = Guid.NewGuid(), UserId = "user", CreatedAt = now.AddDays(-5),
                ExpiresAt = now.AddDays(5), RevokedAt = now.AddDays(-1)
            },
            new CustomAuthSession
            {
                Id = Guid.NewGuid(), UserId = "user", CreatedAt = now.AddDays(-1),
                ExpiresAt = now.AddDays(9)
            },
        });

        await using (var scope = _provider.CreateAsyncScope())
        {
            var cleanupService = new MongoDB.Services.MongoCustomAuthCleanupService(
                scope.ServiceProvider.GetRequiredService<IMongoDatabase>(),
                scope.ServiceProvider.GetRequiredService<Microsoft.Extensions.Options.IOptions<CustomAuthMongoDbOptions>>(),
                timeProvider);

            await cleanupService.CleanupAsync();
        }

        var remainingCodes = await codesCollection.Find(_ => true).ToListAsync();
        Assert.Single(remainingCodes);
        Assert.Equal("valid-code-hash", remainingCodes[0].CodeHash);

        var remainingTokens = await tokensCollection.Find(_ => true).ToListAsync();
        Assert.Single(remainingTokens);
        Assert.Equal("valid-token-hash", remainingTokens[0].TokenHash);

        var remainingSessions = await sessionsCollection.Find(_ => true).ToListAsync();
        Assert.Single(remainingSessions);
        Assert.Null(remainingSessions[0].RevokedAt);
    }

    private sealed class FakeTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => _now;
    }
}
