using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;
using Xunit;

namespace Vefa.CustomAuth.Tests;

public class CustomAuthManagerTests
{
    [Fact]
    public async Task ClientManager_CreateAsync_ValidatesInputAndLogsAudit()
    {
        // Arrange
        var clientStore = new MockClientStore();
        var auditStore = new MockAuditLogStore();
        var timeProvider = new FakeTimeProvider();
        var manager = new CustomAuthClientManager(clientStore, auditStore, timeProvider);

        var client = new CustomAuthClient
        {
            ClientId = "test-client",
            DisplayName = "Test Client",
            RedirectUris = { "https://localhost/callback" }
        };

        // Act
        await manager.CreateAsync(client);

        // Assert
        Assert.Single(clientStore.Clients);
        Assert.Equal("test-client", clientStore.Clients[0].ClientId);
        Assert.Single(auditStore.Logs);
        Assert.Equal("ClientCreated", auditStore.Logs[0].Action);
        Assert.Equal("Client", auditStore.Logs[0].TargetType);
        Assert.Equal("test-client", auditStore.Logs[0].TargetId);
    }

    [Fact]
    public async Task ClientManager_CreateAsync_ThrowsOnMissingRedirectUris()
    {
        // Arrange
        var clientStore = new MockClientStore();
        var auditStore = new MockAuditLogStore();
        var timeProvider = new FakeTimeProvider();
        var manager = new CustomAuthClientManager(clientStore, auditStore, timeProvider);

        var client = new CustomAuthClient
        {
            ClientId = "test-client",
            DisplayName = "Test Client"
        };

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() => manager.CreateAsync(client));
    }

    [Fact]
    public async Task ScopeManager_CreateAsync_StoresScopeAndLogsAudit()
    {
        // Arrange
        var scopeStore = new MockScopeStore();
        var auditStore = new MockAuditLogStore();
        var timeProvider = new FakeTimeProvider();
        var manager = new CustomAuthScopeManager(scopeStore, auditStore, timeProvider);

        var scope = new CustomAuthScope
        {
            Name = "custom-scope",
            DisplayName = "Custom Scope"
        };

        // Act
        await manager.CreateAsync(scope);

        // Assert
        Assert.Single(scopeStore.Scopes);
        Assert.Equal("custom-scope", scopeStore.Scopes[0].Name);
        Assert.Single(auditStore.Logs);
        Assert.Equal("ScopeCreated", auditStore.Logs[0].Action);
        Assert.Equal("Scope", auditStore.Logs[0].TargetType);
        Assert.Equal("custom-scope", auditStore.Logs[0].TargetId);
    }

    private sealed class FakeTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => _now;
    }

    private sealed class MockClientStore : ICustomAuthClientStore
    {
        public List<CustomAuthClient> Clients { get; } = new();

        public Task<CustomAuthClient?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Clients.Find(c => c.ClientId == clientId));
        }

        public Task<CustomAuthPagedResult<CustomAuthClient>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new CustomAuthPagedResult<CustomAuthClient>
            {
                Items = Clients,
                TotalCount = Clients.Count
            });
        }

        public Task StoreAsync(CustomAuthClient client, CancellationToken cancellationToken = default)
        {
            Clients.Add(client);
            return Task.CompletedTask;
        }

        public Task DeleteAsync(string clientId, CancellationToken cancellationToken = default)
        {
            Clients.RemoveAll(c => c.ClientId == clientId);
            return Task.CompletedTask;
        }
    }

    private sealed class MockScopeStore : ICustomAuthScopeStore
    {
        public List<CustomAuthScope> Scopes { get; } = new();

        public Task<CustomAuthScope?> FindByNameAsync(string name, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Scopes.Find(s => s.Name == name));
        }

        public Task<IReadOnlyList<CustomAuthScope>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            IReadOnlyList<CustomAuthScope> result = Scopes;
            return Task.FromResult(result);
        }

        public Task StoreAsync(CustomAuthScope scope, CancellationToken cancellationToken = default)
        {
            Scopes.Add(scope);
            return Task.CompletedTask;
        }

        public Task DeleteAsync(string name, CancellationToken cancellationToken = default)
        {
            Scopes.RemoveAll(s => s.Name == name);
            return Task.CompletedTask;
        }
    }

    private sealed class MockAuditLogStore : ICustomAuthAuditLogStore
    {
        public List<CustomAuthAuditLog> Logs { get; } = new();

        public Task StoreAsync(CustomAuthAuditLog log, CancellationToken cancellationToken = default)
        {
            Logs.Add(log);
            return Task.CompletedTask;
        }

        public Task<CustomAuthPagedResult<CustomAuthAuditLog>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new CustomAuthPagedResult<CustomAuthAuditLog>
            {
                Items = Logs,
                TotalCount = Logs.Count
            });
        }
    }
}
