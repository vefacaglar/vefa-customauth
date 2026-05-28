using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Vefa.CustomAuth.AdminUI.Extensions;
using Vefa.CustomAuth.AspNetCore.Extensions;
using Vefa.CustomAuth.Core.Models;
using Xunit;

namespace Vefa.CustomAuth.AspNetCore.Tests;

public sealed class AdminUIEndpointTests
{
    private const string ClientId = "test-admin-client";

    [Fact]
    public async Task AdminUIRoutesServeStaticAssets()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // 1. Test HTML (Redirect to trailing slash)
        var redirectResponse = await client.GetAsync("/customauth");
        Assert.Equal(HttpStatusCode.Found, redirectResponse.StatusCode);
        Assert.Equal("/customauth/", redirectResponse.Headers.Location?.OriginalString);

        // 2. Test HTML (Success)
        var htmlResponse = await client.GetAsync("/customauth/");
        Assert.Equal(HttpStatusCode.OK, htmlResponse.StatusCode);
        var htmlContent = await htmlResponse.Content.ReadAsStringAsync();
        Assert.Contains("<title>Vefa.CustomAuth Admin Center</title>", htmlContent);

        // 2. Test CSS
        var cssResponse = await client.GetAsync("/customauth/css/admin.css");
        Assert.Equal(HttpStatusCode.OK, cssResponse.StatusCode);
        Assert.Equal("text/css", cssResponse.Content.Headers.ContentType?.MediaType);

        // 3. Test JS
        var jsResponse = await client.GetAsync("/customauth/js/admin.js");
        Assert.Equal(HttpStatusCode.OK, jsResponse.StatusCode);
        Assert.Equal("application/javascript", jsResponse.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task AdminClientCrudEndpointsWorkCorrectly()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // 1. List clients (GET)
        var listResponse = await client.GetAsync("/customauth/api/clients?page=1&pageSize=10");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        var result = await listResponse.Content.ReadFromJsonAsync<CustomAuthPagedResult<CustomAuthClient>>();
        Assert.NotNull(result);
        Assert.Single(result!.Items);
        Assert.Equal(ClientId, result.Items[0].ClientId);

        // 2. Create client (POST)
        var newClient = new CustomAuthClient
        {
            ClientId = "new-app",
            DisplayName = "New Application",
            RedirectUris = new List<string> { "https://localhost/callback" },
            AllowedScopes = new List<string> { "openid" }
        };
        var createResponse = await client.PostAsJsonAsync("/customauth/api/clients", newClient);
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);

        // 3. Verify created client in list (GET)
        var updatedListResponse = await client.GetAsync("/customauth/api/clients?page=1&pageSize=10");
        var updatedResult = await updatedListResponse.Content.ReadFromJsonAsync<CustomAuthPagedResult<CustomAuthClient>>();
        Assert.Equal(2, updatedResult!.TotalCount);

        // 4. Update client (PUT)
        newClient.DisplayName = "Updated Application Name";
        var updateResponse = await client.PutAsJsonAsync($"/customauth/api/clients/{newClient.ClientId}", newClient);
        Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);

        // 5. Delete client (DELETE)
        var deleteResponse = await client.DeleteAsync($"/customauth/api/clients/{newClient.ClientId}");
        Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);

        // 6. Verify deleted (GET)
        var finalListResponse = await client.GetAsync("/customauth/api/clients?page=1&pageSize=10");
        var finalResult = await finalListResponse.Content.ReadFromJsonAsync<CustomAuthPagedResult<CustomAuthClient>>();
        Assert.Equal(1, finalResult!.TotalCount);
    }

    [Fact]
    public async Task AdminScopeEndpointsWorkCorrectly()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // 1. List scopes (GET)
        var listResponse = await client.GetAsync("/customauth/api/scopes");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        var scopes = await listResponse.Content.ReadFromJsonAsync<List<CustomAuthScope>>();
        Assert.NotNull(scopes);

        // 2. Create scope (POST)
        var newScope = new CustomAuthScope
        {
            Name = "custom-scope",
            DisplayName = "Custom Scope",
            Description = "A custom test scope",
            Required = false,
            Emphasize = true
        };
        var createResponse = await client.PostAsJsonAsync("/customauth/api/scopes", newScope);
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);

        // 3. Verify created scope in list
        var updatedListResponse = await client.GetAsync("/customauth/api/scopes");
        var updatedScopes = await updatedListResponse.Content.ReadFromJsonAsync<List<CustomAuthScope>>();
        Assert.Contains(updatedScopes!, s => s.Name == "custom-scope");

        // 4. Update scope (PUT)
        newScope.Description = "Updated description";
        var updateResponse = await client.PutAsJsonAsync($"/customauth/api/scopes/{newScope.Name}", newScope);
        Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);

        // 5. Delete scope (DELETE)
        var deleteResponse = await client.DeleteAsync($"/customauth/api/scopes/{newScope.Name}");
        Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);
    }

    [Fact]
    public async Task AdminSessionEndpointsWorkCorrectly()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // List sessions (GET)
        var listResponse = await client.GetAsync("/customauth/api/sessions?page=1&pageSize=10");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        var result = await listResponse.Content.ReadFromJsonAsync<CustomAuthPagedResult<CustomAuthSession>>();
        Assert.NotNull(result);
    }

    [Fact]
    public async Task AdminRefreshTokenEndpointsWorkCorrectly()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // List refresh tokens (GET)
        var listResponse = await client.GetAsync("/customauth/api/refresh-tokens?page=1&pageSize=10");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        var result = await listResponse.Content.ReadFromJsonAsync<CustomAuthPagedResult<CustomAuthRefreshToken>>();
        Assert.NotNull(result);
    }

    [Fact]
    public async Task AdminSigningKeyEndpointsWorkCorrectly()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // List signing keys (GET)
        var listResponse = await client.GetAsync("/customauth/api/signing-keys");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        var content = await listResponse.Content.ReadAsStringAsync();
        Assert.NotNull(content);
    }

    [Fact]
    public async Task AdminAuditLogEndpointsWorkCorrectly()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // List audit logs (GET)
        var listResponse = await client.GetAsync("/customauth/api/audit-logs?page=1&pageSize=10");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        var result = await listResponse.Content.ReadFromJsonAsync<CustomAuthPagedResult<CustomAuthAuditLog>>();
        Assert.NotNull(result);
    }

    private static async Task<WebApplication> CreateAppAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services
            .AddVefaCustomAuth(options =>
            {
                options.Issuer = "http://localhost";
                options.RequireHttps = false;
            })
            .AddJwtTokenSigning()
            .AddInMemoryStores(stores =>
            {
                stores.Clients.Add(new CustomAuthClient
                {
                    ClientId = ClientId,
                    DisplayName = "Test Admin Client",
                    RedirectUris = { "https://localhost/signin-oidc" },
                    AllowedScopes = { "openid", "profile" },
                });
            });

        var app = builder.Build();
        app.MapVefaCustomAuthEndpoints();
        app.MapVefaCustomAuthAdminUI();
        
        await app.StartAsync();
        return app;
    }
}
