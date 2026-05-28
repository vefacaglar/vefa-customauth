using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.DataProtection;
using Vefa.CustomAuth.AspNetCore.Extensions;
using Vefa.CustomAuth.AspNetCore.Stores.InMemory;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Options;
using Xunit;

namespace Vefa.CustomAuth.AspNetCore.Tests;

public sealed class SessionCookieAndValidationTests
{
    private const string ClientId = "test-client";
    private const string RedirectUri = "http://localhost/signin-oidc";
    private const string UserName = "demo";
    private const string Password = "demo";

    [Fact]
    public async Task SessionCookieHardening_ShouldEncryptAndSignValue_AndUseHostPrefix()
    {
        await using var app = await CreateAppAsync(opts =>
        {
            opts.Issuer = "https://localhost";
            opts.RequireHttps = true;
        }, clientOpts =>
        {
            clientOpts.RedirectUris.Clear();
            clientOpts.RedirectUris.Add("https://localhost/signin-oidc");
        });
        using var client = app.GetTestClient();

        // 1. Sign in to get the cookie
        var antiforgery = await AntiforgeryTestHelpers.GetAntiforgeryAsync(client);
        using var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["userName"] = "demo",
                ["password"] = "demo",
                ["returnUrl"] = "/connect/authorize?client_id=test-client&redirect_uri=" 
                    + Uri.EscapeDataString("https://localhost/signin-oidc") 
                    + "&response_type=code&scope=openid&code_challenge=xyz&code_challenge_method=S256",
                [antiforgery.FormFieldName] = antiforgery.RequestToken,
            }),
        };
        loginRequest.Headers.Add("Cookie", antiforgery.Cookie);
        var loginResponse = await client.SendAsync(loginRequest);

        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);
        
        // Assert that a cookie starting with "__Host-Vefa.CustomAuth.Session" is set
        var setCookie = Assert.Single(
            loginResponse.Headers.GetValues("Set-Cookie"), 
            value => value.StartsWith("__Host-Vefa.CustomAuth.Session=", StringComparison.Ordinal));
        
        var cookieValue = setCookie.Split('=', 2)[1].Split(';', 2)[0];
        
        // Assert that the cookie value is NOT a plain Guid
        Assert.False(Guid.TryParse(cookieValue, out _));

        // Use DataProtection to decrypt and assert the decrypted value is a valid Guid
        var dataProtection = app.Services.GetRequiredService<IDataProtectionProvider>();
        var protector = dataProtection.CreateProtector("Vefa.CustomAuth.SessionCookie");
        var decrypted = protector.Unprotect(cookieValue);
        Assert.True(Guid.TryParse(decrypted, out var sessionId));
        Assert.NotEqual(Guid.Empty, sessionId);

        // Also assert that the cookie contains Path=/ and Secure
        Assert.Contains("path=/", setCookie.ToLowerInvariant());
        Assert.Contains("secure", setCookie.ToLowerInvariant());
    }

    [Fact]
    public async Task SessionCookieHardening_ShouldSupportFallbackNameForHttp()
    {
        await using var app = await CreateAppAsync(opts =>
        {
            opts.RequireHttps = false; // Disable HTTPS requirement (development mode)
        });
        using var client = app.GetTestClient();

        // Sign in to get the cookie
        var antiforgery = await AntiforgeryTestHelpers.GetAntiforgeryAsync(client);
        using var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["userName"] = "demo",
                ["password"] = "demo",
                ["returnUrl"] = "/connect/authorize?client_id=test-client&redirect_uri=" 
                    + Uri.EscapeDataString("http://localhost/signin-oidc") 
                    + "&response_type=code&scope=openid&code_challenge=xyz&code_challenge_method=S256",
                [antiforgery.FormFieldName] = antiforgery.RequestToken,
            }),
        };
        loginRequest.Headers.Add("Cookie", antiforgery.Cookie);
        var loginResponse = await client.SendAsync(loginRequest);

        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);

        // Assert that a cookie starting with ".Vefa.CustomAuth.Session" is set
        var setCookie = Assert.Single(
            loginResponse.Headers.GetValues("Set-Cookie"), 
            value => value.StartsWith(".Vefa.CustomAuth.Session=", StringComparison.Ordinal));
        
        var cookieValue = setCookie.Split('=', 2)[1].Split(';', 2)[0];
        
        // Assert that the cookie contains Path=/ but NOT Secure (since RequireHttps is false)
        Assert.Contains("path=/", setCookie.ToLowerInvariant());
        Assert.DoesNotContain("secure", setCookie.ToLowerInvariant());
    }

    [Fact]
    public async Task ClientCreation_ShouldRejectInsecureRedirectUris()
    {
        await using var app = await CreateAppAsync();
        var clientManager = app.Services.GetRequiredService<ICustomAuthClientManager>();

        var client = new CustomAuthClient
        {
            ClientId = "insecure-app",
            DisplayName = "Insecure Application",
            RedirectUris = new List<string> { "http://example.com/cb" },
            AllowedScopes = new List<string> { "openid" }
        };

        var exception = await Assert.ThrowsAsync<ArgumentException>(() => clientManager.CreateAsync(client));
        Assert.Contains("Redirect URI 'http://example.com/cb' must use HTTPS unless it is a loopback address.", exception.Message);
    }

    [Fact]
    public async Task ClientCreation_ShouldRejectRedirectUrisWithFragments()
    {
        await using var app = await CreateAppAsync();
        var clientManager = app.Services.GetRequiredService<ICustomAuthClientManager>();

        var client = new CustomAuthClient
        {
            ClientId = "fragment-app",
            DisplayName = "Fragment Application",
            RedirectUris = new List<string> { "https://example.com/cb#token" },
            AllowedScopes = new List<string> { "openid" }
        };

        var exception = await Assert.ThrowsAsync<ArgumentException>(() => clientManager.CreateAsync(client));
        Assert.Contains("Redirect URI 'https://example.com/cb#token' must not contain a fragment.", exception.Message);
    }

    [Fact]
    public async Task ClientCreation_ShouldAllowSecureUrisAndLoopbacks()
    {
        await using var app = await CreateAppAsync();
        var clientManager = app.Services.GetRequiredService<ICustomAuthClientManager>();

        var client = new CustomAuthClient
        {
            ClientId = "valid-app",
            DisplayName = "Valid Application",
            RedirectUris = new List<string> 
            { 
                "https://secure-app.com/callback", 
                "http://localhost:5000/callback", 
                "http://127.0.0.1:3000/callback" 
            },
            AllowedScopes = new List<string> { "openid" },
            AllowRefreshTokens = false
        };

        // Should not throw, should succeed
        await clientManager.CreateAsync(client);
        
        var retrieved = await clientManager.FindByClientIdAsync("valid-app");
        Assert.NotNull(retrieved);
        Assert.Equal("Valid Application", retrieved!.DisplayName);
    }

    private static async Task<WebApplication> CreateAppAsync(
        Action<CustomAuthOptions>? configureOptions = null,
        Action<CustomAuthClient>? configureClient = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services
            .AddVefaCustomAuth(options =>
            {
                options.Issuer = "http://localhost";
                options.RequireHttps = false;
                configureOptions?.Invoke(options);
            })
            .AddJwtTokenSigning()
            .AddInMemoryStores(stores =>
            {
                var customAuthClient = new CustomAuthClient
                {
                    ClientId = ClientId,
                    DisplayName = "Test Client",
                    RedirectUris = { RedirectUri },
                    AllowedScopes = { "openid", "profile", "email", "offline_access" },
                };
                configureClient?.Invoke(customAuthClient);
                stores.Clients.Add(customAuthClient);

                stores.Users.Add(new InMemoryUserStore.SeedUser
                {
                    UserId = "user-1",
                    UserName = UserName,
                    Password = Password,
                    Email = "demo@example.com",
                });
            });

        var app = builder.Build();
        app.MapVefaCustomAuthEndpoints();

        await app.StartAsync();
        return app;
    }
}
