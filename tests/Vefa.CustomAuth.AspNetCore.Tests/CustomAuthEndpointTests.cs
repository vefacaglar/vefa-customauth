using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.Tokens;
using Vefa.CustomAuth.AspNetCore.Extensions;
using Vefa.CustomAuth.AspNetCore.Stores.InMemory;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Options;

namespace Vefa.CustomAuth.AspNetCore.Tests;

public sealed class CustomAuthEndpointTests
{
    private const string ClientId = "test-client";
    private const string RedirectUri = "http://localhost/signin-oidc";
    private const string Scope = "openid profile email offline_access test-api";
    private const string UserName = "demo";
    private const string Password = "demo";

    [Fact]
    public async Task AuthorizeRejectsInvalidRedirectUri()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var response = await client.GetAsync(BuildAuthorizeUrl(verifier, redirectUri: "http://localhost/bad"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", await ReadJsonPropertyAsync(response, "error"));
    }

    [Fact]
    public async Task AuthorizeRedirectsInvalidScopeBackToClient()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var response = await client.GetAsync(BuildAuthorizeUrl(verifier, scope: "openid bogus"));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location;
        Assert.NotNull(location);
        Assert.Equal(RedirectUri, location!.GetLeftPart(UriPartial.Path));
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("invalid_scope", query["error"].ToString());
        Assert.Equal("test-state", query["state"].ToString());
    }

    [Fact]
    public async Task AuthorizeRedirectsMissingPkceBackToClient()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var url = "/connect/authorize?client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(RedirectUri)
            + "&response_type=code"
            + "&scope=" + Uri.EscapeDataString(Scope)
            + "&state=test-state";
        var response = await client.GetAsync(url);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location;
        Assert.NotNull(location);
        Assert.Equal(RedirectUri, location!.GetLeftPart(UriPartial.Path));
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("invalid_request", query["error"].ToString());
        Assert.Equal("test-state", query["state"].ToString());
    }

    [Fact]
    public async Task TokenRejectsWrongPkceVerifier()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var code = await IssueAuthorizationCodeAsync(client, CreateVerifier());
        var response = await ExchangeCodeAsync(client, code, "wrong-verifier");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_grant", await ReadJsonPropertyAsync(response, "error"));
    }

    [Fact]
    public async Task AuthorizationCodeCanOnlyBeUsedOnce()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);

        var firstResponse = await ExchangeCodeAsync(client, code, verifier);
        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);

        var secondResponse = await ExchangeCodeAsync(client, code, verifier);
        Assert.Equal(HttpStatusCode.BadRequest, secondResponse.StatusCode);
        Assert.Equal("invalid_grant", await ReadJsonPropertyAsync(secondResponse, "error"));
    }

    [Fact]
    public async Task ExpiredAuthorizationCodeIsRejected()
    {
        var timeProvider = new ManualTimeProvider(new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero));
        await using var app = await CreateAppAsync(timeProvider);
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        timeProvider.Advance(TimeSpan.FromMinutes(3));

        var response = await ExchangeCodeAsync(client, code, verifier);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_grant", await ReadJsonPropertyAsync(response, "error"));
    }

    [Fact]
    public async Task RefreshTokenRotatesOnUse()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);
        var firstRefreshToken = await ReadJsonPropertyAsync(tokenResponse, "refresh_token");

        var refreshResponse = await ExchangeRefreshTokenAsync(client, firstRefreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);
        var secondRefreshToken = await ReadJsonPropertyAsync(refreshResponse, "refresh_token");
        Assert.NotEqual(firstRefreshToken, secondRefreshToken);

        var reuseResponse = await ExchangeRefreshTokenAsync(client, firstRefreshToken);
        Assert.Equal(HttpStatusCode.BadRequest, reuseResponse.StatusCode);
        Assert.Equal("invalid_grant", await ReadJsonPropertyAsync(reuseResponse, "error"));
    }

    [Fact]
    public async Task TokenResponseSetsNoStoreCacheHeaders()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var response = await ExchangeCodeAsync(client, code, verifier);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("no-store", response.Headers.CacheControl?.ToString() ?? string.Empty);
        Assert.Contains(response.Headers.Pragma, p => string.Equals(p.Name, "no-cache", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task LoginPostWithoutAntiforgeryTokenIsRejected()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var response = await client.PostAsync(
            "/login",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["userName"] = UserName,
                ["password"] = Password,
                ["returnUrl"] = "/",
            }));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("error=antiforgery_failed", response.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task ConcurrentCodeRedemptionLetsOnlyOneRequestSucceed()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);

        var responses = await Task.WhenAll(
            ExchangeCodeAsync(client, code, verifier),
            ExchangeCodeAsync(client, code, verifier),
            ExchangeCodeAsync(client, code, verifier),
            ExchangeCodeAsync(client, code, verifier),
            ExchangeCodeAsync(client, code, verifier));

        Assert.Equal(1, responses.Count(r => r.StatusCode == HttpStatusCode.OK));
        Assert.Equal(4, responses.Count(r => r.StatusCode == HttpStatusCode.BadRequest));
    }

    [Fact]
    public async Task IdTokenEchoesNonceFromAuthorizationRequest()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        const string expectedNonce = "n-0S6_WzA2Mj";
        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier, nonce: expectedNonce);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);

        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
        var idToken = await ReadJsonPropertyAsync(tokenResponse, "id_token");

        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(idToken);
        Assert.True(jwt.TryGetPayloadValue<string>("nonce", out var actualNonce));
        Assert.Equal(expectedNonce, actualNonce);
    }

    [Fact]
    public async Task IdTokenOmitsNonceClaimWhenNoNonceProvided()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);
        var idToken = await ReadJsonPropertyAsync(tokenResponse, "id_token");

        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(idToken);
        Assert.False(jwt.TryGetPayloadValue<string>("nonce", out _));
    }

    [Fact]
    public async Task AuthorizationCodeExchangeDoesNotIssueRefreshTokenWithoutOfflineAccessScope()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier, scope: "openid profile email test-api");
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);

        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
        using var document = await JsonDocument.ParseAsync(await tokenResponse.Content.ReadAsStreamAsync());
        Assert.False(document.RootElement.TryGetProperty("refresh_token", out _));
    }

    [Fact]
    public async Task ClientThatAllowsRefreshTokensMustAllowOfflineAccessScope()
    {
        await using var app = await CreateAppAsync();
        var clientManager = app.Services.GetRequiredService<ICustomAuthClientManager>();

        var exception = await Assert.ThrowsAsync<ArgumentException>(() =>
            clientManager.CreateAsync(new CustomAuthClient
            {
                ClientId = "bad-refresh-client",
                DisplayName = "Bad Refresh Client",
                RedirectUris = { RedirectUri },
                AllowedScopes = { "openid", "profile" },
                AllowRefreshTokens = true
            }));

        Assert.Contains("offline_access", exception.Message);
    }

    [Fact]
    public async Task RefreshTokenChainKeepsSessionParentAndAbsoluteExpiration()
    {
        var start = new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero);
        var timeProvider = new ManualTimeProvider(start);
        await using var app = await CreateAppAsync(
            timeProvider,
            configureClient: client =>
            {
                client.RefreshTokenLifetimeSeconds = 600;
                client.RefreshTokenAbsoluteLifetimeSeconds = 3600;
            });
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);
        var firstRefreshToken = await ReadJsonPropertyAsync(tokenResponse, "refresh_token");

        var refreshTokenStore = app.Services.GetRequiredService<ICustomAuthRefreshTokenStore>();
        var firstStoredToken = await refreshTokenStore.FindByHashAsync(TokenHasher.Hash(firstRefreshToken));
        Assert.NotNull(firstStoredToken);
        Assert.NotNull(firstStoredToken!.SessionId);
        Assert.Null(firstStoredToken.ParentTokenId);
        Assert.Equal(start.AddMinutes(10), firstStoredToken.ExpiresAt);
        Assert.Equal(start.AddHours(1), firstStoredToken.AbsoluteExpiresAt);

        timeProvider.Advance(TimeSpan.FromMinutes(5));
        var refreshResponse = await ExchangeRefreshTokenAsync(client, firstRefreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);
        var secondRefreshToken = await ReadJsonPropertyAsync(refreshResponse, "refresh_token");

        var secondStoredToken = await refreshTokenStore.FindByHashAsync(TokenHasher.Hash(secondRefreshToken));
        Assert.NotNull(secondStoredToken);
        Assert.Equal(firstStoredToken.SessionId, secondStoredToken!.SessionId);
        Assert.Equal(firstStoredToken.Id, secondStoredToken.ParentTokenId);
        Assert.Equal(start.AddMinutes(15), secondStoredToken.ExpiresAt);
        Assert.Equal(firstStoredToken.AbsoluteExpiresAt, secondStoredToken.AbsoluteExpiresAt);
    }

    [Fact]
    public async Task RefreshTokenAbsoluteExpirationRejectsRotatedToken()
    {
        var start = new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero);
        var timeProvider = new ManualTimeProvider(start);
        await using var app = await CreateAppAsync(
            timeProvider,
            configureClient: client =>
            {
                client.RefreshTokenLifetimeSeconds = 600;
                client.RefreshTokenAbsoluteLifetimeSeconds = 600;
            });
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);
        var refreshToken = await ReadJsonPropertyAsync(tokenResponse, "refresh_token");

        timeProvider.Advance(TimeSpan.FromMinutes(10));
        var response = await ExchangeRefreshTokenAsync(client, refreshToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_grant", await ReadJsonPropertyAsync(response, "error"));
    }

    [Fact]
    public async Task ReusedRefreshTokenCreatesAuditLogAndRevokesSessionTokenChain()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);
        var firstRefreshToken = await ReadJsonPropertyAsync(tokenResponse, "refresh_token");

        var refreshResponse = await ExchangeRefreshTokenAsync(client, firstRefreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);
        var secondRefreshToken = await ReadJsonPropertyAsync(refreshResponse, "refresh_token");

        var reuseResponse = await ExchangeRefreshTokenAsync(client, firstRefreshToken);
        Assert.Equal(HttpStatusCode.BadRequest, reuseResponse.StatusCode);

        var refreshTokenStore = app.Services.GetRequiredService<ICustomAuthRefreshTokenStore>();
        var secondStoredToken = await refreshTokenStore.FindByHashAsync(TokenHasher.Hash(secondRefreshToken));
        Assert.NotNull(secondStoredToken);
        Assert.NotNull(secondStoredToken!.RevokedAt);

        var auditLogStore = app.Services.GetRequiredService<ICustomAuthAuditLogStore>();
        var auditLogs = await auditLogStore.GetPagedAsync(new CustomAuthPagedRequest { Page = 1, PageSize = 20 });
        Assert.Contains(auditLogs.Items, log => log.Action == "RefreshTokenReuseDetected");
    }

    [Fact]
    public async Task RevokedRefreshTokenIsRejected()
    {
        var timeProvider = new ManualTimeProvider(new DateTimeOffset(2026, 5, 28, 0, 0, 0, TimeSpan.Zero));
        await using var app = await CreateAppAsync(timeProvider);
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);
        var refreshToken = await ReadJsonPropertyAsync(tokenResponse, "refresh_token");

        var refreshTokenStore = app.Services.GetRequiredService<ICustomAuthRefreshTokenStore>();
        var storedRefreshToken = await refreshTokenStore.FindByHashAsync(TokenHasher.Hash(refreshToken));
        Assert.NotNull(storedRefreshToken);
        await refreshTokenStore.RevokeAsync(storedRefreshToken!.Id, timeProvider.GetUtcNow());

        var response = await ExchangeRefreshTokenAsync(client, refreshToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_grant", await ReadJsonPropertyAsync(response, "error"));
    }

    [Fact]
    public async Task IssuedAccessTokenHasValidSignatureIssuerAndAudience()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var accessToken = await IssueAccessTokenAsync(client);
        var validationResult = await ValidateAccessTokenAsync(client, accessToken, "http://localhost", ClientId);

        Assert.True(validationResult.IsValid, validationResult.Exception?.Message);
    }

    [Fact]
    public async Task IssuedAccessTokenRejectsWrongIssuerAndAudience()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var accessToken = await IssueAccessTokenAsync(client);
        var wrongIssuerResult = await ValidateAccessTokenAsync(client, accessToken, "http://wrong-issuer", ClientId);
        var wrongAudienceResult = await ValidateAccessTokenAsync(client, accessToken, "http://localhost", "wrong-audience");

        Assert.False(wrongIssuerResult.IsValid);
        Assert.False(wrongAudienceResult.IsValid);
    }

    [Fact]
    public async Task DiscoveryAndJwksExposeSigningMetadata()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var discoveryResponse = await client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, discoveryResponse.StatusCode);
        using var discovery = await JsonDocument.ParseAsync(await discoveryResponse.Content.ReadAsStreamAsync());
        Assert.Equal("http://localhost", discovery.RootElement.GetProperty("issuer").GetString());
        Assert.Equal("http://localhost/.well-known/jwks.json", discovery.RootElement.GetProperty("jwks_uri").GetString());

        var jwksResponse = await client.GetAsync("/.well-known/jwks.json");
        Assert.Equal(HttpStatusCode.OK, jwksResponse.StatusCode);
        using var jwks = await JsonDocument.ParseAsync(await jwksResponse.Content.ReadAsStreamAsync());
        var key = Assert.Single(jwks.RootElement.GetProperty("keys").EnumerateArray());
        Assert.Equal("RSA", key.GetProperty("kty").GetString());
        Assert.Equal("sig", key.GetProperty("use").GetString());
        Assert.Equal("RS256", key.GetProperty("alg").GetString());
    }

    [Fact]
    public async Task AuthorizeRejectsPlainPkceMethod()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var url = "/connect/authorize?client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(RedirectUri)
            + "&response_type=code"
            + "&scope=" + Uri.EscapeDataString(Scope)
            + "&code_challenge=" + Uri.EscapeDataString(challenge)
            + "&code_challenge_method=plain"
            + "&state=test-state";

        var response = await client.GetAsync(url);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location;
        Assert.NotNull(location);
        Assert.Equal(RedirectUri, location!.GetLeftPart(UriPartial.Path));
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("invalid_request", query["error"].ToString());
        Assert.Equal("Only S256 PKCE method is supported.", query["error_description"].ToString());
    }

    [Fact]
    public async Task TokenEndpointInvalidClientReturns401WithWwwAuthenticate()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var response = await client.PostAsync(
            "/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = "non-existent-client",
                ["redirect_uri"] = RedirectUri,
                ["code"] = "some-code",
                ["code_verifier"] = "some-verifier",
            }));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var authHeader = response.Headers.WwwAuthenticate.ToString();
        Assert.Equal("Basic realm=\"Vefa.CustomAuth\"", authHeader);
    }

    [Fact]
    public async Task RevocationEndpointInvalidClientReturns401WithWwwAuthenticate()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var response = await client.PostAsync(
            "/connect/revoke",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = "some-token",
                ["client_id"] = "non-existent-client",
            }));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var authHeader = response.Headers.WwwAuthenticate.ToString();
        Assert.Equal("Basic realm=\"Vefa.CustomAuth\"", authHeader);
    }

    [Fact]
    public async Task CustomHostLoginEndpointWorks()
    {
        // 1. Create app with MapDefaultLoginEndpoint = false
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services
            .AddCustomAuth(options =>
            {
                options.Issuer = "http://localhost";
                options.RequireHttps = false;
                options.MapDefaultLoginEndpoint = false; // Disable default /login POST
            })
            .AddJwtTokenSigning()
            .AddInMemoryStores(stores =>
            {
                stores.Clients.Add(new CustomAuthClient
                {
                    ClientId = ClientId,
                    DisplayName = "Test Client",
                    RedirectUris = { RedirectUri },
                    AllowedScopes = { "openid", "profile", "email", "offline_access", "test-api" },
                });
                stores.Users.Add(new InMemoryUserStore.SeedUser
                {
                    UserId = "user-1",
                    UserName = UserName,
                    Password = Password,
                    Email = "demo@example.com",
                });
            });

        await using var app = builder.Build();

        // 2. Map a custom host-side POST login endpoint that verifies credentials and calls SignInCustomAuthAsync
        app.MapPost("/login", async (HttpContext context, ICustomAuthUserStore userStore) =>
        {
            var form = await context.Request.ReadFormAsync();
            var user = await userStore.ValidateCredentialsAsync(form["userName"].ToString(), form["password"].ToString());
            if (user is not null)
            {
                // Call the SignInCustomAuthAsync extension method to simulate custom login page
                await context.SignInCustomAuthAsync(user.UserId);
                return Results.Redirect(form["returnUrl"].ToString());
            }
            return Results.BadRequest("Invalid credentials");
        });

        app.MapCustomAuthEndpoints();
        await app.StartAsync();

        using var client = app.GetTestClient();

        // 3. Perform authorization code flow
        var verifier = CreateVerifier();
        var authorizeUrl = BuildAuthorizeUrl(verifier);

        // POST to our custom host login endpoint
        using var loginResponse = await client.PostAsync(
            "/login",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["userName"] = UserName,
                ["password"] = Password,
                ["returnUrl"] = authorizeUrl,
            }));

        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);
        var cookie = GetCookie(loginResponse, ".Vefa.CustomAuth.Session");

        // Request /connect/authorize with the session cookie
        using var authorizeRequest = new HttpRequestMessage(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add("Cookie", cookie);
        var authorizeResponse = await client.SendAsync(authorizeRequest);

        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);
        var location = authorizeResponse.Headers.Location;
        Assert.NotNull(location);
        var code = QueryHelpers.ParseQuery(location!.Query)["code"].ToString();
        Assert.False(string.IsNullOrWhiteSpace(code));

        // Exchange code for tokens
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var accessToken = await ReadJsonPropertyAsync(tokenResponse, "access_token");
        Assert.False(string.IsNullOrWhiteSpace(accessToken));
    }

    private static async Task<WebApplication> CreateAppAsync(
        TimeProvider? timeProvider = null,
        Action<CustomAuthOptions>? configureOptions = null,
        Action<CustomAuthClient>? configureClient = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services
            .AddCustomAuth(options =>
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
                    AllowedScopes = { "openid", "profile", "email", "offline_access", "test-api" },
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

        if (timeProvider is not null)
        {
            builder.Services.Replace(ServiceDescriptor.Singleton(timeProvider));
        }

        var app = builder.Build();
        app.MapAntiforgeryStub();
        app.MapCustomAuthEndpoints();
        await app.StartAsync();
        return app;
    }

    private static async Task<string> IssueAuthorizationCodeAsync(HttpClient client, string verifier, string scope = Scope, string? nonce = null)
    {
        var authorizeUrl = BuildAuthorizeUrl(verifier, scope: scope, nonce: nonce);
        var antiforgery = await GetAntiforgeryAsync(client);

        using var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["userName"] = UserName,
                ["password"] = Password,
                ["returnUrl"] = authorizeUrl,
                [antiforgery.FormFieldName] = antiforgery.RequestToken,
            }),
        };
        loginRequest.Headers.Add("Cookie", antiforgery.Cookie);

        var loginResponse = await client.SendAsync(loginRequest);
        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);
        var cookie = GetCookie(loginResponse, ".Vefa.CustomAuth.Session");

        using var authorizeRequest = new HttpRequestMessage(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add("Cookie", cookie);
        var authorizeResponse = await client.SendAsync(authorizeRequest);

        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);
        var location = authorizeResponse.Headers.Location;
        Assert.NotNull(location);
        Assert.Equal(RedirectUri, location!.GetLeftPart(UriPartial.Path));
        var code = QueryHelpers.ParseQuery(location.Query)["code"].ToString();
        Assert.False(string.IsNullOrWhiteSpace(code));
        return code;
    }

    private static Task<HttpResponseMessage> ExchangeCodeAsync(HttpClient client, string code, string verifier)
        => client.PostAsync(
            "/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = ClientId,
                ["redirect_uri"] = RedirectUri,
                ["code"] = code,
                ["code_verifier"] = verifier,
            }));

    private static Task<HttpResponseMessage> ExchangeRefreshTokenAsync(HttpClient client, string refreshToken)
        => client.PostAsync(
            "/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = ClientId,
                ["refresh_token"] = refreshToken,
            }));

    private static async Task<string> IssueAccessTokenAsync(HttpClient client)
    {
        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);
        return await ReadJsonPropertyAsync(tokenResponse, "access_token");
    }

    private static async Task<TokenValidationResult> ValidateAccessTokenAsync(
        HttpClient client,
        string accessToken,
        string validIssuer,
        string validAudience)
    {
        var jwksResponse = await client.GetAsync("/.well-known/jwks.json");
        var jwksJson = await jwksResponse.Content.ReadAsStringAsync();
        var jwks = new JsonWebKeySet(jwksJson);
        var handler = new JsonWebTokenHandler();

        return await handler.ValidateTokenAsync(
            accessToken,
            new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = validIssuer,
                ValidateAudience = true,
                ValidAudience = validAudience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = jwks.Keys,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
            });
    }

    private static string BuildAuthorizeUrl(string verifier, string redirectUri = RedirectUri, string scope = Scope, string? nonce = null)
    {
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var url = "/connect/authorize?client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(redirectUri)
            + "&response_type=code"
            + "&scope=" + Uri.EscapeDataString(scope)
            + "&code_challenge=" + Uri.EscapeDataString(challenge)
            + "&code_challenge_method=S256"
            + "&state=test-state";
        if (!string.IsNullOrEmpty(nonce))
        {
            url += "&nonce=" + Uri.EscapeDataString(nonce);
        }

        return url;
    }

    private static string CreateVerifier()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncoder.Encode(bytes.ToArray());
    }

    private static Task<AntiforgeryTokens> GetAntiforgeryAsync(HttpClient client)
        => AntiforgeryTestHelpers.GetAntiforgeryAsync(client);

    private static string GetCookie(HttpResponseMessage response, string cookieName)
    {
        var setCookie = Assert.Single(response.Headers.GetValues("Set-Cookie"), value => value.StartsWith(cookieName + "=", StringComparison.Ordinal));
        return setCookie.Split(';', 2)[0];
    }

    private static async Task<string> ReadJsonPropertyAsync(HttpResponseMessage response, string propertyName)
    {
        using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var value = document.RootElement.GetProperty(propertyName).GetString();
        Assert.NotNull(value);
        return value!;
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _utcNow;

        public ManualTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan value)
        {
            _utcNow = _utcNow.Add(value);
        }
    }
}
