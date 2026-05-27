using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
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

    private static async Task<WebApplication> CreateAppAsync(TimeProvider? timeProvider = null)
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

        if (timeProvider is not null)
        {
            builder.Services.Replace(ServiceDescriptor.Singleton(timeProvider));
        }

        var app = builder.Build();
        app.MapVefaCustomAuthEndpoints();
        await app.StartAsync();
        return app;
    }

    private static async Task<string> IssueAuthorizationCodeAsync(HttpClient client, string verifier)
    {
        var authorizeUrl = BuildAuthorizeUrl(verifier);
        var loginResponse = await client.PostAsync(
            "/login",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["userName"] = UserName,
                ["password"] = Password,
                ["returnUrl"] = authorizeUrl,
            }));

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

    private static string BuildAuthorizeUrl(string verifier, string redirectUri = RedirectUri)
    {
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return "/connect/authorize?client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(redirectUri)
            + "&response_type=code"
            + "&scope=" + Uri.EscapeDataString(Scope)
            + "&code_challenge=" + Uri.EscapeDataString(challenge)
            + "&code_challenge_method=S256"
            + "&state=test-state";
    }

    private static string CreateVerifier()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncoder.Encode(bytes.ToArray());
    }

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
