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
using Vefa.CustomAuth.AspNetCore.Extensions;
using Vefa.CustomAuth.AspNetCore.Stores.InMemory;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.Tokens;

namespace Vefa.CustomAuth.AspNetCore.Tests;

public sealed class V02EndpointTests
{
    private const string ClientId = "test-client";
    private const string RedirectUri = "http://localhost/signin-oidc";
    private const string PostLogoutRedirectUri = "http://localhost/signout-callback-oidc";
    private const string Scope = "openid profile email offline_access test-api";
    private const string UserName = "demo";
    private const string Password = "demo";

    [Fact]
    public async Task LogoutClearsCookieAndRevokesSession()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // 1. Sign in to obtain session cookie
        var verifier = CreateVerifier();
        var authorizeUrl = BuildAuthorizeUrl(verifier);
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

        // 2. Perform logout
        using var logoutRequest = new HttpRequestMessage(HttpMethod.Get, "/connect/logout");
        logoutRequest.Headers.Add("Cookie", cookie);
        var logoutResponse = await client.SendAsync(logoutRequest);

        Assert.Equal(HttpStatusCode.OK, logoutResponse.StatusCode);
        var responseHtml = await logoutResponse.Content.ReadAsStringAsync();
        Assert.Contains("Logged Out Successfully", responseHtml);

        // 3. Verify cookie is cleared in response
        var setCookieHeaders = logoutResponse.Headers.GetValues("Set-Cookie");
        Assert.Contains(setCookieHeaders, h => h.Contains(".Vefa.CustomAuth.Session=;") || h.Contains(".Vefa.CustomAuth.Session= "));

        // 4. Verify session is revoked in database
        var sessionStore = app.Services.GetRequiredService<ICustomAuthSessionStore>();
        var sessionId = Guid.Parse(cookie.Split('=', 2)[1].Split(';', 2)[0]);
        var session = await sessionStore.FindAsync(sessionId);
        Assert.NotNull(session);
        Assert.NotNull(session!.RevokedAt);
    }

    [Fact]
    public async Task LogoutWithValidRedirectUriRedirects()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // 1. Sign in and exchange code to get ID token
        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);
        var idToken = await ReadJsonPropertyAsync(tokenResponse, "id_token");

        // 2. Send logout with valid id_token_hint and post_logout_redirect_uri
        var logoutUrl = "/connect/logout?id_token_hint=" + Uri.EscapeDataString(idToken)
            + "&post_logout_redirect_uri=" + Uri.EscapeDataString(PostLogoutRedirectUri)
            + "&state=logout-state";

        var response = await client.GetAsync(logoutUrl);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location;
        Assert.NotNull(location);
        Assert.Equal(PostLogoutRedirectUri, location!.GetLeftPart(UriPartial.Path));
        Assert.Equal("logout-state", QueryHelpers.ParseQuery(location.Query)["state"].ToString());
    }

    [Fact]
    public async Task LogoutWithInvalidRedirectUriDisplaysConfirmation()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);
        var idToken = await ReadJsonPropertyAsync(tokenResponse, "id_token");

        // Invalid redirect URI
        var logoutUrl = "/connect/logout?id_token_hint=" + Uri.EscapeDataString(idToken)
            + "&post_logout_redirect_uri=" + Uri.EscapeDataString("http://localhost/bad-callback")
            + "&state=logout-state";

        var response = await client.GetAsync(logoutUrl);

        // Should NOT redirect, should display HTML page instead
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var responseHtml = await response.Content.ReadAsStringAsync();
        Assert.Contains("Logged Out Successfully", responseHtml);
    }

    [Fact]
    public async Task UserInfoReturnsProfileWithValidAccessToken()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // 1. Obtain access token
        var accessToken = await IssueAccessTokenAsync(client);

        // 2. Send userinfo request with Bearer token
        using var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var profile = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Equal("user-1", profile.RootElement.GetProperty("sub").GetString());
        Assert.Equal(UserName, profile.RootElement.GetProperty("name").GetString());
        Assert.Equal("demo@example.com", profile.RootElement.GetProperty("email").GetString());
        Assert.Equal("custom-val", profile.RootElement.GetProperty("custom-claim").GetString());
    }

    [Fact]
    public async Task UserInfoReturns401WithInvalidOrExpiredToken()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // 1. Without Auth Header
        var responseNoHeader = await client.GetAsync("/connect/userinfo");
        Assert.Equal(HttpStatusCode.Unauthorized, responseNoHeader.StatusCode);
        var authHeader = responseNoHeader.Headers.WwwAuthenticate.ToString();
        Assert.Contains("Bearer error=\"invalid_token\"", authHeader);

        // 2. With Bad/Invalid Token
        using var requestBadToken = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        requestBadToken.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "not-a-valid-token");
        var responseBadToken = await client.SendAsync(requestBadToken);
        Assert.Equal(HttpStatusCode.Unauthorized, responseBadToken.StatusCode);
        Assert.Contains("Bearer error=\"invalid_token\"", responseBadToken.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task RevokeActiveRefreshTokenSetsRevoked()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // 1. Exchange code to get refresh token
        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);
        var refreshToken = await ReadJsonPropertyAsync(tokenResponse, "refresh_token");

        // 2. Revoke the token
        var response = await client.PostAsync(
            "/connect/revoke",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = refreshToken,
                ["client_id"] = ClientId,
                ["token_type_hint"] = "refresh_token"
            }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // 3. Verify in store that it is revoked
        var refreshTokenStore = app.Services.GetRequiredService<ICustomAuthRefreshTokenStore>();
        var storedToken = await refreshTokenStore.FindByHashAsync(TokenHasher.Hash(refreshToken));
        Assert.NotNull(storedToken);
        Assert.NotNull(storedToken!.RevokedAt);
    }

    [Fact]
    public async Task RevokeInvalidOrAlreadyRevokedTokenReturns200()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var response = await client.PostAsync(
            "/connect/revoke",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = "some-random-opaque-value",
                ["client_id"] = ClientId,
            }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task RevokeWithoutClientIdReturns400()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var response = await client.PostAsync(
            "/connect/revoke",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = "some-token",
            }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var responseJson = await response.Content.ReadAsStringAsync();
        Assert.Contains("invalid_request", responseJson);
    }

    [Fact]
    public async Task RevokeWithInvalidClientIdReturns401()
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
        var responseJson = await response.Content.ReadAsStringAsync();
        Assert.Contains("invalid_client", responseJson);
    }

    [Fact]
    public async Task RevokeWithDifferentClientIdReturns400()
    {
        await using var app = await CreateAppAsync(services =>
        {
            var store = services.BuildServiceProvider().GetRequiredService<ICustomAuthClientStore>() as InMemoryClientStore;
            store?.StoreAsync(new CustomAuthClient
            {
                ClientId = "other-client",
                DisplayName = "Other Client",
                RedirectUris = { RedirectUri },
                AllowedScopes = { "openid" }
            }).GetAwaiter().GetResult();
        });
        using var client = app.GetTestClient();

        // 1. Exchange code to get refresh token for test-client
        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);
        var refreshToken = await ReadJsonPropertyAsync(tokenResponse, "refresh_token");

        // 2. Try to revoke it using 'other-client'
        var response = await client.PostAsync(
            "/connect/revoke",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = refreshToken,
                ["client_id"] = "other-client",
            }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var responseJson = await response.Content.ReadAsStringAsync();
        Assert.Contains("invalid_grant", responseJson);
    }

    [Fact]
    public async Task IdTokenContainsAtHash()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // 1. Obtain tokens
        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);

        var accessToken = await ReadJsonPropertyAsync(tokenResponse, "access_token");
        var idToken = await ReadJsonPropertyAsync(tokenResponse, "id_token");

        // 2. Decode ID token and check at_hash
        var handler = new JsonWebTokenHandler();
        var idJwt = handler.ReadJsonWebToken(idToken);

        Assert.True(idJwt.TryGetClaim("at_hash", out var atHashClaim));
        var atHash = atHashClaim.ToString();
        Assert.False(string.IsNullOrWhiteSpace(atHash));

        // 3. Recompute expected at_hash and verify
        using var sha256 = SHA256.Create();
        var tokenBytes = Encoding.ASCII.GetBytes(accessToken);
        var fullHash = sha256.ComputeHash(tokenBytes);
        var halfSize = fullHash.Length / 2;
        var halfHash = new byte[halfSize];
        Array.Copy(fullHash, halfHash, halfSize);
        var expectedAtHash = Base64UrlEncoder.Encode(halfHash);

        Assert.Equal(expectedAtHash, atHash);
    }

    private sealed class FakeLoginAttemptTracker : Core.Services.ICustomAuthLoginAttemptTracker
    {
        private int _failures;

        public Task<bool> IsBlockedAsync(string userName, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_failures >= 3);
        }

        public Task RecordSuccessAsync(string userName, CancellationToken cancellationToken = default)
        {
            _failures = 0;
            return Task.CompletedTask;
        }

        public Task RecordFailureAsync(string userName, CancellationToken cancellationToken = default)
        {
            _failures++;
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task LoginAttemptTrackerBlocksAndLockoutWorks()
    {
        var tracker = new FakeLoginAttemptTracker();
        await using var app = await CreateAppAsync(services =>
        {
            services.Replace(ServiceDescriptor.Scoped<Core.Services.ICustomAuthLoginAttemptTracker>(_ => tracker));
        });

        using var client = app.GetTestClient();

        // 1. Perform 3 failed login attempts
        var antiforgery = await GetAntiforgeryAsync(client);
        for (int i = 0; i < 3; i++)
        {
            using var failedRequest = new HttpRequestMessage(HttpMethod.Post, "/login")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["userName"] = UserName,
                    ["password"] = "wrong-password",
                    ["returnUrl"] = "/dashboard",
                    [antiforgery.FormFieldName] = antiforgery.RequestToken,
                }),
            };
            failedRequest.Headers.Add("Cookie", antiforgery.Cookie);
            var failedResponse = await client.SendAsync(failedRequest);
            Assert.Equal(HttpStatusCode.Unauthorized, failedResponse.StatusCode);
        }

        // 2. Perform a 4th attempt (which should be blocked even with correct password)
        using var blockedRequest = new HttpRequestMessage(HttpMethod.Post, "/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["userName"] = UserName,
                ["password"] = Password,
                ["returnUrl"] = "/dashboard",
                [antiforgery.FormFieldName] = antiforgery.RequestToken,
            }),
        };
        blockedRequest.Headers.Add("Cookie", antiforgery.Cookie);
        var blockedResponse = await client.SendAsync(blockedRequest);

        Assert.Equal(HttpStatusCode.Locked, blockedResponse.StatusCode);
        var content = await blockedResponse.Content.ReadAsStringAsync();
        Assert.Contains("This account is temporarily locked due to too many failed login attempts.", content);
    }

    private static async Task<WebApplication> CreateAppAsync(Action<IServiceCollection>? configureServices = null, Action<CustomAuthOptions>? configureOptions = null)
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
                stores.Clients.Add(new CustomAuthClient
                {
                    ClientId = ClientId,
                    DisplayName = "Test Client",
                    RedirectUris = { RedirectUri },
                    PostLogoutRedirectUris = { PostLogoutRedirectUri },
                    AllowedScopes = { "openid", "profile", "email", "offline_access", "test-api" },
                });

                stores.Users.Add(new InMemoryUserStore.SeedUser
                {
                    UserId = "user-1",
                    UserName = UserName,
                    Password = Password,
                    Email = "demo@example.com",
                    AdditionalClaims = new Dictionary<string, string>
                    {
                        ["custom-claim"] = "custom-val"
                    }
                });
            });

        configureServices?.Invoke(builder.Services);

        var app = builder.Build();
        app.MapVefaCustomAuthEndpoints();
        await app.StartAsync();
        return app;
    }

    private static async Task<string> IssueAuthorizationCodeAsync(HttpClient client, string verifier)
    {
        var authorizeUrl = BuildAuthorizeUrl(verifier);
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

    private static Task<AntiforgeryTokens> GetAntiforgeryAsync(HttpClient client)
        => AntiforgeryTestHelpers.GetAntiforgeryAsync(client);

    private static async Task<string> IssueAccessTokenAsync(HttpClient client)
    {
        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);
        return await ReadJsonPropertyAsync(tokenResponse, "access_token");
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
}
