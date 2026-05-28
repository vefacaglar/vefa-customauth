using System.Net;
using Microsoft.AspNetCore.DataProtection;
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

        // 2. GET /connect/logout without id_token_hint redirects the user to the
        //    host-owned LogoutPath (the library no longer renders confirmation HTML).
        using var logoutRequest = new HttpRequestMessage(HttpMethod.Get, "/connect/logout");
        logoutRequest.Headers.Add("Cookie", cookie);
        var logoutResponse = await client.SendAsync(logoutRequest);

        Assert.Equal(HttpStatusCode.Redirect, logoutResponse.StatusCode);
        Assert.NotNull(logoutResponse.Headers.Location);
        var logoutRedirect = logoutResponse.Headers.Location!.OriginalString;
        Assert.StartsWith("/logout", logoutRedirect);

        // No session work has been done yet — the user has only been redirected.
        var sessionStorePre = app.Services.GetRequiredService<ICustomAuthSessionStore>();
        var dataProtection = app.Services.GetRequiredService<IDataProtectionProvider>();
        var protector = dataProtection.CreateProtector("Vefa.CustomAuth.SessionCookie");
        var rawCookieValue = cookie.Split('=', 2)[1].Split(';', 2)[0];
        var decryptedSessionId = protector.Unprotect(rawCookieValue);
        var sessionId = Guid.Parse(decryptedSessionId);
        var preSession = await sessionStorePre.FindAsync(sessionId);
        Assert.NotNull(preSession);
        Assert.Null(preSession!.RevokedAt);

        // 3. Host's logout page posts back to /connect/logout once the user confirms.
        //    Reuse the antiforgery cookie+token issued earlier by the stub.
        using var postRequest = new HttpRequestMessage(HttpMethod.Post, "/connect/logout")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [antiforgery.FormFieldName] = antiforgery.RequestToken,
                ["post_logout_redirect_uri"] = "",
                ["state"] = "",
                ["client_id"] = "",
            }),
        };
        postRequest.Headers.Add("Cookie", $"{cookie}; {antiforgery.Cookie}");
        var postResponse = await client.SendAsync(postRequest);

        Assert.Equal(HttpStatusCode.Redirect, postResponse.StatusCode);
        Assert.Equal("/", postResponse.Headers.Location!.OriginalString);

        // 4. Verify cookie is cleared in response
        var setCookieHeaders = postResponse.Headers.GetValues("Set-Cookie");
        Assert.Contains(setCookieHeaders, h => h.Contains(".Vefa.CustomAuth.Session=;") || h.Contains(".Vefa.CustomAuth.Session= "));

        // 5. Verify session is revoked in database
        var sessionStore = app.Services.GetRequiredService<ICustomAuthSessionStore>();
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
    public async Task LogoutWithInvalidRedirectUriFallsBackToPostLogoutRedirectUri()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var tokenResponse = await ExchangeCodeAsync(client, code, verifier);
        var idToken = await ReadJsonPropertyAsync(tokenResponse, "id_token");

        // Invalid redirect URI (not registered for the client)
        var logoutUrl = "/connect/logout?id_token_hint=" + Uri.EscapeDataString(idToken)
            + "&post_logout_redirect_uri=" + Uri.EscapeDataString("http://localhost/bad-callback")
            + "&state=logout-state";

        var response = await client.GetAsync(logoutUrl);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/", response.Headers.Location!.OriginalString);
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
        await using var app = await CreateAppAsync(configureStores: stores =>
        {
            stores.Clients.Add(new CustomAuthClient
            {
                ClientId = "other-client",
                DisplayName = "Other Client",
                RedirectUris = { RedirectUri },
                AllowedScopes = { "openid" }
            });
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

        using var document = await JsonDocument.ParseAsync(await tokenResponse.Content.ReadAsStreamAsync());
        var accessToken = document.RootElement.GetProperty("access_token").GetString();
        var idToken = document.RootElement.GetProperty("id_token").GetString();

        Assert.NotNull(accessToken);
        Assert.NotNull(idToken);

        // 2. Decode ID token and check at_hash
        var handler = new JsonWebTokenHandler();
        var idJwt = handler.ReadJsonWebToken(idToken);

        Assert.True(idJwt.TryGetClaim("at_hash", out var atHashClaim));
        var atHash = atHashClaim.Value;
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

        // 1. Perform 3 failed login attempts — each redirects back to LoginPath
        //    with ?error=invalid_credentials so the host can render a message.
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
            Assert.Equal(HttpStatusCode.Redirect, failedResponse.StatusCode);
            Assert.Contains("error=invalid_credentials", failedResponse.Headers.Location!.OriginalString);
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

        Assert.Equal(HttpStatusCode.Redirect, blockedResponse.StatusCode);
        Assert.Contains("error=account_locked", blockedResponse.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task PromptNoneWithoutSessionReturnsLoginRequired()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var authorizeUrl = "/connect/authorize?client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(RedirectUri)
            + "&response_type=code"
            + "&scope=" + Uri.EscapeDataString(Scope)
            + "&code_challenge=" + Uri.EscapeDataString(challenge)
            + "&code_challenge_method=S256"
            + "&prompt=none"
            + "&state=test-state";

        var response = await client.GetAsync(authorizeUrl);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location;
        Assert.NotNull(location);
        Assert.Equal(RedirectUri, location!.GetLeftPart(UriPartial.Path));
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("login_required", query["error"].ToString());
        Assert.Equal("test-state", query["state"].ToString());
    }

    [Fact]
    public async Task PromptNoneCombinedWithLoginReturnsInvalidRequest()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var authorizeUrl = "/connect/authorize?client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(RedirectUri)
            + "&response_type=code"
            + "&scope=" + Uri.EscapeDataString(Scope)
            + "&code_challenge=" + Uri.EscapeDataString(challenge)
            + "&code_challenge_method=S256"
            + "&prompt=none%20login"
            + "&state=test-state";

        var response = await client.GetAsync(authorizeUrl);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location;
        Assert.NotNull(location);
        Assert.Equal(RedirectUri, location!.GetLeftPart(UriPartial.Path));
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("invalid_request", query["error"].ToString());
    }

    [Fact]
    public async Task PromptNoneWithSessionSucceeds()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // 1. Sign in to get session cookie
        var verifier = CreateVerifier();
        var cookie = await GetSessionCookieAsync(client, verifier);

        // 2. Call authorize with prompt=none
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var authorizeUrl = "/connect/authorize?client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(RedirectUri)
            + "&response_type=code"
            + "&scope=" + Uri.EscapeDataString(Scope)
            + "&code_challenge=" + Uri.EscapeDataString(challenge)
            + "&code_challenge_method=S256"
            + "&prompt=none"
            + "&state=test-state";

        using var authorizeRequest = new HttpRequestMessage(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add("Cookie", cookie);
        var response = await client.SendAsync(authorizeRequest);
        
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location;
        Assert.NotNull(location);
        
        var path = location!.IsAbsoluteUri ? location.GetLeftPart(UriPartial.Path) : location.OriginalString.Split('?')[0];
        Assert.Equal(RedirectUri, path);
        
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.False(string.IsNullOrWhiteSpace(query["code"].ToString()));
        Assert.Equal("test-state", query["state"].ToString());
    }

    [Fact]
    public async Task PromptLoginForcesReauth()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // 1. Sign in to establish active session
        var verifier = CreateVerifier();
        var cookie = await GetSessionCookieAsync(client, verifier);

        // 2. Send authorize with prompt=login
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var authorizeUrl = "/connect/authorize?client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(RedirectUri)
            + "&response_type=code"
            + "&scope=" + Uri.EscapeDataString(Scope)
            + "&code_challenge=" + Uri.EscapeDataString(challenge)
            + "&code_challenge_method=S256"
            + "&prompt=login"
            + "&state=test-state";

        using var authorizeRequest = new HttpRequestMessage(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add("Cookie", cookie);
        var response = await client.SendAsync(authorizeRequest);
        
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location;
        Assert.NotNull(location);
        
        var path = location!.IsAbsoluteUri ? location.GetLeftPart(UriPartial.Path) : location.OriginalString.Split('?')[0];
        Assert.Equal("/login", path);
        
        var queryString = location.IsAbsoluteUri ? location.Query : (location.OriginalString.Contains('?') ? location.OriginalString.Substring(location.OriginalString.IndexOf('?')) : string.Empty);
        var query = QueryHelpers.ParseQuery(queryString);
        var returnUrl = query["returnUrl"].ToString();
        Assert.Contains("/connect/authorize", returnUrl);
        Assert.DoesNotContain("prompt=login", returnUrl);
    }

    [Fact]
    public async Task MaxAgeForcesReauth()
    {
        var timeProvider = new TestTimeProvider();
        await using var app = await CreateAppAsync(services =>
        {
            services.Replace(ServiceDescriptor.Singleton<TimeProvider>(timeProvider));
        });
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var cookie = await GetSessionCookieAsync(client, verifier);

        // Fast-forward time past max_age of 10 seconds
        timeProvider.Advance(TimeSpan.FromSeconds(15));

        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var authorizeUrl = "/connect/authorize?client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(RedirectUri)
            + "&response_type=code"
            + "&scope=" + Uri.EscapeDataString(Scope)
            + "&code_challenge=" + Uri.EscapeDataString(challenge)
            + "&code_challenge_method=S256"
            + "&max_age=10"
            + "&state=test-state";

        using var authorizeRequest = new HttpRequestMessage(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add("Cookie", cookie);
        var response = await client.SendAsync(authorizeRequest);
        
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location;
        Assert.NotNull(location);
        
        var path = location!.IsAbsoluteUri ? location.GetLeftPart(UriPartial.Path) : location.OriginalString.Split('?')[0];
        Assert.Equal("/login", path);
    }

    [Fact]
    public async Task MaxAgeWithinLimitSucceeds()
    {
        var timeProvider = new TestTimeProvider();
        await using var app = await CreateAppAsync(services =>
        {
            services.Replace(ServiceDescriptor.Singleton<TimeProvider>(timeProvider));
        });
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var cookie = await GetSessionCookieAsync(client, verifier);

        // Advance time slightly, well within max_age limit of 10s
        timeProvider.Advance(TimeSpan.FromSeconds(2));

        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var authorizeUrl = "/connect/authorize?client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(RedirectUri)
            + "&response_type=code"
            + "&scope=" + Uri.EscapeDataString(Scope)
            + "&code_challenge=" + Uri.EscapeDataString(challenge)
            + "&code_challenge_method=S256"
            + "&max_age=10"
            + "&state=test-state";

        using var authorizeRequest = new HttpRequestMessage(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add("Cookie", cookie);
        var response = await client.SendAsync(authorizeRequest);
        
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location;
        Assert.NotNull(location);
        
        var path = location!.IsAbsoluteUri ? location.GetLeftPart(UriPartial.Path) : location.OriginalString.Split('?')[0];
        Assert.Equal(RedirectUri, path);
        
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.False(string.IsNullOrWhiteSpace(query["code"].ToString()));
    }

    [Fact]
    public async Task UserInfoPostWithHeaderSucceeds()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var accessToken = await IssueAccessTokenAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var profile = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Equal("user-1", profile.RootElement.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task UserInfoPostWithBodySucceeds()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var accessToken = await IssueAccessTokenAsync(client);

        var response = await client.PostAsync(
            "/connect/userinfo",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["access_token"] = accessToken
            }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var profile = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Equal("user-1", profile.RootElement.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task UserInfoFiltersClaimsByScope()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        // 1. Token with openid scope only -> expect sub only
        var verifier1 = CreateVerifier();
        var challenge1 = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier1)));
        var authorizeUrl1 = "/connect/authorize?client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(RedirectUri)
            + "&response_type=code"
            + "&scope=openid"
            + "&code_challenge=" + Uri.EscapeDataString(challenge1)
            + "&code_challenge_method=S256"
            + "&state=test-state";

        var antiforgery = await GetAntiforgeryAsync(client);
        using (var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["userName"] = UserName,
                ["password"] = Password,
                ["returnUrl"] = authorizeUrl1,
                [antiforgery.FormFieldName] = antiforgery.RequestToken,
            }),
        })
        {
            loginRequest.Headers.Add("Cookie", antiforgery.Cookie);
            var loginResponse = await client.SendAsync(loginRequest);
            var cookie = GetCookie(loginResponse, ".Vefa.CustomAuth.Session");

            using var authorizeRequest = new HttpRequestMessage(HttpMethod.Get, authorizeUrl1);
            authorizeRequest.Headers.Add("Cookie", cookie);
            var authorizeResponse = await client.SendAsync(authorizeRequest);
            var location = authorizeResponse.Headers.Location;
            var code1 = QueryHelpers.ParseQuery(location!.Query)["code"].ToString();

            var tokenResponse1 = await ExchangeCodeAsync(client, code1, verifier1);
            using var doc1 = await JsonDocument.ParseAsync(await tokenResponse1.Content.ReadAsStreamAsync());
            var token1 = doc1.RootElement.GetProperty("access_token").GetString();

            using var req1 = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
            req1.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token1);
            var res1 = await client.SendAsync(req1);
            Assert.Equal(HttpStatusCode.OK, res1.StatusCode);
            
            using var docInfo1 = await JsonDocument.ParseAsync(await res1.Content.ReadAsStreamAsync());
            var elem1 = docInfo1.RootElement;
            Assert.True(elem1.TryGetProperty("sub", out _));
            Assert.False(elem1.TryGetProperty("name", out _));
            Assert.False(elem1.TryGetProperty("email", out _));
        }

        // 2. Token with openid and email -> expect sub and email
        var verifier2 = CreateVerifier();
        var challenge2 = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier2)));
        var authorizeUrl2 = "/connect/authorize?client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(RedirectUri)
            + "&response_type=code"
            + "&scope=openid%20email"
            + "&code_challenge=" + Uri.EscapeDataString(challenge2)
            + "&code_challenge_method=S256"
            + "&state=test-state";

        var antiforgery2 = await GetAntiforgeryAsync(client);
        using (var loginRequest2 = new HttpRequestMessage(HttpMethod.Post, "/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["userName"] = UserName,
                ["password"] = Password,
                ["returnUrl"] = authorizeUrl2,
                [antiforgery2.FormFieldName] = antiforgery2.RequestToken,
            }),
        })
        {
            loginRequest2.Headers.Add("Cookie", antiforgery2.Cookie);
            var loginResponse2 = await client.SendAsync(loginRequest2);
            var cookie2 = GetCookie(loginResponse2, ".Vefa.CustomAuth.Session");

            using var authorizeRequest2 = new HttpRequestMessage(HttpMethod.Get, authorizeUrl2);
            authorizeRequest2.Headers.Add("Cookie", cookie2);
            var authorizeResponse2 = await client.SendAsync(authorizeRequest2);
            var location2 = authorizeResponse2.Headers.Location;
            var code2 = QueryHelpers.ParseQuery(location2!.Query)["code"].ToString();

            var tokenResponse2 = await ExchangeCodeAsync(client, code2, verifier2);
            using var doc2 = await JsonDocument.ParseAsync(await tokenResponse2.Content.ReadAsStreamAsync());
            var token2 = doc2.RootElement.GetProperty("access_token").GetString();

            using var req2 = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
            req2.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token2);
            var res2 = await client.SendAsync(req2);
            Assert.Equal(HttpStatusCode.OK, res2.StatusCode);
            
            using var docInfo2 = await JsonDocument.ParseAsync(await res2.Content.ReadAsStreamAsync());
            var elem2 = docInfo2.RootElement;
            Assert.True(elem2.TryGetProperty("sub", out _));
            Assert.False(elem2.TryGetProperty("name", out _));
            Assert.True(elem2.TryGetProperty("email", out _));
        }
    }

    private static async Task<WebApplication> CreateAppAsync(
        Action<IServiceCollection>? configureServices = null, 
        Action<CustomAuthOptions>? configureOptions = null,
        Action<InMemoryStoresBuilder>? configureStores = null)
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

                configureStores?.Invoke(stores);
            });

        configureServices?.Invoke(builder.Services);

        var app = builder.Build();
        app.MapAntiforgeryStub();
        app.MapCustomAuthEndpoints();
        await app.StartAsync();
        return app;
    }

    private static async Task<string> GetSessionCookieAsync(HttpClient client, string verifier)
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
        return GetCookie(loginResponse, ".Vefa.CustomAuth.Session");
    }

    private static async Task<string> IssueAuthorizationCodeAsync(HttpClient client, string verifier)
    {
        var cookie = await GetSessionCookieAsync(client, verifier);
        var authorizeUrl = BuildAuthorizeUrl(verifier);

        using var authorizeRequest = new HttpRequestMessage(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add("Cookie", cookie);
        var authorizeResponse = await client.SendAsync(authorizeRequest);

        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);
        var location = authorizeResponse.Headers.Location;
        Assert.NotNull(location);
        
        var path = location!.IsAbsoluteUri ? location.GetLeftPart(UriPartial.Path) : location.OriginalString.Split('?')[0];
        Assert.Equal(RedirectUri, path);
        
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

    private sealed class TestTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan amount)
        {
            _now = _now.Add(amount);
        }
    }
}
