using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Vefa.CustomAuth.AspNetCore.Extensions;
using Vefa.CustomAuth.AspNetCore.Stores.InMemory;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Tokens.ClientAssertion;

namespace Vefa.CustomAuth.AspNetCore.Tests;

public sealed class PrivateKeyJwtClientAuthTests
{
    private const string ClientId = "confidential-client";
    private const string RedirectUri = "http://localhost/signin-oidc";
    private const string Scope = "openid profile email offline_access test-api";
    private const string UserName = "demo";
    private const string Password = "demo";
    private const string Issuer = "http://localhost";
    private const string TokenAudience = "http://localhost/connect/token";
    private const string AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    [Fact]
    public async Task DiscoveryAdvertisesPrivateKeyJwt()
    {
        using var rsa = RSA.Create(2048);
        await using var app = await CreateAppAsync(BuildJwks(rsa, "kid-1"));
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/.well-known/openid-configuration");
        using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());

        var methods = doc.RootElement.GetProperty("token_endpoint_auth_methods_supported")
            .EnumerateArray().Select(e => e.GetString()).ToArray();
        Assert.Contains("private_key_jwt", methods);
        Assert.True(doc.RootElement.TryGetProperty("token_endpoint_auth_signing_alg_values_supported", out _));
    }

    [Fact]
    public async Task CodeExchangeSucceedsWithValidAssertion()
    {
        using var rsa = RSA.Create(2048);
        await using var app = await CreateAppAsync(BuildJwks(rsa, "kid-1"));
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var assertion = SignAssertion(rsa, "kid-1", ClientId, TokenAudience, Guid.NewGuid().ToString("N"));

        using var response = await ExchangeCodeAsync(client, code, verifier, assertion);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task CodeExchangeFailsWithoutAssertion()
    {
        using var rsa = RSA.Create(2048);
        await using var app = await CreateAppAsync(BuildJwks(rsa, "kid-1"));
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);

        using var response = await ExchangeCodeAsync(client, code, verifier, assertion: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_client", await ReadJsonPropertyAsync(response, "error"));
    }

    [Fact]
    public async Task CodeExchangeFailsWithAssertionSignedByUnregisteredKey()
    {
        using var registeredRsa = RSA.Create(2048);
        using var attackerRsa = RSA.Create(2048);
        await using var app = await CreateAppAsync(BuildJwks(registeredRsa, "kid-1"));
        using var client = app.GetTestClient();

        var verifier = CreateVerifier();
        var code = await IssueAuthorizationCodeAsync(client, verifier);
        var forgedAssertion = SignAssertion(attackerRsa, "kid-1", ClientId, TokenAudience, Guid.NewGuid().ToString("N"));

        using var response = await ExchangeCodeAsync(client, code, verifier, forgedAssertion);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_client", await ReadJsonPropertyAsync(response, "error"));
    }

    [Fact]
    public async Task ReplayedAssertionJtiIsRejected()
    {
        using var rsa = RSA.Create(2048);
        await using var app = await CreateAppAsync(BuildJwks(rsa, "kid-1"));
        using var client = app.GetTestClient();

        var sharedJti = Guid.NewGuid().ToString("N");

        var firstVerifier = CreateVerifier();
        var firstCode = await IssueAuthorizationCodeAsync(client, firstVerifier);
        var firstAssertion = SignAssertion(rsa, "kid-1", ClientId, TokenAudience, sharedJti);
        using var firstResponse = await ExchangeCodeAsync(client, firstCode, firstVerifier, firstAssertion);
        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);

        var secondVerifier = CreateVerifier();
        var secondCode = await IssueAuthorizationCodeAsync(client, secondVerifier);
        var replayedAssertion = SignAssertion(rsa, "kid-1", ClientId, TokenAudience, sharedJti);
        using var secondResponse = await ExchangeCodeAsync(client, secondCode, secondVerifier, replayedAssertion);

        Assert.Equal(HttpStatusCode.Unauthorized, secondResponse.StatusCode);
        Assert.Equal("invalid_client", await ReadJsonPropertyAsync(secondResponse, "error"));
    }

    // --- Direct validator unit tests ---

    [Fact]
    public async Task ValidatorRejectsWrongAudience()
    {
        using var rsa = RSA.Create(2048);
        var validator = CreateValidator();
        var assertion = SignAssertion(rsa, "kid-1", ClientId, "http://wrong-audience", Guid.NewGuid().ToString("N"));

        var result = await validator.ValidateAsync(assertion, BuildJwks(rsa, "kid-1"), ClientId, new[] { Issuer, TokenAudience });

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task ValidatorRejectsExpiredAssertion()
    {
        using var rsa = RSA.Create(2048);
        var validator = CreateValidator();
        var expired = SignAssertion(rsa, "kid-1", ClientId, TokenAudience, Guid.NewGuid().ToString("N"),
            issuedAt: DateTime.UtcNow.AddMinutes(-30), expires: DateTime.UtcNow.AddMinutes(-20));

        var result = await validator.ValidateAsync(expired, BuildJwks(rsa, "kid-1"), ClientId, new[] { Issuer, TokenAudience });

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task ValidatorRejectsIssuerSubjectMismatch()
    {
        using var rsa = RSA.Create(2048);
        var validator = CreateValidator();
        var assertion = SignAssertion(rsa, "kid-1", ClientId, TokenAudience, Guid.NewGuid().ToString("N"), subject: "someone-else");

        var result = await validator.ValidateAsync(assertion, BuildJwks(rsa, "kid-1"), ClientId, new[] { Issuer, TokenAudience });

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task ValidatorRejectsMissingJti()
    {
        using var rsa = RSA.Create(2048);
        var validator = CreateValidator();
        var assertion = SignAssertion(rsa, "kid-1", ClientId, TokenAudience, jti: null);

        var result = await validator.ValidateAsync(assertion, BuildJwks(rsa, "kid-1"), ClientId, new[] { Issuer, TokenAudience });

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task ValidatorAcceptsValidAssertion()
    {
        using var rsa = RSA.Create(2048);
        var validator = CreateValidator();
        var jti = Guid.NewGuid().ToString("N");
        var assertion = SignAssertion(rsa, "kid-1", ClientId, TokenAudience, jti);

        var result = await validator.ValidateAsync(assertion, BuildJwks(rsa, "kid-1"), ClientId, new[] { Issuer, TokenAudience });

        Assert.True(result.Succeeded, result.FailureReason);
        Assert.Equal(ClientId, result.ClientId);
        Assert.Equal(jti, result.Jti);
    }

    private static ClientAssertionValidator CreateValidator()
        => new(new StaticOptionsMonitor<CustomAuthOptions>(new CustomAuthOptions { Issuer = Issuer }));

    private static string BuildJwks(RSA rsa, string kid)
    {
        var p = rsa.ExportParameters(includePrivateParameters: false);
        var n = Base64UrlEncoder.Encode(p.Modulus);
        var e = Base64UrlEncoder.Encode(p.Exponent);
        return $"{{\"keys\":[{{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"{kid}\",\"n\":\"{n}\",\"e\":\"{e}\"}}]}}";
    }

    private static string SignAssertion(
        RSA rsa,
        string kid,
        string issuer,
        string audience,
        string? jti,
        string? subject = null,
        DateTime? issuedAt = null,
        DateTime? expires = null)
    {
        var now = issuedAt ?? DateTime.UtcNow;
        var claims = new Dictionary<string, object>
        {
            ["sub"] = subject ?? issuer,
        };
        if (jti is not null)
        {
            claims["jti"] = jti;
        }

        var signingKey = new RsaSecurityKey(rsa) { KeyId = kid };
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Claims = claims,
            IssuedAt = now,
            NotBefore = now,
            Expires = expires ?? now.AddMinutes(5),
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static async Task<WebApplication> CreateAppAsync(string jwksJson)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services
            .AddCustomAuth(options =>
            {
                options.Issuer = Issuer;
                options.RequireHttps = false;
            })
            .AddJwtTokenSigning()
            .AddInMemoryStores(stores =>
            {
                stores.Clients.Add(new CustomAuthClient
                {
                    ClientId = ClientId,
                    DisplayName = "Confidential Client",
                    RedirectUris = { RedirectUri },
                    AllowedScopes = { "openid", "profile", "email", "offline_access", "test-api" },
                    TokenEndpointAuthMethod = CustomAuthClientAuthenticationMethod.PrivateKeyJwt,
                    JwksJson = jwksJson,
                });

                stores.Users.Add(new InMemoryUserStore.SeedUser
                {
                    UserId = "user-1",
                    UserName = UserName,
                    Password = Password,
                    Email = "demo@example.com",
                });
            });

        var app = builder.Build();
        app.MapAntiforgeryStub();
        app.MapCustomAuthEndpoints();
        await app.StartAsync();
        return app;
    }

    private static async Task<string> IssueAuthorizationCodeAsync(HttpClient client, string verifier)
    {
        var authorizeUrl = BuildAuthorizeUrl(verifier);
        var antiforgery = await AntiforgeryTestHelpers.GetAntiforgeryAsync(client);

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
        var code = QueryHelpers.ParseQuery(location!.Query)["code"].ToString();
        Assert.False(string.IsNullOrWhiteSpace(code));
        return code;
    }

    private static Task<HttpResponseMessage> ExchangeCodeAsync(HttpClient client, string code, string verifier, string? assertion)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = ClientId,
            ["redirect_uri"] = RedirectUri,
            ["code"] = code,
            ["code_verifier"] = verifier,
        };
        if (assertion is not null)
        {
            form["client_assertion_type"] = AssertionType;
            form["client_assertion"] = assertion;
        }

        return client.PostAsync("/connect/token", new FormUrlEncodedContent(form));
    }

    private static string BuildAuthorizeUrl(string verifier)
    {
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return "/connect/authorize?client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString(RedirectUri)
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

    private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
    {
        public StaticOptionsMonitor(T value) => CurrentValue = value;

        public T CurrentValue { get; }

        public T Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
