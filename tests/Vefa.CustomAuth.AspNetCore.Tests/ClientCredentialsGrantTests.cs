using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Vefa.CustomAuth.AspNetCore.Endpoints.Grants;
using Vefa.CustomAuth.AspNetCore.Extensions;
using Vefa.CustomAuth.AspNetCore.Stores.InMemory;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;

namespace Vefa.CustomAuth.AspNetCore.Tests;

public sealed class ClientCredentialsGrantTests
{
    private const string ConfidentialClientId = "cc-client";
    private const string DisabledClientId = "cc-disabled";
    private const string PublicClientId = "cc-public";
    private const string Issuer = "http://localhost";
    private const string TokenAudience = "http://localhost/connect/token";
    private const string AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private const string Kid = "kid-1";

    [Fact]
    public async Task DiscoveryAdvertisesClientCredentials()
    {
        using var rsa = RSA.Create(2048);
        await using var app = await CreateAppAsync(rsa);
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/.well-known/openid-configuration");
        using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());

        var grants = doc.RootElement.GetProperty("grant_types_supported")
            .EnumerateArray().Select(e => e.GetString()).ToArray();
        Assert.Contains("client_credentials", grants);
    }

    [Fact]
    public async Task SucceedsWithValidAssertionAndIssuesAccessTokenOnly()
    {
        using var rsa = RSA.Create(2048);
        await using var app = await CreateAppAsync(rsa);
        using var client = app.GetTestClient();

        var assertion = SignAssertion(rsa, ConfidentialClientId);
        using var response = await RequestTokenAsync(client, ConfidentialClientId, "api1 api2", assertion);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());

        using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var root = doc.RootElement;
        Assert.True(root.TryGetProperty("access_token", out _));
        Assert.Equal("Bearer", root.GetProperty("token_type").GetString());
        Assert.Equal("api1 api2", root.GetProperty("scope").GetString());
        Assert.False(root.TryGetProperty("id_token", out _));
        Assert.False(root.TryGetProperty("refresh_token", out _));

        var accessToken = root.GetProperty("access_token").GetString()!;
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(accessToken);
        Assert.True(jwt.TryGetPayloadValue<string>("sub", out var sub));
        Assert.Equal(ConfidentialClientId, sub);
        Assert.True(jwt.TryGetPayloadValue<string>("client_id", out var clientIdClaim));
        Assert.Equal(ConfidentialClientId, clientIdClaim);
    }

    [Fact]
    public async Task SucceedsWithoutScope()
    {
        using var rsa = RSA.Create(2048);
        await using var app = await CreateAppAsync(rsa);
        using var client = app.GetTestClient();

        var assertion = SignAssertion(rsa, ConfidentialClientId);
        using var response = await RequestTokenAsync(client, ConfidentialClientId, scope: null, assertion);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.True(doc.RootElement.TryGetProperty("access_token", out _));
    }

    [Fact]
    public async Task PublicClientIsRejected()
    {
        using var rsa = RSA.Create(2048);
        await using var app = await CreateAppAsync(rsa);
        using var client = app.GetTestClient();

        // A public client cannot present a private_key_jwt assertion; it is rejected before scope checks.
        using var response = await RequestTokenAsync(client, PublicClientId, "api1", assertion: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_client", await ReadJsonPropertyAsync(response, "error"));
    }

    [Fact]
    public async Task ClientWithoutAllowClientCredentialsIsRejected()
    {
        using var rsa = RSA.Create(2048);
        await using var app = await CreateAppAsync(rsa);
        using var client = app.GetTestClient();

        var assertion = SignAssertion(rsa, DisabledClientId);
        using var response = await RequestTokenAsync(client, DisabledClientId, "api1", assertion);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("unauthorized_client", await ReadJsonPropertyAsync(response, "error"));
    }

    [Fact]
    public async Task MissingAssertionIsRejected()
    {
        using var rsa = RSA.Create(2048);
        await using var app = await CreateAppAsync(rsa);
        using var client = app.GetTestClient();

        using var response = await RequestTokenAsync(client, ConfidentialClientId, "api1", assertion: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_client", await ReadJsonPropertyAsync(response, "error"));
    }

    [Fact]
    public async Task ScopeOutsideAllowedScopesIsRejected()
    {
        using var rsa = RSA.Create(2048);
        await using var app = await CreateAppAsync(rsa);
        using var client = app.GetTestClient();

        var assertion = SignAssertion(rsa, ConfidentialClientId);
        using var response = await RequestTokenAsync(client, ConfidentialClientId, "api1 forbidden", assertion);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_scope", await ReadJsonPropertyAsync(response, "error"));
    }

    [Fact]
    public async Task UnknownClientIsRejected()
    {
        using var rsa = RSA.Create(2048);
        await using var app = await CreateAppAsync(rsa);
        using var client = app.GetTestClient();

        var assertion = SignAssertion(rsa, "no-such-client");
        using var response = await RequestTokenAsync(client, "no-such-client", "api1", assertion);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_client", await ReadJsonPropertyAsync(response, "error"));
    }

    [Fact]
    public async Task CustomGrantHandlerIsDispatched()
    {
        using var rsa = RSA.Create(2048);
        await using var app = await CreateAppAsync(rsa, services => services.AddScoped<ICustomAuthGrantHandler, EchoGrantHandler>());
        using var client = app.GetTestClient();

        using var response = await client.PostAsync(
            "/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "urn:example:echo" }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("echo", await ReadJsonPropertyAsync(response, "grant"));
    }

    private static Task<HttpResponseMessage> RequestTokenAsync(HttpClient client, string clientId, string? scope, string? assertion)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
        };
        if (scope is not null)
        {
            form["scope"] = scope;
        }
        if (assertion is not null)
        {
            form["client_assertion_type"] = AssertionType;
            form["client_assertion"] = assertion;
        }

        return client.PostAsync("/connect/token", new FormUrlEncodedContent(form));
    }

    private static string BuildJwks(RSA rsa, string kid)
    {
        var p = rsa.ExportParameters(includePrivateParameters: false);
        var n = Base64UrlEncoder.Encode(p.Modulus);
        var e = Base64UrlEncoder.Encode(p.Exponent);
        return $"{{\"keys\":[{{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"{kid}\",\"n\":\"{n}\",\"e\":\"{e}\"}}]}}";
    }

    private static string SignAssertion(RSA rsa, string clientId)
    {
        var now = DateTime.UtcNow;
        var signingKey = new RsaSecurityKey(rsa) { KeyId = Kid };
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = TokenAudience,
            Claims = new Dictionary<string, object>
            {
                ["sub"] = clientId,
                ["jti"] = Guid.NewGuid().ToString("N"),
            },
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static async Task<WebApplication> CreateAppAsync(RSA rsa, Action<IServiceCollection>? configureServices = null)
    {
        var jwksJson = BuildJwks(rsa, Kid);
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
                    ClientId = ConfidentialClientId,
                    DisplayName = "Confidential M2M Client",
                    AllowedScopes = { "api1", "api2" },
                    AllowClientCredentials = true,
                    TokenEndpointAuthMethod = CustomAuthClientAuthenticationMethod.PrivateKeyJwt,
                    JwksJson = jwksJson,
                });

                stores.Clients.Add(new CustomAuthClient
                {
                    ClientId = DisabledClientId,
                    DisplayName = "Confidential Client Without Client Credentials",
                    AllowedScopes = { "api1" },
                    AllowClientCredentials = false,
                    TokenEndpointAuthMethod = CustomAuthClientAuthenticationMethod.PrivateKeyJwt,
                    JwksJson = jwksJson,
                });

                stores.Clients.Add(new CustomAuthClient
                {
                    ClientId = PublicClientId,
                    DisplayName = "Public Client",
                    AllowedScopes = { "api1" },
                    AllowClientCredentials = true,
                    TokenEndpointAuthMethod = CustomAuthClientAuthenticationMethod.None,
                });
            });

        configureServices?.Invoke(builder.Services);

        var app = builder.Build();
        app.MapCustomAuthEndpoints();
        await app.StartAsync();
        return app;
    }

    private static async Task<string> ReadJsonPropertyAsync(HttpResponseMessage response, string propertyName)
    {
        using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var value = document.RootElement.GetProperty(propertyName).GetString();
        Assert.NotNull(value);
        return value!;
    }

    private sealed class EchoGrantHandler : ICustomAuthGrantHandler
    {
        public string GrantType => "urn:example:echo";

        public Task<IResult> HandleAsync(IFormCollection form, CancellationToken cancellationToken = default)
            => Task.FromResult(Results.Json(new { grant = "echo" }));
    }
}
