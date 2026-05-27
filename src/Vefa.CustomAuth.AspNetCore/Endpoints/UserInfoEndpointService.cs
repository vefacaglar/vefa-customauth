using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net.Http.Headers;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.Tokens.Signing;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

internal sealed class UserInfoEndpointService
{
    private readonly ICustomAuthUserStore _userStore;
    private readonly ISigningCredentialsProvider _signingCredentialsProvider;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;

    public UserInfoEndpointService(
        ICustomAuthUserStore userStore,
        ISigningCredentialsProvider signingCredentialsProvider,
        IOptionsMonitor<CustomAuthOptions> options)
    {
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        _signingCredentialsProvider = signingCredentialsProvider ?? throw new ArgumentNullException(nameof(signingCredentialsProvider));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var request = context.Request;

        // 1. Extract Bearer token from Authorization header
        if (!request.Headers.TryGetValue("Authorization", out var authHeaderValue)
            || !AuthenticationHeaderValue.TryParse(authHeaderValue, out var header)
            || !string.Equals(header.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(header.Parameter))
        {
            context.Response.Headers.Append("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"Missing or malformed Authorization header.\"");
            return Results.Unauthorized();
        }

        var accessToken = header.Parameter;

        // 2. Validate token signature and lifetime
        string? userId = null;
        try
        {
            var jwks = await _signingCredentialsProvider.GetJsonWebKeySetAsync(cancellationToken).ConfigureAwait(false);
            var handler = new JsonWebTokenHandler();
            var validationResult = await handler.ValidateTokenAsync(
                accessToken,
                new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = _options.CurrentValue.Issuer,
                    ValidateAudience = false, // audience validation is skipped or checked if strict
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = jwks,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(5),
                }).ConfigureAwait(false);

            if (!validationResult.IsValid)
            {
                var errorDesc = validationResult.Exception?.Message ?? "Token validation failed.";
                context.Response.Headers.Append("WWW-Authenticate", $"Bearer error=\"invalid_token\", error_description=\"{errorDesc}\"");
                return Results.Unauthorized();
            }

            userId = validationResult.ClaimsIdentity.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        }
        catch (Exception ex)
        {
            context.Response.Headers.Append("WWW-Authenticate", $"Bearer error=\"invalid_token\", error_description=\"{ex.Message}\"");
            return Results.Unauthorized();
        }

        if (string.IsNullOrWhiteSpace(userId))
        {
            context.Response.Headers.Append("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"Subject (sub) claim not found in token.\"");
            return Results.Unauthorized();
        }

        // 3. Resolve user details from user store
        var user = await _userStore.FindByIdAsync(userId, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            context.Response.Headers.Append("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"User associated with token not found.\"");
            return Results.Unauthorized();
        }

        // 4. Build standard OIDC UserInfo response claims
        var responseClaims = new Dictionary<string, object>
        {
            ["sub"] = user.UserId,
        };

        if (!string.IsNullOrWhiteSpace(user.UserName))
        {
            responseClaims["name"] = user.UserName;
            responseClaims["preferred_username"] = user.UserName;
        }

        if (!string.IsNullOrWhiteSpace(user.Email))
        {
            responseClaims["email"] = user.Email;
        }

        if (user.AdditionalClaims is not null)
        {
            foreach (var (key, value) in user.AdditionalClaims)
            {
                if (!responseClaims.ContainsKey(key))
                {
                    responseClaims[key] = value;
                }
            }
        }

        return Results.Json(responseClaims);
    }
}
