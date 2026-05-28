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
        string? accessToken = null;

        // 1. Extract Bearer token from Authorization header or POST form body
        if (request.Headers.TryGetValue("Authorization", out var authHeaderValue)
            && AuthenticationHeaderValue.TryParse(authHeaderValue, out var header)
            && string.Equals(header.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(header.Parameter))
        {
            accessToken = header.Parameter;
        }
        else if (string.Equals(request.Method, HttpMethods.Post, StringComparison.OrdinalIgnoreCase)
                 && request.HasFormContentType)
        {
            var form = await request.ReadFormAsync(cancellationToken).ConfigureAwait(false);
            accessToken = form["access_token"].ToString();
        }

        if (string.IsNullOrWhiteSpace(accessToken))
        {
            context.Response.Headers.Append("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"Missing or malformed access token.\"");
            return Results.Unauthorized();
        }

        // 2. Validate token signature and lifetime
        string? userId = null;
        string? scopeClaim = null;
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
                    ValidateAudience = false, // audience validation is skipped in UserInfo per spec defaults
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
            scopeClaim = validationResult.ClaimsIdentity.FindFirst("scope")?.Value;
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

        // 4. Build standard OIDC UserInfo response claims filtered by scope
        var scopes = (scopeClaim ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var responseClaims = new Dictionary<string, object>
        {
            ["sub"] = user.UserId,
        };

        if (scopes.Contains("profile"))
        {
            if (!string.IsNullOrWhiteSpace(user.UserName))
            {
                responseClaims["name"] = user.UserName;
                responseClaims["preferred_username"] = user.UserName;
            }
        }

        if (scopes.Contains("email"))
        {
            if (!string.IsNullOrWhiteSpace(user.Email))
            {
                responseClaims["email"] = user.Email;
            }
        }

        // Standard OIDC claim names mapping to scopes
        var profileClaims = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "name", "given_name", "family_name", "middle_name", "nickname", 
            "preferred_username", "profile", "picture", "website", "gender", 
            "birthdate", "zoneinfo", "locale", "updated_at"
        };

        var emailClaims = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "email", "email_verified"
        };

        var phoneClaims = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "phone_number", "phone_number_verified"
        };

        var addressClaims = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "address"
        };

        if (user.AdditionalClaims is not null)
        {
            foreach (var (key, value) in user.AdditionalClaims)
            {
                if (responseClaims.ContainsKey(key))
                {
                    continue;
                }

                if (profileClaims.Contains(key))
                {
                    if (scopes.Contains("profile"))
                    {
                        responseClaims[key] = value;
                    }
                }
                else if (emailClaims.Contains(key))
                {
                    if (scopes.Contains("email"))
                    {
                        responseClaims[key] = value;
                    }
                }
                else if (phoneClaims.Contains(key))
                {
                    if (scopes.Contains("phone"))
                    {
                        responseClaims[key] = value;
                    }
                }
                else if (addressClaims.Contains(key))
                {
                    if (scopes.Contains("address"))
                    {
                        responseClaims[key] = value;
                    }
                }
                else
                {
                    // Non-standard custom claims are returned by default
                    responseClaims[key] = value;
                }
            }
        }

        return Results.Json(responseClaims);
    }
}
