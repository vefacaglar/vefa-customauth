using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using System.Text.Json.Serialization;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

internal static class EndpointResults
{
    public static IResult OAuthError(string error, string? description = null, int statusCode = StatusCodes.Status400BadRequest)
        => new NoStoreJsonResult(new OAuthErrorResponse(error, description), statusCode);

    /// <summary>
    /// JSON response that sets the RFC 6749 §5.1 cache headers (Cache-Control: no-store, Pragma: no-cache)
    /// before writing the body. Use for token endpoint success responses.
    /// </summary>
    public static IResult NoStoreJson(object value, int statusCode = StatusCodes.Status200OK)
        => new NoStoreJsonResult(value, statusCode);

    private sealed class NoStoreJsonResult : IResult
    {
        private readonly object _value;
        private readonly int _statusCode;

        public NoStoreJsonResult(object value, int statusCode)
        {
            _value = value;
            _statusCode = statusCode;
        }

        public Task ExecuteAsync(HttpContext httpContext)
        {
            httpContext.Response.Headers["Cache-Control"] = "no-store";
            httpContext.Response.Headers["Pragma"] = "no-cache";
            return Results.Json(_value, statusCode: _statusCode).ExecuteAsync(httpContext);
        }
    }

    /// <summary>
    /// Returns an RFC 6749 §4.1.2.1 compliant authorization-error redirect.
    /// Use only after the redirect URI has been validated against the registered client.
    /// </summary>
    public static IResult OAuthAuthorizeRedirectError(string redirectUri, string error, string? description, string? state)
    {
        var values = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["error"] = error,
        };

        if (!string.IsNullOrEmpty(description))
        {
            values["error_description"] = description;
        }

        if (!string.IsNullOrEmpty(state))
        {
            values["state"] = state;
        }

        return Results.Redirect(QueryHelpers.AddQueryString(redirectUri, values));
    }

    private sealed class OAuthErrorResponse
    {
        public OAuthErrorResponse(string error, string? errorDescription)
        {
            Error = error;
            ErrorDescription = errorDescription;
        }

        [JsonPropertyName("error")]
        public string Error { get; }

        [JsonPropertyName("error_description")]
        public string? ErrorDescription { get; }
    }
}
