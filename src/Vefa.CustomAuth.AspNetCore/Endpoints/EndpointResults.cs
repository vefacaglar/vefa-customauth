using Microsoft.AspNetCore.Http;
using System.Text.Json.Serialization;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

internal static class EndpointResults
{
    public static IResult OAuthError(string error, string? description = null, int statusCode = StatusCodes.Status400BadRequest)
        => Results.Json(new OAuthErrorResponse(error, description), statusCode: statusCode);

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
