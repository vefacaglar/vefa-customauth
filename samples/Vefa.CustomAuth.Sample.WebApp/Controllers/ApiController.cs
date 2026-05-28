using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Json;
using System.Text.Json;

namespace Vefa.CustomAuth.Sample.WebApp.Controllers;

[ApiController]
public class ApiController : ControllerBase
{
    private readonly IHttpClientFactory _httpClientFactory;

    public ApiController(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    [HttpGet("/login")]
    public IActionResult Login()
    {
        var properties = new AuthenticationProperties { RedirectUri = "/" };
        return Challenge(properties, OpenIdConnectDefaults.AuthenticationScheme);
    }

    [Authorize]
    [HttpGet("/api/test-api")]
    public async Task<IActionResult> TestApi()
    {
        var accessToken = await HttpContext.GetTokenAsync("access_token").ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return Unauthorized();
        }

        var client = _httpClientFactory.CreateClient("sample-api");
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        
        try
        {
            var apiResponse = await client.GetStringAsync("/weather").ConfigureAwait(false);
            var jsonDocument = JsonDocument.Parse(apiResponse);
            return Ok(jsonDocument);
        }
        catch (Exception ex)
        {
            return Problem(ex.Message);
        }
    }

    [Authorize]
    [HttpPost("/api/refresh")]
    public async Task<IActionResult> RefreshToken()
    {
        var refreshToken = await HttpContext.GetTokenAsync("refresh_token").ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return BadRequest("No refresh token found in current session.");
        }

        var authClient = _httpClientFactory.CreateClient("auth-server");
        
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = "sample-webapp"
        });

        var response = await authClient.PostAsync("/connect/token", tokenRequest).ConfigureAwait(false);
        
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            return BadRequest(error);
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(false);
        
        var authResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (authResult?.Succeeded == true)
        {
            authResult.Properties.UpdateTokenValue("access_token", tokenResponse.GetProperty("access_token").GetString()!);
            if (tokenResponse.TryGetProperty("refresh_token", out var newRefresh))
            {
                authResult.Properties.UpdateTokenValue("refresh_token", newRefresh.GetString()!);
            }
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, authResult.Principal, authResult.Properties);
        }
        
        return Ok(new 
        { 
            message = "Refresh successful! New tokens acquired and saved to session.",
            access_token_prefix = tokenResponse.GetProperty("access_token").GetString()?.Substring(0, 10) + "...",
            refresh_token_prefix = tokenResponse.TryGetProperty("refresh_token", out var rt) ? rt.GetString()?.Substring(0, 10) + "..." : "none"
        });
    }
}
