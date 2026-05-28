using Microsoft.AspNetCore.Authentication;
using Vefa.CustomAuth.AspNetCore.Client;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCustomAuthClient(options =>
{
    options.Authority = "http://localhost:5175";
    options.ClientId = "sample-webapp";
    options.RequireHttpsMetadata = false;
    options.AdditionalScopes.Add("sample-api");
    options.RequireNonce = false;
});

builder.Services.AddAuthorization();
builder.Services.AddHttpClient("sample-api", client =>
{
    client.BaseAddress = new Uri("http://localhost:5098");
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", async (HttpContext context, IHttpClientFactory httpClientFactory) =>
{
    var accessToken = await context.GetTokenAsync("access_token").ConfigureAwait(false);
    if (string.IsNullOrWhiteSpace(accessToken))
    {
        return Results.Content("Signed in, but no access token was issued.", "text/plain");
    }

    var client = httpClientFactory.CreateClient("sample-api");
    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
    var apiResponse = await client.GetStringAsync("/weather").ConfigureAwait(false);

    return Results.Content($"Signed in as {context.User.Identity?.Name ?? context.User.FindFirst("sub")?.Value}.\nAPI response: {apiResponse}", "text/plain");
}).RequireAuthorization();

app.MapCustomAuthSignOut("/logout");

app.Run();
