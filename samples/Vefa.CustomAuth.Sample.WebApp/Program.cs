using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect(options =>
    {
        options.Authority = "http://localhost:5175";
        options.RequireHttpsMetadata = false;
        options.ClientId = "sample-webapp";
        options.ResponseType = "code";
        options.ResponseMode = "query";
        options.UsePkce = true;
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = false;
        options.MapInboundClaims = false;
        options.CallbackPath = "/signin-oidc";
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("offline_access");
        options.Scope.Add("sample-api");
        options.TokenValidationParameters.NameClaimType = "name";
        options.ProtocolValidator.RequireNonce = false;
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

app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).ConfigureAwait(false);
    return Results.Redirect("/");
});

app.Run();
