using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Vefa.CustomAuth.AdminUI.Extensions;
using Vefa.CustomAuth.AspNetCore.Extensions;
using Vefa.CustomAuth.AspNetCore.Stores.InMemory;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

var builder = WebApplication.CreateBuilder(args);

// Configure fixed local port
builder.WebHost.UseUrls("http://localhost:5220");

// Register in-memory host user store (demo / demo)
builder.Services.TryAddSingleton<ICustomAuthUserStore>(_ => new InMemoryUserStore(new[]
{
    new InMemoryUserStore.SeedUser
    {
        UserId = "user-1",
        UserName = "demo",
        Password = "demo",
        Email = "demo@example.com",
    },
}));

// Register CustomAuth and seed a default client app
builder.Services
    .AddCustomAuth(options =>
    {
        options.Issuer = "http://localhost:5220";
        options.RequireHttps = false;
    })
    .AddInMemoryStores(setup =>
    {
        setup.Clients.Add(new CustomAuthClient
        {
            ClientId = "sample-webapp",
            DisplayName = "Sample Web App",
            RedirectUris = { "http://localhost:5043/signin-oidc" },
            PostLogoutRedirectUris = { "http://localhost:5043/" },
            AllowedScopes = { "openid", "profile", "email", "offline_access" }
        });
    })
    .AddJwtTokenSigning();

var app = builder.Build();

// Redirect root to the Admin UI
app.MapGet("/", () => Results.Redirect("/customauth"));

// Map SSO protocol endpoints and the embedded Admin UI.
// AllowAnonymous is enabled here for the local sample only; production deployments
// must either wire RequireAuthorization through CustomAuthAdminUIOptions.AuthorizationPolicyName
// or rely on the application's default authorization policy.
app.MapCustomAuthEndpoints();
app.MapCustomAuthAdminUI(options => options.AllowAnonymous = true);

app.Run();
