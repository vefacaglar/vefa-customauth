using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Vefa.CustomAuth.AspNetCore.Extensions;
using Vefa.CustomAuth.AspNetCore.Stores.InMemory;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.EntityFrameworkCore;
using Vefa.CustomAuth.EntityFrameworkCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

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

builder.Services.AddCustomAuthEntityFrameworkCore(options =>
{
    options.UseSqlite("Data Source=customauth-sample.db");
});

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

builder.Services.AddRazorPages();

builder.Services
    .AddCustomAuth(options =>
    {
        options.Issuer = "http://localhost:5175";
        options.RequireHttps = false;
        // LoginPath / LogoutPath point at this host's Razor Pages; the library only
        // handles POST /login (credential validation) and /connect/logout (RP-initiated
        // logout). UI rendering is fully owned by the host.
    })
    .AddJwtTokenSigning();

var app = builder.Build();

app.UseCors();

await EnsureDatabaseSeededAsync(app.Services);

app.MapGet("/", () => "Vefa.CustomAuth sample auth server. Sign in with demo / demo.");
app.MapCustomAuthEndpoints();
app.MapRazorPages();

app.Run();

static async Task EnsureDatabaseSeededAsync(IServiceProvider services)
{
    await using var scope = services.CreateAsyncScope();
    var context = scope.ServiceProvider.GetRequiredService<CustomAuthDbContext>();

    await context.Database.EnsureCreatedAsync();

    bool changed = false;

    if (!await context.Clients.AnyAsync(client => client.ClientId == "sample-webapp"))
    {
        context.Clients.Add(new CustomAuthClient
        {
            ClientId = "sample-webapp",
            DisplayName = "Sample Web App",
            RedirectUris = { "http://localhost:5043/signin-oidc" },
            PostLogoutRedirectUris = { "http://localhost:5043/" },
            AllowedScopes = { "openid", "profile", "email", "offline_access", "sample-api" },
            AllowRefreshTokens = true,
        });
        changed = true;
    }

    if (!await context.Clients.AnyAsync(client => client.ClientId == "swagger-ui"))
    {
        context.Clients.Add(new CustomAuthClient
        {
            ClientId = "swagger-ui",
            DisplayName = "Sample Swagger UI",
            RedirectUris = { "http://localhost:5098/swagger/oauth2-redirect.html" },
            PostLogoutRedirectUris = { "http://localhost:5098/swagger/" },
            AllowedScopes = { "openid", "profile", "email", "offline_access", "sample-api" },
            AllowRefreshTokens = true,
        });
        changed = true;
    }

    if (changed)
    {
        await context.SaveChangesAsync();
    }
}
