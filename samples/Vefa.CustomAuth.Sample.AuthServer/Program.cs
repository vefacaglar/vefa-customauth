using Vefa.CustomAuth.AspNetCore.Extensions;
using Vefa.CustomAuth.AspNetCore.Stores.InMemory;
using Vefa.CustomAuth.Core.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddVefaCustomAuth(options =>
    {
        options.Issuer = "http://localhost:5175";
        options.RequireHttps = false;
    })
    .AddJwtTokenSigning()
    .AddInMemoryStores(stores =>
    {
        stores.Clients.Add(new CustomAuthClient
        {
            ClientId = "sample-webapp",
            DisplayName = "Sample Web App",
            RedirectUris = { "http://localhost:5043/signin-oidc" },
            PostLogoutRedirectUris = { "http://localhost:5043/" },
            AllowedScopes = { "openid", "profile", "email", "offline_access", "sample-api" },
        });

        stores.Users.Add(new InMemoryUserStore.SeedUser
        {
            UserId = "user-1",
            UserName = "demo",
            Password = "demo",
            Email = "demo@example.com",
        });
    });

var app = builder.Build();

app.MapGet("/", () => "Vefa.CustomAuth sample auth server. Sign in with demo / demo.");
app.MapVefaCustomAuthEndpoints();

app.Run();
