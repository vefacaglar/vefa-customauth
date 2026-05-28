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

await Vefa.CustomAuth.Sample.AuthServer.Data.DatabaseSeeder.EnsureDatabaseSeededAsync(app.Services);

app.MapGet("/", () => "Vefa.CustomAuth sample auth server. Sign in with demo / demo.");
app.MapCustomAuthEndpoints();
app.MapRazorPages();

app.Run();
