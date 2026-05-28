using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Vefa.CustomAuth.AspNetCore.Extensions;
using Vefa.CustomAuth.AspNetCore.Stores.InMemory;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.EntityFrameworkCore.Extensions;
using Vefa.CustomAuth.Sample.AuthServer.Data;

var builder = WebApplication.CreateBuilder(args);

builder.Services.TryAddSingleton<ICustomAuthUserStore>(_ => new InMemoryUserStore(new[]
{
    new InMemoryUserStore.SeedUser
    {
        UserId = "user-1",
        UserName = "demo",
        Password = "demo",
        Email = "demo@example.com",
        // Вот burası sizin özel claim'lerinizi eklediğiniz yer:
        AdditionalClaims = new Dictionary<string, object>
        {
            { "role", new[] { "admin", "superadmin" } },
            { "department", "IT" },
            { "tenant_id", 42 },
            { "is_premium", true },
            { "custom_permission", "write_access" }
        }
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

// Add our dynamic profile service that intercepts token requests
builder.Services.AddScoped<Vefa.CustomAuth.Core.Services.ICustomAuthProfileService, MyProfileService>();

var app = builder.Build();

app.UseCors();
app.UseStaticFiles();

await DatabaseSeeder.EnsureDatabaseSeededAsync(app.Services);

app.MapGet("/", () => "Vefa.CustomAuth sample auth server. Sign in with demo / demo.");
app.MapCustomAuthEndpoints();
app.MapRazorPages();

app.Run();

// Here is the highly flexible Profile Service example:
public class MyProfileService : Vefa.CustomAuth.Core.Services.ICustomAuthProfileService
{
    private readonly Vefa.CustomAuth.Core.Stores.ICustomAuthUserStore _userStore;

    public MyProfileService(Vefa.CustomAuth.Core.Stores.ICustomAuthUserStore userStore)
    {
        _userStore = userStore;
    }

    public async Task GetProfileDataAsync(Vefa.CustomAuth.Core.Services.CustomAuthProfileContext context, CancellationToken cancellationToken = default)
    {
        // 1. You can call your own database, API, or use the built-in user store.
        var user = await _userStore.FindByIdAsync(context.UserId, cancellationToken);
        if (user is null) return;

        // 2. Add standard claims
        if (!string.IsNullOrWhiteSpace(user.UserName)) context.Claims["name"] = user.UserName;
        if (!string.IsNullOrWhiteSpace(user.Email)) context.Claims["email"] = user.Email;

        // 3. Add Custom Claims from the store
        if (user.AdditionalClaims is not null)
        {
            foreach (var claim in user.AdditionalClaims)
            {
                context.Claims[claim.Key] = claim.Value;
            }
        }

        // 4. DYNAMICALLY inject claims specifically based on the client!
        if (context.Client.ClientId == "webapp1")
        {
            context.Claims["webapp1_specific_claim"] = "dynamically_added_value";
        }
    }

    public async Task<bool> IsUserActiveAsync(string userId, CancellationToken cancellationToken = default)
    {
        // Here you can check if the user is suspended/banned before they get a new token.
        var user = await _userStore.FindByIdAsync(userId, cancellationToken);
        return user is not null;
    }
}
