using System.Threading.RateLimiting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Vefa.CustomAuth.AdminUI.Extensions;
using Vefa.CustomAuth.AspNetCore.Extensions;
using Vefa.CustomAuth.AspNetCore.Stores.InMemory;
using Vefa.CustomAuth.Core.Services;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.EntityFrameworkCore.Extensions;
using Vefa.CustomAuth.Sample.AuthServer.Data;
using Vefa.CustomAuth.Sample.AuthServer.DataProtection;
using Vefa.CustomAuth.Sample.AuthServer.Identity;
using Vefa.CustomAuth.Sample.AuthServer.Services;

var builder = WebApplication.CreateBuilder(args);

// Choose the user store. Both expose the same ICustomAuthUserStore contract to the library, so the
// protocol code is identical either way. Set "UseAspNetCoreIdentity" to false in configuration to
// use the simple in-memory demo store instead. Defaults to the Identity-backed store.
var useAspNetCoreIdentity = builder.Configuration.GetValue("UseAspNetCoreIdentity", true);

if (useAspNetCoreIdentity)
{
    // ASP.NET Core Identity backs user lookup and password validation. It owns its own
    // SampleIdentityDbContext (a separate SQLite database from the protocol data) and is wired to
    // the library purely through the IdentityUserStore : ICustomAuthUserStore adapter.
    builder.Services.AddDbContext<SampleIdentityDbContext>(options =>
        options.UseSqlite("Data Source=identity-sample.db"));

    builder.Services
        .AddIdentityCore<IdentityUser>(options =>
        {
            // Relaxed so the "demo" / "demo" credentials work out of the box; tighten for production.
            options.Password.RequiredLength = 4;
            options.Password.RequireDigit = false;
            options.Password.RequireUppercase = false;
            options.Password.RequireLowercase = false;
            options.Password.RequireNonAlphanumeric = false;
        })
        .AddRoles<IdentityRole>()
        .AddEntityFrameworkStores<SampleIdentityDbContext>()
        .AddDefaultTokenProviders();

    builder.Services.AddScoped<ICustomAuthUserStore, IdentityUserStore>();
}
else
{
    builder.Services.TryAddSingleton<ICustomAuthUserStore>(_ => new InMemoryUserStore(new[]
    {
        new InMemoryUserStore.SeedUser
        {
            UserId = "user-1",
            UserName = "demo",
            Password = "demo",
            Email = "demo@example.com",
            // This is where you add your own custom claims:
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
}

builder.Services.AddDbContext<SampleCustomAuthDbContext>(options =>
{
    options.UseSqlite("Data Source=customauth-sample.db");
});
builder.Services.AddCustomAuthStores<SampleCustomAuthDbContext>();

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

// Brute-force protection is host-owned. Register a demo in-memory lockout tracker (registered
// before AddCustomAuth so it wins over the library's default no-op tracker) and a rate limiter
// that throttles POST /login per client IP. A production host should use a durable store and
// tune these limits to its threat model.
builder.Services.AddSingleton<ICustomAuthLoginAttemptTracker, DemoLoginAttemptTracker>();

builder.Services.AddRateLimiter(rateLimiterOptions =>
{
    rateLimiterOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    rateLimiterOptions.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        // Only throttle the login POST; every other endpoint is unlimited in this sample.
        if (HttpMethods.IsPost(httpContext.Request.Method)
            && httpContext.Request.Path.StartsWithSegments("/login"))
        {
            var partitionKey = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            return RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            });
        }

        return RateLimitPartition.GetNoLimiter("__no_limit");
    });
});

// Persist the Data Protection key ring in SQLite so the SSO session cookie and antiforgery tokens
// stay readable across restarts and across every instance behind a load balancer. SetApplicationName
// must be identical on all instances; without a shared key ring + name, instances cannot decrypt each
// other's cookies (random logouts / antiforgery failures). See docs/production-hardening.md.
builder.Services.AddDbContext<SampleDataProtectionDbContext>(options =>
    options.UseSqlite("Data Source=dataprotection-sample.db"));

builder.Services.AddDataProtection()
    .SetApplicationName("vefa-customauth-authserver")
    .PersistKeysToDbContext<SampleDataProtectionDbContext>();

var customAuthBuilder = builder.Services
    .AddCustomAuth(options =>
    {
        options.Issuer = "http://localhost:5175";
        options.RequireHttps = false;
        options.MapDefaultLoginEndpoint = false;
        // LoginPath / LogoutPath point at this host's Razor Pages. UI rendering and
        // credential-validation POST are fully owned by the host application.
    })
    .AddJwtTokenSigning();

// Signing key source: if a PFX is present, sign with it (the same certificate on every instance keeps
// the JWKS consistent across a load-balanced farm). Otherwise fall back to the auto-generated key in
// the signing key store. The PFX is git-ignored, so a fresh clone uses the store-backed key.
var signingCertificatePath = Path.Combine(builder.Environment.ContentRootPath, "Keys", "signing.pfx");
if (File.Exists(signingCertificatePath))
{
    customAuthBuilder.AddSigningCertificate(
        signingCertificatePath,
        builder.Configuration["SigningCertificate:Password"]);
}

// Add our dynamic profile service that intercepts token requests
builder.Services.AddScoped<Vefa.CustomAuth.Core.Services.ICustomAuthProfileService, MyProfileService>();

var app = builder.Build();

app.UseCors();
app.UseStaticFiles();
app.UseRateLimiter();

await DatabaseSeeder.EnsureDatabaseSeededAsync(app.Services);

// Ensure the Data Protection key table exists before the key ring is first accessed.
using (var dataProtectionScope = app.Services.CreateScope())
{
    await dataProtectionScope.ServiceProvider
        .GetRequiredService<SampleDataProtectionDbContext>()
        .Database.EnsureCreatedAsync();
}

if (useAspNetCoreIdentity)
{
    await IdentitySeeder.EnsureSeededAsync(app.Services);
}

app.MapGet("/", () => "Vefa.CustomAuth sample auth server. Sign in with demo / demo.");
app.MapCustomAuthEndpoints();
app.MapCustomAuthAdminUI(options =>
{
    options.PathPrefix = "/customauth";
    // This sample auth server has no ASP.NET Core application cookie for dashboard users.
    // Keep anonymous access only for local development; protect this route in production.
    options.AllowAnonymous = true;
});
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
        if (context.Client.ClientId == "sample-webapp")
        {
            context.Claims["sample_webapp_specific_claim"] = "dynamically_added_value";
        }
    }

    public async Task<bool> IsUserActiveAsync(string userId, CancellationToken cancellationToken = default)
    {
        // Here you can check if the user is suspended/banned before they get a new token.
        var user = await _userStore.FindByIdAsync(userId, cancellationToken);
        return user is not null;
    }
}
