using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.OpenApi.Models;
using Vefa.CustomAuth.Sample.Api.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Load Configurations from appsettings.json
var customAuthSection = builder.Configuration.GetSection("CustomAuth");
var authority = customAuthSection["Authority"] ?? "http://localhost:5175";
var requireHttpsMetadata = customAuthSection.GetValue<bool>("RequireHttpsMetadata");
var validAudiences = customAuthSection.GetSection("ValidAudiences").Get<string[]>() ?? new[] { "sample-webapp", "swagger-ui" };

// Add services to the container.
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.RequireHttpsMetadata = requireHttpsMetadata;
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidAudiences = validAudiences
        };

        // Diagnostics: surface *why* a bearer token was rejected. Without this, the API just
        // returns 401 with no explanation and tracking down audience/issuer/signature/expiry
        // mismatches is slow. These handlers never expose the reason to the caller (the 401
        // body stays generic); they only write it to the server log.
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("Vefa.CustomAuth.Sample.Api.JwtBearer");
                logger.LogWarning(
                    context.Exception,
                    "JWT bearer authentication failed: {Reason}. Expected issuer/authority: {Authority}, accepted audiences: [{ValidAudiences}].",
                    context.Exception.Message,
                    authority,
                    string.Join(", ", validAudiences));
                return Task.CompletedTask;
            },
            OnChallenge = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("Vefa.CustomAuth.Sample.Api.JwtBearer");
                logger.LogWarning(
                    "JWT bearer challenge (401) for {Path}. error: '{Error}', description: '{ErrorDescription}'. Common causes: missing Authorization header, expired token, wrong audience, or signature validation failure.",
                    context.Request.Path,
                    context.Error,
                    context.ErrorDescription);
                return Task.CompletedTask;
            },
            OnForbidden = context =>
            {
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("Vefa.CustomAuth.Sample.Api.JwtBearer");
                logger.LogWarning(
                    "JWT bearer forbidden (403) for {Path}. The token was valid but did not satisfy the authorization policy (e.g. a required scope or role claim is missing).",
                    context.Request.Path);
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddSampleApiSwagger(builder.Configuration);

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseCors();
app.UseSampleApiSwagger();

// Serve the beautiful static UI at the root path "/"
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

// Standard authorized endpoint returning rich user claims info
app.MapGet("/weather", (HttpContext context) => new
{
    Message = "Protected API call succeeded.",
    Subject = context.User.FindFirst("sub")?.Value,
    Scope = context.User.FindFirst("scope")?.Value,
    Claims = context.User.Claims.Select(c => new { c.Type, c.Value }).ToList(),
    RequestHeaders = context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString())
}).RequireAuthorization();

app.Run();

