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

