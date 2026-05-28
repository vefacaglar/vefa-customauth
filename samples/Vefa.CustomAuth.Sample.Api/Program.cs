using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Load Configurations from appsettings.json
var customAuthSection = builder.Configuration.GetSection("CustomAuth");
var authority = customAuthSection["Authority"] ?? "http://localhost:5175";
var requireHttpsMetadata = customAuthSection.GetValue<bool>("RequireHttpsMetadata");
var validAudiences = customAuthSection.GetSection("ValidAudiences").Get<string[]>() ?? new[] { "sample-webapp", "swagger-ui" };

var swaggerSection = builder.Configuration.GetSection("Swagger");
var swaggerTitle = swaggerSection["Title"] ?? "Vefa.CustomAuth Sample Protected API";
var swaggerDesc = swaggerSection["Description"] ?? "A sample protected API demonstrating OAuth2 JWT Bearer token authentication issued by Vefa.CustomAuth Server.";
var swaggerClientId = swaggerSection["ClientId"] ?? "swagger-ui";
var swaggerClientSecret = swaggerSection["ClientSecret"] ?? "not-required-for-pkce";
var swaggerAppName = swaggerSection["AppName"] ?? "Vefa.CustomAuth Swagger Client";

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

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = swaggerTitle,
        Version = "v1",
        Description = swaggerDesc
    });

    options.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = JwtBearerDefaults.AuthenticationScheme,
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter 'Bearer' [space] and then your valid JWT access token in the text input below.\n\nExample: \"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...\""
    });

    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.OAuth2,
        Flows = new OpenApiOAuthFlows
        {
            AuthorizationCode = new OpenApiOAuthFlow
            {
                AuthorizationUrl = new Uri($"{authority.TrimEnd('/')}/connect/authorize"),
                TokenUrl = new Uri($"{authority.TrimEnd('/')}/connect/token"),
                Scopes = new Dictionary<string, string>
                {
                    { "openid", "OpenID Connect identification" },
                    { "profile", "Profile information (name, preferred username)" },
                    { "email", "User's email address" },
                    { "offline_access", "Retrieve a refresh token for extended access" },
                    { "sample-api", "Access to protected sample API resources" }
                }
            }
        }
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = JwtBearerDefaults.AuthenticationScheme
                }
            },
            Array.Empty<string>()
        },
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "oauth2"
                }
            },
            new[] { "openid", "profile", "sample-api" }
        }
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseCors();

// Enable Swagger / OpenAPI
app.UseSwagger();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/swagger/v1/swagger.json", $"{swaggerTitle} v1");
    options.RoutePrefix = "swagger";
    
    // Enable interactive OAuth2 Login via Swagger UI
    options.OAuthClientId(swaggerClientId);
    options.OAuthClientSecret(swaggerClientSecret);
    options.OAuthAppName(swaggerAppName);
    options.OAuthUsePkce();
});

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

