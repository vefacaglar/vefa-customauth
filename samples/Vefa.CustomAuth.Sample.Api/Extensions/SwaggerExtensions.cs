using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;

namespace Vefa.CustomAuth.Sample.Api.Extensions;

public static class SwaggerExtensions
{
    public static IServiceCollection AddSampleApiSwagger(this IServiceCollection services, IConfiguration configuration)
    {
        var swaggerSection = configuration.GetSection("Swagger");
        var swaggerTitle = swaggerSection["Title"] ?? "Vefa.CustomAuth Sample Protected API";
        var swaggerDesc = swaggerSection["Description"] ?? "A sample protected API demonstrating OAuth2 JWT Bearer token authentication issued by Vefa.CustomAuth Server.";
        
        var customAuthSection = configuration.GetSection("CustomAuth");
        var authority = customAuthSection["Authority"] ?? "http://localhost:5175";

        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(options =>
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

        return services;
    }

    public static WebApplication UseSampleApiSwagger(this WebApplication app)
    {
        var swaggerSection = app.Configuration.GetSection("Swagger");
        var swaggerTitle = swaggerSection["Title"] ?? "Vefa.CustomAuth Sample Protected API";
        var swaggerClientId = swaggerSection["ClientId"] ?? "swagger-ui";
        var swaggerClientSecret = swaggerSection["ClientSecret"] ?? "not-required-for-pkce";
        var swaggerAppName = swaggerSection["AppName"] ?? "Vefa.CustomAuth Swagger Client";

        app.UseSwagger();
        app.UseSwaggerUI(options =>
        {
            options.SwaggerEndpoint("/swagger/v1/swagger.json", $"{swaggerTitle} v1");
            options.RoutePrefix = "swagger";
            
            options.OAuthClientId(swaggerClientId);
            options.OAuthClientSecret(swaggerClientSecret);
            options.OAuthAppName(swaggerAppName);
            options.OAuthUsePkce();
        });

        return app;
    }
}
