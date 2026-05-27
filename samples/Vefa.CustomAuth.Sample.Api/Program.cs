using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "http://localhost:5175";
        options.RequireHttpsMetadata = false;
        options.Audience = "sample-webapp";
        options.MapInboundClaims = false;
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Vefa.CustomAuth sample protected API.");
app.MapGet("/weather", (HttpContext context) => new
{
    Message = "Protected API call succeeded.",
    Subject = context.User.FindFirst("sub")?.Value,
    Scope = context.User.FindFirst("scope")?.Value,
}).RequireAuthorization();

app.Run();
