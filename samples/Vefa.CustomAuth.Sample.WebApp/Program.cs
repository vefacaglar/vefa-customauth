using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System;
using Vefa.CustomAuth.AspNetCore.Client;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCustomAuthClient(options =>
{
    options.Authority = "http://localhost:5175";
    options.ClientId = "sample-webapp";
    options.RequireHttpsMetadata = false;
    options.AdditionalScopes.Add("sample-api");
    options.AdditionalScopes.Add("offline_access");
    options.RequireNonce = false;
});

builder.Services.AddAuthorization();
builder.Services.AddRazorPages();
builder.Services.AddControllers();

builder.Services.AddHttpClient("sample-api", client =>
{
    client.BaseAddress = new Uri("http://localhost:5098");
});
builder.Services.AddHttpClient("auth-server", client =>
{
    client.BaseAddress = new Uri("http://localhost:5175");
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.MapCustomAuthSignOut("/logout");

app.Run();

