using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.AspNetCore.Extensions;
using Vefa.CustomAuth.AspNetCore.Validation;
using Vefa.CustomAuth.Core.Options;

namespace Vefa.CustomAuth.AspNetCore.Tests;

public sealed class CustomAuthOptionsValidationTests
{
    private readonly CustomAuthOptionsValidator _validator = new();

    [Fact]
    public void ValidOptions_PassesValidation()
    {
        var options = new CustomAuthOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(2),
            AccessTokenLifetime = TimeSpan.FromHours(1),
            IdTokenLifetime = TimeSpan.FromHours(1),
            RefreshTokenLifetime = TimeSpan.FromDays(30),
            RefreshTokenAbsoluteLifetime = TimeSpan.FromDays(30),
            LoginPath = "/login",
            CookieName = ".Vefa.CustomAuth.Session",
            RequireHttps = true
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData("", true)]
    [InlineData("   ", true)]
    [InlineData("invalid-url", true)]
    [InlineData("http://localhost", true)]
    public void InvalidIssuer_FailsValidation(string? issuer, bool requireHttps)
    {
        var options = new CustomAuthOptions
        {
            Issuer = issuer!,
            RequireHttps = requireHttps,
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(2),
            AccessTokenLifetime = TimeSpan.FromHours(1),
            IdTokenLifetime = TimeSpan.FromHours(1),
            RefreshTokenLifetime = TimeSpan.FromDays(30),
            RefreshTokenAbsoluteLifetime = TimeSpan.FromDays(30),
            LoginPath = "/login",
            CookieName = ".Vefa.CustomAuth.Session"
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.NotEmpty(result.Failures);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void InvalidLifetimes_FailValidation(double minutes)
    {
        var lifetime = TimeSpan.FromMinutes(minutes);
        var options = new CustomAuthOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationCodeLifetime = lifetime,
            AccessTokenLifetime = lifetime,
            IdTokenLifetime = lifetime,
            RefreshTokenLifetime = lifetime,
            RefreshTokenAbsoluteLifetime = lifetime,
            LoginPath = "/login",
            CookieName = ".Vefa.CustomAuth.Session"
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains(nameof(options.AuthorizationCodeLifetime)));
        Assert.Contains(result.Failures, f => f.Contains(nameof(options.AccessTokenLifetime)));
        Assert.Contains(result.Failures, f => f.Contains(nameof(options.IdTokenLifetime)));
        Assert.Contains(result.Failures, f => f.Contains(nameof(options.RefreshTokenLifetime)));
        Assert.Contains(result.Failures, f => f.Contains(nameof(options.RefreshTokenAbsoluteLifetime)));
    }

    [Fact]
    public void RefreshTokenAbsoluteLifetimeShorterThanSlidingLifetime_FailsValidation()
    {
        var options = new CustomAuthOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(2),
            AccessTokenLifetime = TimeSpan.FromHours(1),
            IdTokenLifetime = TimeSpan.FromHours(1),
            RefreshTokenLifetime = TimeSpan.FromDays(30),
            RefreshTokenAbsoluteLifetime = TimeSpan.FromDays(7),
            LoginPath = "/login",
            CookieName = ".Vefa.CustomAuth.Session"
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains(nameof(options.RefreshTokenAbsoluteLifetime)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("login")]
    [InlineData("   ")]
    public void InvalidLoginPath_FailsValidation(string loginPath)
    {
        var options = new CustomAuthOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(2),
            AccessTokenLifetime = TimeSpan.FromHours(1),
            IdTokenLifetime = TimeSpan.FromHours(1),
            RefreshTokenLifetime = TimeSpan.FromDays(30),
            RefreshTokenAbsoluteLifetime = TimeSpan.FromDays(30),
            LoginPath = loginPath,
            CookieName = ".Vefa.CustomAuth.Session"
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains(nameof(options.LoginPath)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void InvalidCookieName_FailsValidation(string cookieName)
    {
        var options = new CustomAuthOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(2),
            AccessTokenLifetime = TimeSpan.FromHours(1),
            IdTokenLifetime = TimeSpan.FromHours(1),
            RefreshTokenLifetime = TimeSpan.FromDays(30),
            RefreshTokenAbsoluteLifetime = TimeSpan.FromDays(30),
            LoginPath = "/login",
            CookieName = cookieName
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains(nameof(options.CookieName)));
    }

    [Fact]
    public async Task ValidateOnStart_ThrowsOptionsValidationException_WhenOptionsAreInvalid()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddVefaCustomAuth(options =>
        {
            // Invalid options
            options.Issuer = "";
            options.RequireHttps = true;
        });

        var app = builder.Build();

        // Trigger ValidateOnStart by starting the host
        var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => app.StartAsync());
        Assert.Contains("Issuer must be specified.", exception.Message);

        await app.StopAsync();
    }
}
