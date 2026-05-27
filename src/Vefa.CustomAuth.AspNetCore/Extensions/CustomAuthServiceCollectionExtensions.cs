using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Vefa.CustomAuth.AspNetCore.Endpoints;
using Vefa.CustomAuth.Core.Options;

namespace Vefa.CustomAuth.AspNetCore.Extensions;

public static class CustomAuthServiceCollectionExtensions
{
    public static CustomAuthBuilder AddVefaCustomAuth(this IServiceCollection services, Action<CustomAuthOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<AuthorizationEndpointService>();
        services.TryAddScoped<LoginEndpointService>();
        services.TryAddScoped<TokenEndpointService>();
        services.TryAddSingleton<SessionCookieService>();

        return new CustomAuthBuilder(services);
    }
}

public sealed class CustomAuthBuilder
{
    public CustomAuthBuilder(IServiceCollection services)
    {
        Services = services;
    }

    public IServiceCollection Services { get; }
}
