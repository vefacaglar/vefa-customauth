using Microsoft.Extensions.DependencyInjection;
using Vefa.CustomAuth.Core.Options;

namespace Vefa.CustomAuth.AspNetCore.Extensions;

public static class CustomAuthServiceCollectionExtensions
{
    public static CustomAuthBuilder AddVefaCustomAuth(this IServiceCollection services, Action<CustomAuthOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);

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
