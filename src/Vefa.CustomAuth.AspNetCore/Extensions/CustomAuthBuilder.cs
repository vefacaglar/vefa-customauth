using Microsoft.Extensions.DependencyInjection;

namespace Vefa.CustomAuth.AspNetCore.Extensions;

/// <summary>
/// Provides fluent access to the service collection while configuring Vefa.CustomAuth.
/// </summary>
public sealed class CustomAuthBuilder
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CustomAuthBuilder"/> class.
    /// </summary>
    /// <param name="services">The service collection being configured.</param>
    public CustomAuthBuilder(IServiceCollection services)
    {
        Services = services ?? throw new ArgumentNullException(nameof(services));
    }

    /// <summary>
    /// Gets the service collection being configured.
    /// </summary>
    public IServiceCollection Services { get; }
}
