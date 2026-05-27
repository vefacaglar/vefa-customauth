using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Vefa.CustomAuth.EntityFrameworkCore.Extensions;

public static class CustomAuthEntityFrameworkCoreExtensions
{
    public static IServiceCollection AddVefaCustomAuthEntityFrameworkCore(
        this IServiceCollection services,
        Action<DbContextOptionsBuilder> optionsAction)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(optionsAction);

        services.AddDbContext<CustomAuthDbContext>(optionsAction);
        return services;
    }
}
