using System;
using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Services;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.AspNetCore.Services;

/// <summary>
/// Default implementation of <see cref="ICustomAuthProfileService"/> that copies the statically defined claims 
/// from <see cref="ICustomAuthUserStore"/> into the profile context.
/// </summary>
internal sealed class DefaultProfileService : ICustomAuthProfileService
{
    private readonly ICustomAuthUserStore _userStore;

    public DefaultProfileService(ICustomAuthUserStore userStore)
    {
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
    }

    public async Task GetProfileDataAsync(CustomAuthProfileContext context, CancellationToken cancellationToken = default)
    {
        var user = await _userStore.FindByIdAsync(context.UserId, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            return;
        }

        if (!string.IsNullOrWhiteSpace(user.UserName))
        {
            context.Claims["name"] = user.UserName;
        }

        if (!string.IsNullOrWhiteSpace(user.Email))
        {
            context.Claims["email"] = user.Email;
        }

        if (user.AdditionalClaims is not null)
        {
            foreach (var claim in user.AdditionalClaims)
            {
                context.Claims.TryAdd(claim.Key, claim.Value);
            }
        }
    }

    public async Task<bool> IsUserActiveAsync(string userId, CancellationToken cancellationToken = default)
    {
        var user = await _userStore.FindByIdAsync(userId, cancellationToken).ConfigureAwait(false);
        return user is not null;
    }
}
