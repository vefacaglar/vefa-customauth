using Microsoft.AspNetCore.Identity;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.Sample.AuthServer.Identity;

/// <summary>
/// An <see cref="ICustomAuthUserStore"/> backed by ASP.NET Core Identity. It validates
/// credentials with <see cref="UserManager{TUser}"/> (constant-time password hashing is handled
/// by Identity) and projects the user's roles and claims into <see cref="CustomAuthUserInfo"/> so
/// the profile service can flow them into issued tokens. The subject identifier is the Identity
/// user's stable <c>Id</c> (a GUID string).
/// </summary>
public sealed class IdentityUserStore : ICustomAuthUserStore
{
    private readonly UserManager<IdentityUser> _userManager;

    public IdentityUserStore(UserManager<IdentityUser> userManager)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
    }

    public async Task<CustomAuthUserInfo?> ValidateCredentialsAsync(string userName, string password, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(userName);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var user = await _userManager.FindByNameAsync(userName).ConfigureAwait(false);
        if (user is null)
        {
            return null;
        }

        if (!await _userManager.CheckPasswordAsync(user, password).ConfigureAwait(false))
        {
            return null;
        }

        return await ToInfoAsync(user).ConfigureAwait(false);
    }

    public async Task<CustomAuthUserInfo?> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(userId);

        var user = await _userManager.FindByIdAsync(userId).ConfigureAwait(false);
        return user is null ? null : await ToInfoAsync(user).ConfigureAwait(false);
    }

    private async Task<CustomAuthUserInfo> ToInfoAsync(IdentityUser user)
    {
        var additionalClaims = new Dictionary<string, object>(StringComparer.Ordinal);

        var roles = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
        if (roles.Count > 0)
        {
            additionalClaims["role"] = roles.ToArray();
        }

        // Identity claims are string-valued; non-string types (numbers, booleans) become strings.
        foreach (var claim in await _userManager.GetClaimsAsync(user).ConfigureAwait(false))
        {
            additionalClaims[claim.Type] = claim.Value;
        }

        return new CustomAuthUserInfo
        {
            UserId = user.Id,
            UserName = user.UserName,
            Email = user.Email,
            AdditionalClaims = additionalClaims.Count > 0 ? additionalClaims : null,
        };
    }
}
