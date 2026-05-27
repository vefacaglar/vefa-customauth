namespace Vefa.CustomAuth.Core.Stores;

public sealed class CustomAuthUserInfo
{
    public string UserId { get; set; } = default!;
    public string? UserName { get; set; }
    public string? Email { get; set; }
    public IReadOnlyDictionary<string, string>? AdditionalClaims { get; set; }
}

public interface ICustomAuthUserStore
{
    Task<CustomAuthUserInfo?> ValidateCredentialsAsync(string userName, string password, CancellationToken cancellationToken = default);
    Task<CustomAuthUserInfo?> FindByIdAsync(string userId, CancellationToken cancellationToken = default);
}
