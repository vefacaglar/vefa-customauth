# Vefa.CustomAuth.Tokens

JWT signing and token issuance services for Vefa.CustomAuth.

This package issues JWT access tokens, JWT ID tokens, and opaque refresh token values. It depends on `Vefa.CustomAuth.Core` for signing key persistence abstractions.

## Typical Usage

```csharp
builder.Services
    .AddCustomAuth(options =>
    {
        options.Issuer = "https://auth.example.com";
    })
    .AddJwtTokenSigning();
```

`AddJwtTokenSigning` registers the default RSA signing credentials provider and JWT token issuer.

## Security Notes

Signing keys are loaded from `ICustomAuthSigningKeyStore`. Use durable storage in production and protect private key material.

Refresh token persistence, rotation, absolute expiration, and reuse detection are handled by the ASP.NET Core endpoint and Core manager/store layers.
