# Confidential clients with `private_key_jwt`

By default every Vefa.CustomAuth client is a **public client**: the token endpoint identifies it by
`client_id` and relies on PKCE. That is correct for SPAs and mobile apps, but a backend
(service-to-service) client should be able to **prove its identity** so that another service which
learns a `client_id` cannot impersonate it.

`private_key_jwt` (RFC 7521 / 7523, OpenID Connect Core 1.0 §9) adds asymmetric client
authentication: the client signs a short-lived JWT **client assertion** with its private key, and
the authorization server verifies the signature with the client's **registered public key**. The
private key never leaves the client.

This is independent of the server's own token signing (the server still signs access/ID tokens with
its RSA key and publishes the public JWK at `/.well-known/jwks.json`). `private_key_jwt` is the
*inbound* direction: a client-provided assertion validated at the token endpoint.

## How it works

1. The client is registered with `TokenEndpointAuthMethod = PrivateKeyJwt` and a JWKS containing its
   **public** key(s).
2. On every token request the client adds two form fields:
   - `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
   - `client_assertion=<signed JWT>`
3. The server verifies the assertion: signature against the registered JWKS, asymmetric algorithm
   only (`none`/HMAC rejected), `aud` is the issuer or the token endpoint URL, `iss == sub == client_id`,
   `exp` present and unexpired (within `CustomAuthOptions.ClientAssertionClockSkew`), and `jti`
   present and not replayed.
4. On failure the caller receives an opaque `401 invalid_client` (with `WWW-Authenticate`); the
   precise reason is written to the server log only.

PKCE is still enforced for confidential clients (defense in depth).

## Registering a confidential client

```csharp
new CustomAuthClient
{
    ClientId = "service-client",
    DisplayName = "My Backend Service",
    RedirectUris = { "https://service.example.com/signin-oidc" },
    AllowedScopes = { "openid", "profile", "email", "offline_access", "my-api" },
    AllowRefreshTokens = true,
    TokenEndpointAuthMethod = CustomAuthClientAuthenticationMethod.PrivateKeyJwt,
    JwksJson = """{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"key-1","n":"...","e":"AQAB"}]}""",
};
```

`JwksJson` holds **public keys only**. The same client can also be created/edited from the Admin UI
(the client editor exposes a "Token Endpoint Authentication" selector and a JWKS textarea).

## Generating a key pair

Generate an RSA private key (kept by the client) and derive the public JWKS (registered on the
server). For example:

```bash
openssl genrsa -out service-client.key 2048
# Convert the public part into a JWK (n,e). Any JWKS tooling works; the modulus/exponent must be
# base64url-encoded without padding.
```

The repository's sample stores a ready-made **public** JWKS at
`samples/Vefa.CustomAuth.Sample.AuthServer/Keys/service-client.jwks.json`. See the README next to it
for how to regenerate it. ES256/384/512 and PS256 keys are also supported.

## Signing a client assertion (client side)

Using `Microsoft.IdentityModel.JsonWebTokens`:

```csharp
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

var rsa = RSA.Create(); // load the client's PRIVATE key here
var signingKey = new RsaSecurityKey(rsa) { KeyId = "key-1" };
var now = DateTime.UtcNow;

var assertion = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
{
    Issuer = "service-client",                       // iss
    Audience = "https://auth.example.com/connect/token", // aud (token endpoint or issuer)
    Claims = new Dictionary<string, object>
    {
        ["sub"] = "service-client",                  // sub == iss == client_id
        ["jti"] = Guid.NewGuid().ToString("N"),      // unique per request (replay protection)
    },
    IssuedAt = now,
    NotBefore = now,
    Expires = now.AddMinutes(2),                     // keep it short-lived
    SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
});
```

## Token request

```http
POST /connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&client_id=service-client
&redirect_uri=https://service.example.com/signin-oidc
&code=<authorization_code>
&code_verifier=<pkce_verifier>
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<signed_jwt>
```

The same `client_assertion` fields apply to the `refresh_token` grant.

## Replay protection and scaling

Each `jti` is single-use within the assertion's lifetime. The default
`IClientAssertionReplayCache` is an in-memory, **per-instance** cache. When running multiple
instances, provide a distributed implementation (e.g. Redis) so a replay is detected across the
cluster:

```csharp
services.AddSingleton<IClientAssertionReplayCache, MyRedisClientAssertionReplayCache>();
```

## Discovery

When the feature is available the discovery document advertises:

```json
{
  "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
  "token_endpoint_auth_signing_alg_values_supported": ["RS256","RS384","RS512","PS256","ES256","ES384","ES512"]
}
```

## Security notes

- `alg: none` and symmetric (HMAC) algorithms are rejected — asymmetric signatures only.
- `aud` is checked against the issuer and the token endpoint URL.
- `iss`, `sub`, and the request `client_id` must all match.
- The raw assertion is never logged; only `client_id`, `jti`, and a short failure reason are.
- This iteration uses an **inline JWKS** on the client record. Remote `jwks_uri` fetching is not
  implemented (to avoid HTTP/SSRF surface) and can be added later.
