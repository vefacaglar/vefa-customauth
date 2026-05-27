# Vefa.CustomAuth Gereksinim Planı

Amaç: ASP.NET Core projelerine eklenebilen, basit ama düzgün tasarlanmış bir **OAuth2 / OpenID Connect tabanlı custom SSO kütüphanesi** oluşturmak.

Ana hedef full IdentityServer yazmak değil. İlk hedef:

```text
Authorization Code + PKCE
SSO session cookie
JWT access token
ID token
Refresh token
JWKS
ASP.NET Core endpoint mapping
EF Core persistence
```

## 1. Solution Yapısı

```text
Vefa.CustomAuth.sln

src/
  Vefa.CustomAuth.Core
  Vefa.CustomAuth.AspNetCore
  Vefa.CustomAuth.EntityFrameworkCore
  Vefa.CustomAuth.Tokens
  Vefa.CustomAuth.Server

samples/
  Vefa.CustomAuth.Sample.AuthServer
  Vefa.CustomAuth.Sample.WebApp
  Vefa.CustomAuth.Sample.Api

tests/
  Vefa.CustomAuth.Tests
  Vefa.CustomAuth.AspNetCore.Tests
```

İlk etapta `Tokens` ayrı paket olmayabilir. Karmaşıklaşırsa ayırmak daha doğru olur.

Minimum NuGet hedefi:

```text
Vefa.CustomAuth.Core
Vefa.CustomAuth.AspNetCore
Vefa.CustomAuth.EntityFrameworkCore
```

## 2. Temel Kullanım Hedefi

Kütüphaneyi kullanan kişi kendi ASP.NET Core projesinde şuna yakın bir yapı kurabilmeli:

```csharp
builder.Services
    .AddVefaCustomAuth(options =>
    {
        options.Issuer = "https://auth.local";
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddJwtTokenSigning();

app.MapVefaCustomAuthEndpoints();
```

API tarafında:

```csharp
builder.Services
    .AddAuthentication("Bearer")
    .AddJwtBearer(...);
```

Client uygulama tarafında ise normal OIDC client gibi bağlanabilmeli.

## 3. Desteklenecek Endpointler

v0.1 için:

```text
GET  /connect/authorize
POST /connect/token
GET  /.well-known/openid-configuration
GET  /.well-known/jwks.json
GET  /login
POST /login
```

v0.2 için:

```text
POST /connect/logout
GET  /connect/userinfo
POST /connect/revoke
```

v0.3+ için:

```text
POST /connect/introspect
GET  /consent
POST /consent
```

Consent ilk etapta şart değil. Kendi uygulamaların arası SSO için gereksiz karmaşıklık.

## 4. Desteklenecek OAuth/OIDC Akışları

İlk versiyon sadece:

```text
Authorization Code Flow + PKCE
```

Desteklenmeyecekler:

```text
Implicit Flow
Password Grant
Device Code
Client Credentials
Hybrid Flow
```

Client Credentials sonradan eklenebilir ama SSO için ilk ihtiyaç değil.

## 5. Domain Modelleri

Minimum modeller:

```csharp
CustomAuthClient
CustomAuthAuthorizationCode
CustomAuthRefreshToken
CustomAuthSession
CustomAuthSigningKey
```

User modeli pakete gömülmemeli.

Bunun yerine:

```csharp
ICustomAuthUserStore
```

olmalı.

Örnek user modeli sample projede olabilir ama ana pakette zorunlu olmamalı.

## 6. Client Modeli

```csharp
public sealed class CustomAuthClient
{
    public string ClientId { get; set; }
    public string DisplayName { get; set; }

    public List<string> RedirectUris { get; set; }
    public List<string> PostLogoutRedirectUris { get; set; }

    public List<string> AllowedScopes { get; set; }

    public bool RequirePkce { get; set; } = true;
    public bool AllowRefreshTokens { get; set; } = true;

    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
    public int RefreshTokenLifetimeSeconds { get; set; } = 2592000;
}
```

## 7. Authorization Code Gereksinimleri

Authorization code:

```text
tek kullanımlık olmalı
kısa ömürlü olmalı
PKCE code_challenge ile bağlı olmalı
client_id ile bağlı olmalı
redirect_uri ile bağlı olmalı
user_id ile bağlı olmalı
```

Öneri:

```text
authorization code lifetime: 60-120 saniye
```

Model:

```csharp
CustomAuthAuthorizationCode
{
    Id
    CodeHash
    ClientId
    UserId
    RedirectUri
    CodeChallenge
    CodeChallengeMethod
    Scope
    ExpiresAt
    ConsumedAt
    CreatedAt
}
```

Code raw olarak DB’ye yazılmamalı. Hash yazılması daha doğru.

## 8. Token Gereksinimleri

Üretilecek tokenlar:

```text
access_token
id_token
refresh_token
```

Access token JWT olabilir.

ID token OIDC tarafı için JWT olmalı.

Refresh token opaque random string olmalı, JWT yapmaya gerek yok.

Access token claims:

```text
sub
iss
aud
exp
iat
jti
scope
```

ID token claims:

```text
sub
iss
aud
exp
iat
auth_time
name
email
```

`name` ve `email` zorunlu olmamalı. User store ne sağlıyorsa o.

## 9. Refresh Token Gereksinimleri

Refresh token:

```text
DB’de hash olarak tutulmalı
rotate edilmeli
reuse detection yapılmalı
client_id ile bağlı olmalı
user_id ile bağlı olmalı
session_id ile bağlı olabilir
```

Model:

```csharp
CustomAuthRefreshToken
{
    Id
    TokenHash
    ClientId
    UserId
    SessionId
    Scope
    ExpiresAt
    ConsumedAt
    RevokedAt
    CreatedAt
}
```

İlk versiyonda rotation yeterli. Reuse detection v0.2’ye kalabilir.

## 10. Session / SSO Cookie

Auth server kendi cookie’sini basmalı.

```text
cookie name: .Vefa.CustomAuth.Session
HttpOnly: true
Secure: true
SameSite: Lax
```

SSO mantığı bu cookie üzerinden çalışır.

User App A’da login olduysa, App B `/connect/authorize` çağırınca Auth Server cookie’yi görür ve tekrar login istemeden code üretir.

## 11. Store Interface’leri

Core pakette sadece abstraction olmalı:

```csharp
ICustomAuthClientStore
ICustomAuthAuthorizationCodeStore
ICustomAuthRefreshTokenStore
ICustomAuthSessionStore
ICustomAuthSigningKeyStore
ICustomAuthUserStore
```

EF Core paketi bunların default implementasyonunu sağlar.

## 12. ASP.NET Core Paketi

`Vefa.CustomAuth.AspNetCore` şunları sağlamalı:

```csharp
AddVefaCustomAuth(...)
MapVefaCustomAuthEndpoints()
```

Endpoint handler’lar burada olur.

```text
AuthorizeEndpoint
TokenEndpoint
LoginEndpoint
LogoutEndpoint
DiscoveryEndpoint
JwksEndpoint
UserInfoEndpoint
```

Controller yerine minimal API endpoint mapping daha paket dostu olur.

## 13. EF Core Paketi

`Vefa.CustomAuth.EntityFrameworkCore` şunları sağlar:

```csharp
CustomAuthDbContext
CustomAuthEntityConfigurations
EfCustomAuthClientStore
EfCustomAuthAuthorizationCodeStore
EfCustomAuthRefreshTokenStore
EfCustomAuthSessionStore
EfCustomAuthSigningKeyStore
```

Kullanım:

```csharp
builder.Services.AddVefaCustomAuthEntityFrameworkCore(options =>
{
    options.UseNpgsql(connectionString);
});
```

veya daha esnek:

```csharp
builder.Services.AddVefaCustomAuthStores<AppDbContext>();
```

Bence ikinci yaklaşım daha iyi. Kullanıcı kendi DbContext’ine tabloları ekleyebilir.

## 14. Güvenlik Gereksinimleri

Minimum güvenlik kuralları:

```text
PKCE zorunlu
redirect_uri exact match
state client tarafından doğrulanmalı
authorization code tek kullanımlık
token signing key private kalmalı
refresh token hash tutulmalı
client input validation yapılmalı
open redirect engellenmeli
issuer/audience doğru set edilmeli
HTTPS prod ortamda zorunlu olmalı
```

İlk versiyonda client secret desteği koymayabiliriz. Public client + PKCE yeterli olur.

## 15. Config Gereksinimleri

Options modeli:

```csharp
public sealed class CustomAuthOptions
{
    public string Issuer { get; set; }

    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(2);
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);

    public string LoginPath { get; set; } = "/login";
    public string CookieName { get; set; } = ".Vefa.CustomAuth.Session";

    public bool RequirePkce { get; set; } = true;
    public bool RequireHttps { get; set; } = true;
}
```

## 16. Sample Senaryolar

En az iki sample olmalı:

```text
Auth Server
Web App Client
Protected API
```

Akış:

```text
Web App login ister
Auth Server’a redirect eder
Auth Server login yapar
Web App callback alır
Token alır
API’ye access_token ile istek atar
```

Bu sample NuGet öncesi en önemli doğrulama alanı olur.

## 17. Test Gereksinimleri

Öncelikli testler:

```text
invalid redirect_uri reddedilmeli
PKCE yanlışsa token verilmemeli
authorization code ikinci kez kullanılamamalı
expired code reddedilmeli
refresh token rotation çalışmalı
revoked refresh token reddedilmeli
JWKS public key dönmeli
JWT signature doğrulanabilmeli
```

## 18. Roadmap

```text
v0.1
Authorization Code + PKCE
Login cookie
JWT access token
ID token
JWKS
Discovery endpoint
In-memory stores

v0.2
EF Core stores
Refresh token
Logout
UserInfo endpoint

v0.3
Sample Auth Server + Web Client + API
Options validation
Basic tests

v0.4
NuGet package split
README
XML docs
CI package build

v1.0
Security hardening
Stable public API
Migration strategy
```

İlk hedef:

```text
v0.1: in-memory store ile çalışan Authorization Code + PKCE akışı
```

EF Core’a hemen girmek yerine önce akışı çalıştırmak daha doğru. Protokol tasarımı oturduktan sonra persistence tarafı değiştirilebilir hale getirilebilir.
