# CLAUDE.md

Project-specific rules for Codex when working on **Vefa.CustomAuth**.

## Current progress (handoff note)

Read this first. The previous session ended here and the user will continue with a fresh model.

### Completed milestones

1. **Solution scaffolding** — sln (`Vefa.CustomAuth.slnx`), 5 src projects, 3 sample projects, 2 test projects all on `net8.0`. `Directory.Build.props` carries shared package metadata; `src/`, `samples/`, `tests/` each override `IsPackable`. Project references and NuGet dependencies are wired. `dotnet build` is 0 warnings / 0 errors.
2. **Domain models, store abstractions, options** — `Vefa.CustomAuth.Core` contains all 5 models (`CustomAuthClient`, `CustomAuthAuthorizationCode`, `CustomAuthRefreshToken`, `CustomAuthSession`, `CustomAuthSigningKey`), 6 store interfaces (`ICustomAuth*Store`), and `CustomAuthOptions`. See `src/Vefa.CustomAuth.Core/`.
3. **JWT signing + token issuance** — `Vefa.CustomAuth.Tokens` has `TokenHasher` (SHA-256 + base64url + opaque token generator), `RsaKeyGenerator`, `RsaSigningCredentialsProvider` (auto-bootstraps an RSA key on first use), and `JwtTokenIssuer` (access + id JWTs, opaque refresh). Registered via `AddJwtTokenSigning()`. Signing/token services are scoped so they can consume scoped EF stores.
4. **Real v0.1 auth endpoints** — `MapVefaCustomAuthEndpoints()` maps working handlers for discovery, JWKS, authorize, token, and login. Endpoint helpers live in `src/Vefa.CustomAuth.AspNetCore/Endpoints/`. Implemented behavior includes exact redirect URI validation, scope subset validation, required PKCE, SSO session cookie lookup, authorization-code creation, authorization-code exchange, refresh-token rotation, and OAuth-style error JSON.
5. **In-memory stores** — full set in `src/Vefa.CustomAuth.AspNetCore/Stores/InMemory/`, registered via `AddInMemoryStores(configure)` with optional client + user seed lists. `InMemoryUserStore` uses `CryptographicOperations.FixedTimeEquals` for password compare. Sample-only, not production.
6. **EF Core stores** — `CustomAuthDbContext`, entity configurations, and all EF-backed store implementations are in `Vefa.CustomAuth.EntityFrameworkCore`. Registration is available via `AddVefaCustomAuthEntityFrameworkCore(optionsAction)` and `AddVefaCustomAuthStores<TContext>()`. `EfCustomAuthSigningKeyStore.GetAllAsync()` orders in memory to avoid SQLite `DateTimeOffset` ordering limitations.
7. **Runnable sample flow** — `scripts/run-samples.sh` builds and starts all three sample apps. `Sample.AuthServer` uses SQLite-backed EF stores for clients, authorization codes, refresh tokens, sessions, and signing keys; only the demo user store remains in-memory because user persistence is host-owned. `Sample.WebApp` uses ASP.NET Core OpenID Connect with code + PKCE and calls `Sample.Api`; `Sample.Api` validates JWT access tokens with `JwtBearer`.
8. **Options validation and hardening** — Added `IValidateOptions<CustomAuthOptions>` with startup validation via `ValidateOnStart()` and comprehensive validation tests. Quieted EF Core commands output in samples by setting the level to `Warning`.
9. **v0.2 Endpoints** — Fully implemented and mapped `/connect/logout`, `/connect/userinfo`, and `/connect/revoke` OIDC endpoints, registered them in DI, updated the discovery configuration, and added comprehensive end-to-end integration tests (all 36 tests pass!).
10. **v0.4 Packaging & CI Automation** — Versioned to `1.0.0` in `Directory.Build.props`, completed XML comments on public models, removed the `CS1591` suppression, and created a GitHub Actions CI workflow under `.github/workflows/build-test.yml` running on Node 24 (addressing Node 20 deprecation warnings) that restores, builds, tests, and packs the solution in Release mode.
11. **v0.5-v0.7 Admin UI SPA & Decoupled Persistence** — Implemented the provider-agnostic `Vefa.CustomAuth.AdminUI` class library using Alpine.js and Tailwind CSS. Built full client CRUD Minimal API endpoints connected to core Managers and Stores. Added complete integration tests (`AdminUIEndpointTests.cs`) and resolved trailing-slash relative assets resolving issues and Alpine execution race conditions. The dashboard is fully dynamic, featuring interactive client selection, visual selection highlights, and real-time C#/JSON integration code generators.
12. **v0.8 MongoDB Provider** — Implemented `Vefa.CustomAuth.MongoDB` package with all 7 store implementations (`MongoCustomAuthClientStore`, `MongoCustomAuthAuthorizationCodeStore`, `MongoCustomAuthRefreshTokenStore`, `MongoCustomAuthSessionStore`, `MongoCustomAuthSigningKeyStore`, `MongoCustomAuthScopeStore`, `MongoCustomAuthAuditLogStore`), `MongoCustomAuthCleanupService`, `MongoCustomAuthIndexManager` for index creation, BsonClassMap registrations, and `AddVefaCustomAuthMongoDbStores` DI extension. Added 12 comprehensive contract tests using Testcontainers.MongoDb (all pass). Total test count: 56 (24 store/manager + 32 AspNetCore).
13. **v0.9 Admin UI Extended Management** — Extended the Admin UI SPA with tab-based navigation and 5 new management screens: scope CRUD, session viewer with revocation, refresh token viewer with revocation, signing key viewer (private keys stripped from API), and audit log viewer with search/pagination. Added `GetPagedAsync` to `ICustomAuthSessionStore` and `ICustomAuthRefreshTokenStore` (implemented across InMemory, EF Core, and MongoDB providers). Added corresponding manager methods. Added 5 new admin API endpoint groups. Total test count: 61 (24 store/manager + 37 AspNetCore).
14. **v1.0 Public API and Packaging Stabilization** — Synchronized `plan.md`, `plan-phase-2.md`, root `README.md`, package READMEs, and `docs/production-hardening.md` with the implemented state. Added package-specific README files for all 7 `src` packages, `PackageReadmeFile` metadata, and `scripts/pack-all-packages.sh <version> [output-directory]` to create all NuGet packages under `artifacts/packages` by default. Added NuGet push instructions to the README.
15. **v1.0 Refresh Token Lifecycle Hardening** — Refresh tokens are now opaque/hash-only in storage, session-bound, rotated on use, chained through `ParentTokenId`, constrained by sliding `ExpiresAt` plus fixed `AbsoluteExpiresAt`, and guarded by reuse detection. `CustomAuthAuthorizationCode` carries `SessionId`; `CustomAuthRefreshToken` carries `SessionId`, `ParentTokenId`, and `AbsoluteExpiresAt`; `CustomAuthClient` carries `RefreshTokenAbsoluteLifetimeSeconds`; `CustomAuthOptions` carries `RefreshTokenAbsoluteLifetime` and `DetectRefreshTokenReuse`. Reused consumed refresh tokens write `RefreshTokenReuseDetected` audit logs and revoke the session-bound refresh token chain when possible. Refresh token issuance now requires both `AllowRefreshTokens = true` and granted `offline_access`; clients that allow refresh tokens must include `offline_access` in `AllowedScopes`. Admin UI auto-selects `offline_access` when refresh tokens are enabled and shows session, parent, sliding expiry, and absolute expiry in the refresh token viewer.
16. **Security audit + P0 remediation (2026-05-28)** — A full RFC 6749 / 7009 / 7636 / 8414 / 9700 / OIDC Core 1.0 audit was run against the v1.0 implementation. The complete findings, severity-ordered remediation roadmap (21 numbered items grouped P0/P1/P2), and verification plan live at `/Users/vefa/.claude/plans/first-you-need-handover-federated-nygaard.md` — read it before touching protocol code. **All six P0 fixes shipped on `development`:**
    1. **Admin UI authorization bypass closed.** `MapVefaCustomAuthAdminUI` now returns a `RouteGroupBuilder` (via `MapGroup`), so `RequireAuthorization()` actually covers every admin API route — not only the index page. By default the group requires an authenticated request that satisfies the application's default authorization policy. Opt out via `CustomAuthAdminUIOptions.AllowAnonymous` (sample uses this) or specify a named policy via `AuthorizationPolicyName`. `Sample.Admin/Program.cs` sets `AllowAnonymous = true` with a documented comment, since it is a local dev sample.
    2. **OIDC `nonce` wired end-to-end.** `CustomAuthAuthorizationCode.Nonce` and `TokenIssueRequest.Nonce` added. `AuthorizationEndpointService` parses `?nonce=`, stores it on the code, and `JwtTokenIssuer` echoes it into the ID token. EF entity config adds the `Nonce` column (max length 512); Mongo picks it up via `AutoMap`.
    3. **Authorize errors redirect per RFC 6749 §4.1.2.1.** `redirect_uri` is validated *before* response_type/scope/PKCE. Post-validation errors call `EndpointResults.OAuthAuthorizeRedirectError`, which 302s back to the validated `redirect_uri` with `error=`, `error_description=`, `state=`. Pre-validation errors (missing client_id, unknown client, bad redirect_uri) still return JSON/HTML — never redirect to an unvalidated URI.
    4. **Authorization code & refresh token consumption is atomic.** `ICustomAuthAuthorizationCodeStore.MarkConsumedAsync` and `ICustomAuthRefreshTokenStore.MarkConsumedAsync` now return `Task<bool>` (true only when the CAS actually transitioned `ConsumedAt` from null). EF Core uses `ExecuteUpdateAsync` with `WHERE Id = @id AND ConsumedAt IS NULL`. Mongo uses `UpdateOneAsync` with the same filter, checking `ModifiedCount`. InMemory uses a per-entity lock. `TokenEndpointService` calls `MarkConsumed` **before** issuing tokens; on the refresh-token path a CAS failure triggers reuse-detection chain revocation.
    5. **CSRF protection on `/login` POST.** `LoginEndpointService` depends on `IAntiforgery`; the render path embeds the token in the form, the POST path calls `ValidateRequestAsync` and returns 400 on failure (with a refreshed form). `AddVefaCustomAuth` registers `AddAntiforgery()`.
    6. **Token endpoint cache headers.** All success and error responses now go through `EndpointResults.NoStoreJson`, which sets `Cache-Control: no-store` and `Pragma: no-cache` (RFC 6749 §5.1/§5.2).
    Test infrastructure changes: `tests/Vefa.CustomAuth.Tests` gained `Microsoft.EntityFrameworkCore.Sqlite` (8.0.10) because `Microsoft.EntityFrameworkCore.InMemory` does not support `ExecuteUpdateAsync`. `EfCustomAuthStoreTests.CreateSqliteProvider()` is the helper for tests that exercise the atomic-update path; the rest of the EF tests still use the InMemory provider via the original `CreateProvider()`. New helper `tests/Vefa.CustomAuth.AspNetCore.Tests/AntiforgeryTestHelpers.cs` scrapes the rendered login form for the antiforgery cookie + token so other tests can POST `/login`. Current test count: **77** (26 store/manager + 51 AspNetCore).
17. **OIDC P1 & P2 Group A Security Hardening (2026-05-28)**:
    - **`at_hash` ID Token claim**: Computes the Access Token validation hash (`at_hash`) using the leftmost half of the SHA-256/384/512 digest, base64url-encoded, and adds it as a claim in issued ID tokens.
    - **`prompt` and `max_age` handling**: Implemented full OIDC re-authentication logic for `prompt=none` (immediate redirect with `login_required` error when no SSO session exists) and `prompt=login` (forces login ignore-session). Added `max_age` logic.
    - **`/connect/userinfo` POST support & Scope Claim Filtering**: Mapped both GET and POST for `/connect/userinfo`, and filtered returned claims strictly based on the scopes granted to the access token (`profile` for name/preferred_username, `email` for email/email_verified).
    - **Rate Limiting & Lockout**: Integrated `Microsoft.AspNetCore.RateLimiting` on login endpoints and introduced `ICustomAuthLoginAttemptTracker` brute-force lockout interface.
    - **Constant-time comparison for PKCE**: Used `CryptographicOperations.FixedTimeEquals` on decoded bytes in `PkceVerifier` to protect S256 PKCE verification.
    - **Revocation Hardening**: Bound token revocation to the requesting client, honored type hints, and enabled token chain revocation.
    - **PKCE `plain` drop (P2-13)**: Dropped standard PKCE `plain` method, allowing only timing-safe S256.
    - **Lowered auth code lifetime (P2-14)**: Reduced default code lifetime to 60s.
    - **invalid_client 401 with WWW-Authenticate (P2-17)**: Token endpoint returns 401 carrying `WWW-Authenticate: Basic realm="Vefa.CustomAuth"` when client validation fails.
18. **OIDC P2 Group B & Group C Security Hardening (2026-05-28) [THIS SESSION]**:
    - **Admin UI CSRF Antiforgery (P2-15)**: Integrated standard antiforgery cookie + HTML meta tags to Admin UI index SPA, wired `RequestVerificationToken` headers on all mutating fetch requests, and configured a custom `AdminUIAntiforgeryFilter` on all CRUD API endpoints (`POST`, `PUT`, `DELETE`).
    - **Secure Logout (P2-16)**: Upgraded `LogoutEndpointService` to cryptographically validate `id_token_hint` first. Bypasses logout and serves an elegant OIDC Logout Confirmation form carrying the antiforgery token when the hint is absent/invalid. Validates antiforgery token on form `POST` before terminating the session.
    - **SSO Session Cookie Hardening (P2-18)**: Encrypted and signed the session ID cookie value using `IDataProtectionProvider`, enforced `Path=/` explicitly on append/delete operations, and implemented dynamic `__Host-` cookie prefixing when `RequireHttps=true` falling back to the standard name dynamically under HTTP to prevent browser rejection.
    - **Strict Native / Web Redirect URI Validation (P2-19)**: Mandated absolute URIs, banned fragments (`#`), and enforced HTTPS on all client redirects unless the host is a local loopback (`localhost`, `127.0.0.1`, `[::1]`).
    - **Clean-up Service Optimizations (P2-20)**: Implemented dual-mode in `EfCustomAuthCleanupService` executing database-level high-performance bulk `ExecuteDeleteAsync()` on production servers (PostgreSQL/SQL Server) and safe in-memory deletions on dev/test environments (SQLite/InMemory) to bypass SQLite's `DateTimeOffset` translation limitations.
    - **100/100 Green Tests**: Re-architected integration tests to support encrypted cookies and added a dedicated test suite in `SessionCookieAndValidationTests.cs` bringing the total passing tests in the solution to exactly **100/100 passing flawlessly with zero warnings/errors!**
19. **UI-free AspNetCore package (2026-05-28)** — repositioned `Vefa.CustomAuth.AspNetCore` as a Duende-style protocol library. The package no longer ships any HTML:
    - **Resources removed**: `Resources/login.html`, `Resources/logout-confirm.html`, `Resources/logged-out.html` and the `EmbeddedResource` glob are deleted.
    - **`LoginEndpointService`**: dropped the `Render` path and the `LoadTemplate` helper. `HandleAsync` is now POST-only: it validates antiforgery, checks credentials/lockout, opens an SSO session, and redirects. On any failure it 302s back to `LoginPath` with `?error=<code>&returnUrl=<orig>` (`invalid_credentials`, `missing_credentials`, `account_locked`, `antiforgery_failed`). The host owns the GET page and is expected to surface the error code.
    - **`LogoutEndpointService`**: HTML render gone. GET without a cryptographically valid `id_token_hint` 302s to `LogoutPath` (forwarding `post_logout_redirect_uri`/`state`/`client_id`). POST validates antiforgery, then terminates the session and redirects to the registered `post_logout_redirect_uri` (when the supplied one matches `CustomAuthClient.PostLogoutRedirectUris`) or to the new `CustomAuthOptions.PostLogoutRedirectUri` fallback (default `/`).
    - **`CustomAuthOptions`**: added `LogoutPath` (default `/logout`) and `PostLogoutRedirectUri` (default `/`); validator covers both. Removed `MapDefaultLoginEndpoint`, `MapDefaultLogoutEndpoint`, and `LoginRateLimitingPolicyName` (UI/throttling concerns now belong to the host).
    - **`CustomAuthEndpointRouteExtensions`**: protocol-only route table. No GET `/login` mapping anymore; just POST `/login`, GET+POST `/connect/logout`, plus the existing discovery/JWKS/authorize/token/userinfo/revoke endpoints.
    - **`Sample.AuthServer`**: `Login.cshtml` now posts to `/login` with `@Html.AntiForgeryToken()` and reads `?error=` from the query; the obsolete Razor `OnPostAsync` is gone. New `Pages/Logout.cshtml(.cs)` renders the confirmation page that POSTs back to `/connect/logout`.
    - **Tests**: 100/100 still green. Added `AntiforgeryTestHelpers.MapAntiforgeryStub()` extension (mapped in each test app's `CreateAppAsync`) to issue antiforgery cookie+token via a tiny `/login` GET stub since the library no longer ships one. `LogoutClearsCookieAndRevokesSession`, `LogoutWithInvalidRedirectUriFallsBackToPostLogoutRedirectUri`, `LoginAttemptTrackerBlocksAndLockoutWorks`, and `LoginPostWithoutAntiforgeryTokenIsRejected` were rewritten for the redirect-based contract.
20. **`AddCustomAuthClient` relying-party helper (2026-05-28)** — `Vefa.CustomAuth.AspNetCore` now also ships the client-side OIDC integration so relying-party apps don't have to hand-wire `AddAuthentication().AddCookie().AddOpenIdConnect(...)` themselves:
    - New `Client/VefaCustomAuthClientOptions.cs` — minimal surface: `Authority`, `ClientId`, optional `ClientSecret`, plus toggles for `RequireHttpsMetadata`, `CallbackPath`, `SignedOutCallbackPath`, `SignedOutRedirectUri`, `SaveTokens`, `GetClaimsFromUserInfoEndpoint`, `RequireNonce`. `Scopes` is pre-populated with `openid profile email offline_access`; `AdditionalScopes` is the API-audience extension point.
    - New `Client/VefaCustomAuthClientExtensions.cs` — `services.AddCustomAuthClient(configure)` returns an `AuthenticationBuilder`, defaults code+PKCE+SaveTokens+`MapInboundClaims=false`+`name` claim type. `endpoints.MapCustomAuthSignOut("/logout")` is a one-liner that pairs cookie sign-out with the upstream OIDC end-session call.
    - Added `Microsoft.AspNetCore.Authentication.OpenIdConnect` 8.0.10 to `Vefa.CustomAuth.AspNetCore.csproj` so the client API works without a separate package install.
    - `Sample.WebApp/Program.cs` rewritten on top of the new helper (just sets `Authority`, `ClientId`, dev `RequireHttpsMetadata=false`, adds `sample-api` scope) and now references `Vefa.CustomAuth.AspNetCore` directly instead of the raw `OpenIdConnect` package. Build 0/0, tests 100/100.

### What is the user's intended next step

All P0, P1, and P2 security audit items from `/Users/vefa/.claude/plans/first-you-need-handover-federated-nygaard.md` are fully completed! The remaining tasks include:

1. **Deferred Introspection (`P2-21`)**: Implement `/connect/introspect` if protected APIs ever require opaque token validation or administrative diagnostics.
2. **Admin UI route cleanup**: Split the large `AdminUIEndpointRouteExtensions.cs` file into smaller endpoint groups without behavior changes (now extremely easy since everything lives under one `MapGroup`).
3. **Production key protection**: Add guidance or extension points for encrypting/signing-key private material at rest.
4. **CI packaging alignment**: Optionally update `.github/workflows/build-test.yml` to use `scripts/pack-all-packages.sh`.

### Operating rules reminder for the next model

- Read the rest of this file before touching anything.
- Build must stay at 0 warnings / 0 errors. Run `dotnet build` after each meaningful change.
- Update `plan.md` `Status:` lines in the same change that advances them.
- All code, comments, logs, exception messages, and commit messages in English. Turkish only in chat replies.
- Do not commit unless explicitly asked.

## Project context

- OAuth2 / OIDC SSO library for ASP.NET Core, distributed as NuGet packages.
- Target framework: `net8.0` (LTS). Do not introduce other TFMs without discussion.
- See [`plan.md`](plan.md) for the full requirements roadmap. It is the source of truth for scope and design intent — extend it when scope changes, but do not silently rewrite existing sections.

## Language rules (strict)

Everything that ships inside the repository as part of the codebase must be in **English**:

- All code identifiers (types, members, parameters, locals).
- All code comments (`//`, `/* */`, XML doc `///`).
- All log messages and structured log property names.
- All exception messages.
- All user-facing strings emitted by the libraries (error responses, problem details).
- All commit messages and PR descriptions.
- All `.md` files written for the public (README, package READMEs, XML doc output).
- All NuGet package metadata (`Description`, `PackageTags`, etc.).
- All test names and test data unless the test explicitly verifies non-ASCII handling.

Turkish is allowed **only** in:

- `Codex.local.md` if it exists (personal scratch, gitignored).
- Conversational replies to the user in this chat.

If you find existing Turkish content in the codebase, flag it and offer to convert it.

## Code style

- `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` is on — keep builds warning-free.
- Nullable reference types are enabled. No `!` null-forgiving without a comment justifying it.
- Prefer `sealed` on classes that aren't designed for inheritance.
- Use `ArgumentNullException.ThrowIfNull` / `ArgumentException.ThrowIfNullOrEmpty` for guard clauses.
- Use `TimeProvider` for time, never `DateTime.UtcNow` directly. The DI container registers `TimeProvider.System` by default; tests substitute `FakeTimeProvider`.
- Async methods take `CancellationToken cancellationToken = default` as the last parameter and use `.ConfigureAwait(false)` in library code.
- One public top-level type per file. File name matches the type.
- Namespaces follow folder structure (`Vefa.CustomAuth.<Project>.<Folder>`).

## Architecture rules

- **`Core`** holds models, store abstractions, options. No ASP.NET Core, no EF Core, no JWT references.
- **`Tokens`** depends on `Core` only. Handles signing keys, JWT issuance, hashing.
- **`AspNetCore`** depends on `Core` + `Tokens`. Endpoint handlers and DI extensions live here.
- **`EntityFrameworkCore`** depends on `Core` only. Provides EF-backed store implementations and `CustomAuthDbContext`.
- **`Server`** is the composition root that pulls everything together for the auth server scenario.
- Domain types in `Core` must not reference any concrete user model — go through `ICustomAuthUserStore`.
- Endpoint handlers must be minimal API (no MVC controllers).
- Public APIs that ship via NuGet need XML doc comments.

## Security rules (non-negotiable)

- PKCE is required by default.
- Authorization codes are single-use, short-lived (≤ 2 min), hashed in storage.
- Refresh tokens are opaque, hashed in storage, rotated on use, session-bound when possible, and constrained by sliding plus absolute expiration.
- Refresh token issuance requires `AllowRefreshTokens = true` and granted `offline_access`.
- `redirect_uri` must match exactly — no prefix matching, no wildcard.
- Signing keys' private material never leaves the server; only public JWK is exposed.
- Never log secrets, raw tokens, authorization codes, passwords, or PII.

## Plan tracking

- [`plan.md`](plan.md) is the requirements roadmap. Each top-level numbered section represents a discrete deliverable.
- When a section is fully implemented, insert a `Status: completed` line directly under its heading.
- For partial progress, use `Status: partial — <short note in English>` and update the note as scope advances. Convert it to `completed` only when nothing in the section remains undone.
- Leave unstarted sections unmarked.
- Update the status marker in the same change that completes (or advances) the work, so `plan.md` always reflects reality.

## Workflow rules

- After meaningful changes, run `dotnet build` from the repo root and confirm 0 warnings / 0 errors before reporting done.
- Do not edit `obj/` or `bin/` output. If a Turkish string shows up there, fix the source (e.g. `Directory.Build.props`), not the generated file.
- Do not commit unless the user explicitly asks.
- Do not push, force-push, or amend commits unless explicitly asked.
- Prefer adding new files over rewriting existing ones when extending; prefer editing over rewriting when modifying.
