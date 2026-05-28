# AGENTS.md

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

### What is the user's intended next step

Phase 2 is complete through `v0.9`, v1.0 stabilization is mostly complete, and the audit's P0 security gaps are closed. **The next development work is the audit's P1 list** (`/Users/vefa/.claude/plans/first-you-need-handover-federated-nygaard.md` §4.1). They are listed roughly in priority order; each can ship as its own commit:

7. **Add `at_hash` to the ID token** — OIDC Core §3.1.3.6 token-substitution defense. Hash the access token's ASCII bytes (SHA-256 for RS256), take the leftmost half, base64url, add as `at_hash` claim in `JwtTokenIssuer.CreateIdToken`. The access token is already issued first; pass it (or its claims) so the ID token issuer can compute the hash.
8. **Implement `prompt=none` / `prompt=login`** — parse `prompt` in `AuthorizationEndpointService` (alongside the existing nonce parsing on lines ~37-45). `prompt=none` returns a `login_required` redirect when no SSO session exists; `prompt=login` always forces the login form even when a session cookie is valid. Also consider `max_age` for forced re-auth.
9. **UserInfo: support POST + filter claims by scope** — map both `GET` and `POST /connect/userinfo` in `CustomAuthEndpointRouteExtensions.cs` (current handler is `MapGet` only). In `UserInfoEndpointService` read the access token's `scope` claim and only emit `email`/`email_verified` when `email` is granted, `name`/`preferred_username`/`profile` when `profile` is granted (OIDC Core §5.3, §5.4).
10. **Rate limiting on `/login`** — use `Microsoft.AspNetCore.RateLimiting` with a configurable policy in `CustomAuthOptions`. Document an `ICustomAuthLoginAttemptTracker` extension point so hosts can plug in account lockout.
11. **Constant-time hash compare** — replace ordinal `string.Equals` in `PkceVerifier.Verify` ([PkceVerifier.cs:23](src/Vefa.CustomAuth.AspNetCore/Endpoints/PkceVerifier.cs:23)) with byte-array decoding + `CryptographicOperations.FixedTimeEquals`. Introduce a small `SecureCompare` helper to centralize the pattern.
12. **Revocation hardening (`/connect/revoke`)** — currently does not authenticate the client and does not chain-revoke. Bind the call to the requesting `client_id`, honor `token_type_hint=refresh_token|access_token`, and reuse the same chain-revocation path used by reuse detection when a refresh token is revoked.

P2 hardening items (drop PKCE `plain`, lower auth-code lifetime to 60s, Admin UI CSRF tokens, restrict `/connect/logout` to POST+anti-forgery, return 401 + `WWW-Authenticate` for `invalid_client`, `__Host-` cookie prefix, redirect-URI format validation per RFC 8252 §7.3, EF cleanup parity with Mongo) follow in the audit plan §4.1.

Other useful threads left over from before the audit:
1. **Admin UI route cleanup** — split the large `AdminUIEndpointRouteExtensions.cs` file into smaller endpoint groups without behavior changes (now easier since everything lives under one `MapGroup`).
2. **Protocol coverage** — add `/connect/introspect` if protected APIs need opaque-token style validation or admin diagnostics.
3. **Production key protection** — add guidance or extension points for encrypting/signing-key private material at rest.
4. **CI packaging alignment** — optionally update `.github/workflows/build-test.yml` to use `scripts/pack-all-packages.sh`.

Recent troubleshooting note: if `http://localhost:5043/` shows a 401 from the API after previous successful login, the browser likely has an old WebApp auth cookie containing tokens signed by an older local signing key. Open `http://localhost:5043/logout`, then reload `http://localhost:5043/` and sign in again with `demo / demo`.

**State of the working tree at the time of this handover:** all milestone 16 (audit + P0) source/test changes are committed on `development` as `28787a5` ("feat: implement atomic token consumption with concurrency checks and update EF Core to use ExecuteUpdateAsync"). The commit covers all six P0 items even though the title only names P0-4. The audit-plan file (`/Users/vefa/.claude/plans/first-you-need-handover-federated-nygaard.md`) is outside the repo and is not under version control. Verify `dotnet build` reports `0 Warning(s) 0 Error(s)` and `dotnet test` reports **77 / 77** passing before reporting any further milestone done.

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
